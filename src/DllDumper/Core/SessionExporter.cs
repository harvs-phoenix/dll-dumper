using System.Text;

namespace DllDumper.Core;

/// <summary>
/// Writes one neat, send-able folder per recording session:
/// report.txt (log + injections + recover verdicts), mono.txt, memory.txt,
/// files.txt — plus the recovered\ subfolder the dumper writes recovered dlls into.
/// The whole folder can be zipped and sent to someone as-is.
/// </summary>
public static class SessionExporter
{
    /// <summary>Root folder on the desktop (homescreen) where sessions are created.</summary>
    public static string Root => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "sessions");

    /// <summary>Creates a fresh timestamped session folder, e.g. sessions\2026-10-20_145502_GorillaTag.</summary>
    public static string CreateSessionFolder(string targetName)
    {
        string safe = new(targetName.Where(c => char.IsLetterOrDigit(c) || c is '-' or '_' or '.').ToArray());
        if (safe.Length == 0) safe = "target";
        string dir = Path.Combine(Root, $"{DateTime.Now:yyyyMMdd_HHmmss}_{safe}");
        Directory.CreateDirectory(dir);
        return dir;
    }

    /// <summary>Writes the captured data + log into an existing session folder.</summary>
    public static void Write(
        string folder,
        string targetName,
        int pid,
        bool is64Bit,
        DateTime startedAt,
        DateTime stoppedAt,
        string summary,
        Recorder rec,
        MonoRuntime? runtime,
        List<AssemblyScan> assemblies,
        List<MemoryRegion> regions,
        List<ModuleInfo> modules,
        IReadOnlyList<string> recoverNotes)
    {
        // --- report.txt: the story of the session ---------------------------
        var sb = new StringBuilder();
        sb.AppendLine("dll dumper — session report");
        sb.AppendLine("===========================");
        sb.AppendLine($"target    : {targetName} (PID {pid}) · {(is64Bit ? "x64" : "x86")}");
        sb.AppendLine($"recorded  : {startedAt:yyyy-MM-dd HH:mm:ss} → {stoppedAt:HH:mm:ss} " +
                      $"({(stoppedAt - startedAt).ToString(@"hh\:mm\:ss")})");
        sb.AppendLine($"summary   : {summary}");
        sb.AppendLine($"generated : {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine();

        sb.AppendLine("recovered dlls");
        sb.AppendLine("--------------");
        if (recoverNotes.Count == 0)
            sb.AppendLine("(no new dlls appeared in the target during the session)");
        else
            foreach (var n in recoverNotes)
                sb.AppendLine(n);
        sb.AppendLine();

        sb.AppendLine("injections (through this app)");
        sb.AppendLine("-----------------------------");
        if (rec.Injections.Count == 0)
            sb.AppendLine("(none — if you used an external injector, its dll shows up under recovered dlls)");
        else
            foreach (var inj in rec.Injections)
            {
                sb.AppendLine($"[{inj.Time:HH:mm:ss}] {inj.Mode} · {inj.Payload} → {inj.Target} · {inj.Status}");
                foreach (var s in inj.Steps)
                    sb.AppendLine("    " + s);
            }
        sb.AppendLine();

        sb.AppendLine("session log");
        sb.AppendLine("-----------");
        foreach (var it in rec.Items)
            sb.AppendLine($"[{it.Time:HH:mm:ss.fff}] {it.Kind,-12} {it.Item}  {it.Detail}".TrimEnd());
        File.WriteAllText(Path.Combine(folder, "report.txt"), sb.ToString());

        // --- mono.txt: runtime + exports + every managed assembly ------------
        var mo = new StringBuilder();
        mo.AppendLine("mono / runtime");
        mo.AppendLine("==============");
        if (runtime is null)
        {
            mo.AppendLine("no managed runtime detected in the target");
        }
        else
        {
            mo.AppendLine($"runtime : {runtime.KindName}");
            mo.AppendLine($"module  : {runtime.ModuleName} @ 0x{runtime.ModuleBase.ToInt64():X}");
            mo.AppendLine($"path    : {runtime.ModulePath}");
            mo.AppendLine($"exports : {runtime.Exports.Count}");
            if (runtime.Exports.Count > 0)
            {
                mo.AppendLine();
                foreach (var e in runtime.Exports)
                    mo.AppendLine($"  {e.AddressHex}  {e.Name}{(e.Forwarded ? "  (forwarded)" : "")}");
            }
        }
        mo.AppendLine();
        mo.AppendLine($"assemblies ({assemblies.Count})");
        mo.AppendLine("----------");
        foreach (var a in assemblies)
            mo.AppendLine($"  {a.Name,-44} {a.TypeCount,6} types {a.MethodCount,7} methods  {a.Path}");
        File.WriteAllText(Path.Combine(folder, "mono.txt"), mo.ToString());

        // --- memory.txt: full region walk ------------------------------------
        var mem = new StringBuilder();
        mem.AppendLine($"memory map — {regions.Count} regions");
        mem.AppendLine("===============");
        mem.AppendLine($"{"base",-18} {"size",10}  {"state",-8} {"protect",-10} {"type",-8} owner");
        foreach (var r in regions)
            mem.AppendLine($"{r.BaseHex,-18} {r.SizeText,10}  {r.StateText,-8} {r.ProtectText,-10} {r.TypeText,-8} {r.Owner}");
        File.WriteAllText(Path.Combine(folder, "memory.txt"), mem.ToString());

        // --- files.txt: every mapped module ----------------------------------
        var fl = new StringBuilder();
        fl.AppendLine($"loaded files — {modules.Count} modules");
        fl.AppendLine("===================");
        foreach (var m in modules)
            fl.AppendLine($"{m.Name,-44} {m.BaseHex,-18} {MemoryRegion.FormatSize(m.Size),9}" +
                          $"{(m.IsManaged ? "  managed" : "")}  {m.Path}");
        File.WriteAllText(Path.Combine(folder, "files.txt"), fl.ToString());
    }
}
