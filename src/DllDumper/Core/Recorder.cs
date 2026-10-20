namespace DllDumper.Core;

/// <summary>
/// A recording session: everything Dll Dumper has observed about the selected
/// process — mono exports, assemblies, files, memory regions — plus every
/// injection that happened during the session, de-duplicated as it goes.
/// </summary>
public sealed class Recorder
{
    public const int MaxItems = 25_000;

    public bool IsRecording { get; private set; }
    public DateTime StartedAt { get; private set; }
    public TimeSpan Elapsed => IsRecording ? DateTime.Now - StartedAt : TimeSpan.Zero;

    public readonly List<RecordItem> Items = new();
    public readonly List<InjectItem> Injections = new();

    private readonly HashSet<string> _seen = new(StringComparer.OrdinalIgnoreCase);
    private long _dropped;

    public event Action<RecordItem>? ItemAdded;
    public event Action? StateChanged;

    public long DroppedCount => _dropped;

    // --- session -------------------------------------------------------------

    public void StartSession()
    {
        if (IsRecording) return;
        IsRecording = true;
        StartedAt = DateTime.Now;
        _seen.Clear();
        _dropped = 0;
        Add("Session", "recording started", "mono + memory + files capture is live");
        StateChanged?.Invoke();
    }

    public string StopSession(string summary)
    {
        if (!IsRecording) return "";
        IsRecording = false;
        var elapsed = DateTime.Now - StartedAt;
        Add("Session", "recording stopped",
            $"duration {elapsed:hh\\:mm\\:ss} · {summary}");
        StateChanged?.Invoke();
        return $"Recorded for {elapsed:hh\\:mm\\:ss}";
    }

    public void Reset()
    {
        IsRecording = false;
        Items.Clear();
        Injections.Clear();
        _seen.Clear();
        _dropped = 0;
        StateChanged?.Invoke();
    }

    // --- plain entries -------------------------------------------------------

    public RecordItem Add(string kind, string item, string detail = "")
    {
        var rec = new RecordItem { Kind = kind, Item = item, Detail = detail };
        if (Items.Count >= MaxItems)
        {
            _dropped++;
            return rec;
        }
        Items.Add(rec);
        ItemAdded?.Invoke(rec);
        return rec;
    }

    /// <summary>Adds only the first time this key is seen in the session.</summary>
    public bool AddOnce(string key, string kind, string item, string detail = "")
    {
        if (!_seen.Add(key)) return false;
        Add(kind, item, detail);
        return true;
    }

    // --- typed helpers -------------------------------------------------------

    public bool RecordModule(ModuleInfo m) =>
        AddOnce("file:" + m.Path, "File", m.Path, $"{m.Name} · {m.BaseHex} · {MemoryRegion.FormatSize(m.Size)}");

    public bool RecordAssembly(AssemblyScan a) =>
        AddOnce("asm:" + a.Path, "Mono",
            $"{a.Name}.dll",
            $"{a.TypeCount} types · {a.MethodCount} methods · {a.Path}");

    public bool RecordMonoExport(MonoRuntime rt, MonoExport e) =>
        AddOnce($"mono:{rt.ModuleName}:{e.Name}", "Mono",
            e.Name, $"{e.AddressHex} · {rt.ModuleName}" + (e.Forwarded ? " · forwarded" : ""));

    public bool RecordMemory(MemoryRegion r, long minSize = 0) =>
        r.Size >= minSize && AddOnce("mem:" + r.Key, "Memory",
            $"{r.BaseHex} · {r.SizeText}",
            $"{r.StateText} · {r.ProtectText} · {r.TypeText} {r.Owner}".TrimEnd());

    public void RecordInjection(InjectItem item)
    {
        Injections.Add(item);
        Add("Inject", $"{item.Mode} → {Short(item.Payload)}", $"target {item.Target} · {item.Status}");
    }

    public void RecordInjectionStep(InjectItem item, string message)
    {
        item.Steps.Add($"{DateTime.Now:HH:mm:ss.fff}  {message}");
        Add("Inject step", Short(item.Payload), message);
    }

    public void RecordError(string where, string message) => Add("Error", where, message);

    private static string Short(string path)
    {
        if (string.IsNullOrEmpty(path)) return "(none)";
        int i = Math.Max(path.LastIndexOf('\\'), path.LastIndexOf('/'));
        return i >= 0 ? path[(i + 1)..] : path;
    }
}
