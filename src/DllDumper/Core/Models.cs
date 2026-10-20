namespace DllDumper.Core;

// ---------------------------------------------------------------------------
// Shared data models
// ---------------------------------------------------------------------------

/// <summary>A module (file) mapped into the target process.</summary>
public sealed class ModuleInfo
{
    public string Name = "";
    public string Path = "";
    public IntPtr Base;
    public int Size;
    public bool IsManaged;

    public string BaseHex => $"0x{Base.ToInt64():X}";
}

/// <summary>One region of the target's virtual memory map.</summary>
public sealed class MemoryRegion
{
    public IntPtr Base;
    public long Size;
    public uint State;
    public uint Protect;
    public uint Type;
    public string Owner = "";

    public string BaseHex => $"0x{Base.ToInt64():X}";
    public string SizeText => FormatSize(Size);
    public string StateText => State switch
    {
        Native.MEM_COMMIT => "Commit",
        Native.MEM_RESERVE => "Reserve",
        Native.MEM_FREE => "Free",
        _ => $"0x{State:X}",
    };
    public string TypeText => Type switch
    {
        Native.MEM_IMAGE => "Image",
        Native.MEM_MAPPED => "Mapped",
        Native.MEM_PRIVATE => "Private",
        0 => "",
        _ => $"0x{Type:X}",
    };

    public string ProtectText
    {
        get
        {
            uint baseProt = Protect & 0xFF;
            string text = baseProt switch
            {
                0x01 => "NOACCESS",
                0x02 => "R",
                0x04 => "RW",
                0x08 => "RWC",      // write copy
                0x10 => "X",
                0x20 => "RX",
                0x40 => "RWX",
                0x80 => "RXC",
                _ => $"0x{Protect:X}",
            };
            if ((Protect & Native.PAGE_GUARD) != 0) text += "+GUARD";
            if ((Protect & Native.PAGE_NOCACHE) != 0) text += "+NC";
            if ((Protect & Native.PAGE_WRITECOMBINE) != 0) text += "+WC";
            return text;
        }
    }

    public string Key => $"{Base.ToInt64():X}-{Size}";

    public static string FormatSize(long size)
    {
        if (size >= 1024L * 1024 * 1024) return $"{size / (1024.0 * 1024 * 1024):0.##} GB";
        if (size >= 1024L * 1024) return $"{size / (1024.0 * 1024):0.##} MB";
        if (size >= 1024) return $"{size / 1024.0:0.#} KB";
        return $"{size} B";
    }
}

// --- mono ---------------------------------------------------------------------

public enum RuntimeKind { None, Mono, Il2Cpp, CoreClr }

public sealed class MonoExport
{
    public string Name = "";
    public uint Rva;
    public bool Forwarded;
    public ulong Address;      // absolute address inside the target process

    public string AddressHex => $"0x{Address:X}";
}

public sealed class MonoRuntime
{
    public RuntimeKind Kind = RuntimeKind.None;
    public string ModuleName = "";
    public string ModulePath = "";
    public IntPtr ModuleBase;
    public string ExportError = "";
    public readonly List<MonoExport> Exports = new();
    public readonly Dictionary<string, MonoExport> ByName = new(StringComparer.Ordinal);

    public string KindName => Kind switch
    {
        RuntimeKind.Mono => "Mono",
        RuntimeKind.Il2Cpp => "IL2CPP",
        RuntimeKind.CoreClr => "CoreCLR / .NET",
        _ => "none",
    };

    public ulong? AddressOf(string name) =>
        ByName.TryGetValue(name, out var e) && !e.Forwarded ? e.Address : null;

    public bool Has(string name) => ByName.ContainsKey(name);
}

// --- managed metadata ---------------------------------------------------------

public sealed class TypeScan
{
    public string FullName = "";
    public readonly List<string> Methods = new();
}

public sealed class AssemblyScan
{
    public string Path = "";
    public string Name = "";
    public int TypeCount;
    public int MethodCount;
    public readonly List<TypeScan> Types = new();
}

public sealed class MonoScanResult
{
    public readonly List<AssemblyScan> Assemblies = new();
    public int TotalTypes;
    public int TotalMethods;
}

// --- recording / injection log ------------------------------------------------

public sealed class RecordItem
{
    public DateTime Time = DateTime.Now;
    public string Kind = "";
    public string Item = "";
    public string Detail = "";
}

public sealed class InjectItem
{
    public DateTime Time = DateTime.Now;
    public string Mode = "";
    public string Payload = "";
    public string Target = "";
    public string Status = "Running";
    public readonly List<string> Steps = new();
}

public sealed class InjectionResult
{
    public bool Success;
    public string Summary = "";
    public readonly List<string> Steps = new();

    public void Step(string message) => Steps.Add($"{DateTime.Now:HH:mm:ss.fff}  {message}");
}
