// TestPayload — the entry point Dll Dumper's Mono injector calls.
//
// Mono mode fields for this payload:
//     namespace : TestPayload
//     class     : Loader
//     method    : Load
//     params    : (empty)
//
// The method must be static. Mono mode supports up to 32 parameters of
// primitive/marshalled types — this sample uses none.

namespace TestPayload;

public static class Loader
{
    public static bool Loaded { get; private set; }

    public static void Load()
    {
        Loaded = true;
        string line = $"[TestPayload] loaded at {DateTime.Now:HH:mm:ss.fff}";
        Console.WriteLine(line);
        try
        {
            File.AppendAllText(
                Path.Combine(Path.GetTempPath(), "dlldumper-payload.log"),
                line + Environment.NewLine);
        }
        catch { /* temp folder unavailable — console output is enough */ }
    }

    public static string Status() => Loaded ? "loaded" : "not loaded";
}
