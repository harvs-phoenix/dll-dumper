// TestTarget — a harmless x64 process you can point Dll Dumper at to try out
// recording (mono/memory/files) and injection without touching a real game.
//
//   dotnet run --project samples/TestTarget
//
// Leave it running, then select "TestTarget" in Dll Dumper's process list.

namespace TestTarget;

internal static class Program
{
    private static void Main()
    {
        Console.Title = "Dll Dumper — Test Target";
        Console.WriteLine("TestTarget running (PID {0}). Press Q to quit.", Environment.ProcessId);
        Console.WriteLine("Point Dll Dumper at this window to try Record / Inject.");

        int beat = 0;
        while (!Console.KeyAvailable || Console.ReadKey(true).Key != ConsoleKey.Q)
        {
            Console.WriteLine("[{0:HH:mm:ss}] heartbeat {1}", DateTime.Now, ++beat);
            Thread.Sleep(1000);
        }
    }
}
