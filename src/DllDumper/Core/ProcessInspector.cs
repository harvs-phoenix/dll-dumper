using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace DllDumper.Core;

/// <summary>
/// Read-only view of a running process: its module list, its virtual memory map,
/// its main executable path and its architecture.
/// </summary>
public sealed class ProcessInspector : IDisposable
{
    public int Pid { get; }
    public string Name { get; }
    public string? WindowTitle { get; }
    public string? ExePath { get; private set; }
    public bool Is64Bit { get; private set; } = true;
    public string Architecture => Is64Bit ? "x64" : "x86";
    public IntPtr Handle { get; }

    public ProcessInspector(int pid)
    {
        using var p = Process.GetProcessById(pid);
        Pid = pid;
        Name = p.ProcessName;
        try { WindowTitle = p.MainWindowTitle; } catch { /* no window / access */ }

        Handle = Native.OpenProcess(Native.INSPECT_RIGHTS, false, pid);
        if (Handle == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            throw new Win32Exception(err, Native.FriendlyError(err, Name));
        }

        var sb = new StringBuilder(1024);
        uint size = 1024;
        if (Native.QueryFullProcessImageNameW(Handle, 0, sb, ref size))
            ExePath = sb.ToString();

        if (Native.IsWow64Process(Handle, out bool wow64))
            Is64Bit = !wow64;    // we are a 64-bit process: WOW64 == the target is 32-bit
        else
            Is64Bit = Environment.Is64BitOperatingSystem;
    }

    /// <summary>All modules currently mapped into the process (i.e. its loaded files).</summary>
    public List<ModuleInfo> GetModules()
    {
        var list = new List<ModuleInfo>(64);
        try
        {
            using var p = Process.GetProcessById(Pid);
            foreach (ProcessModule m in p.Modules)
            {
                string path = "";
                try { path = m.FileName ?? ""; } catch { /* module unloaded mid-walk */ }

                list.Add(new ModuleInfo
                {
                    Name = m.ModuleName ?? "?",
                    Path = path,
                    Base = m.BaseAddress,
                    Size = m.ModuleMemorySize,
                    IsManaged = LooksManaged(path),
                });
            }
        }
        catch (Win32Exception ex)
        {
            throw new Win32Exception(ex.NativeErrorCode,
                Native.FriendlyError(ex.NativeErrorCode, Name) + " (module list)");
        }

        list.Sort((a, b) => a.Base.ToInt64().CompareTo(b.Base.ToInt64()));
        return list;
    }

    /// <summary>Walks the whole virtual address space with VirtualQueryEx.</summary>
    public List<MemoryRegion> WalkMemory(List<ModuleInfo> modules)
    {
        var result = new List<MemoryRegion>(2048);
        int mbiSize = Marshal.SizeOf<Native.MEMORY_BASIC_INFORMATION>();
        long addr = 0;

        // walk from address 0 upward until VirtualQueryEx fails or we stop making progress
        while (addr >= 0)
        {
            if (Native.VirtualQueryEx(Handle, (IntPtr)addr, out var mbi, (nuint)mbiSize) == 0)
                break;

            long baseAddr = mbi.BaseAddress.ToInt64();
            long size = mbi.RegionSize.ToInt64();
            if (size <= 0) break;

            if (mbi.State != Native.MEM_FREE)
            {
                var region = new MemoryRegion
                {
                    Base = mbi.BaseAddress,
                    Size = size,
                    State = mbi.State,
                    Protect = mbi.Protect,
                    Type = mbi.Type,
                };
                region.Owner = ResolveOwner(modules, baseAddr, mbi.Type);
                result.Add(region);
            }

            long next = baseAddr + size;
            if (next <= addr) break;   // defensive: no progress / wrap-around
            addr = next;
        }

        return result;
    }

    private string ResolveOwner(List<ModuleInfo> modules, long address, uint type)
    {
        // 1) inside a loaded module?
        int lo = 0, hi = modules.Count - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) / 2;
            var m = modules[mid];
            long b = m.Base.ToInt64();
            long e = b + m.Size;
            if (address < b) hi = mid - 1;
            else if (address >= e) lo = mid + 1;
            else return m.Name;
        }

        // 2) mapped file? (data sections of DLLs, section objects, pagefile-backed maps)
        if (type == Native.MEM_MAPPED || type == Native.MEM_IMAGE)
        {
            var sb = new StringBuilder(512);
            uint n = Native.K32GetMappedFileNameW(Handle, (IntPtr)address, sb, (uint)sb.Capacity);
            if (n > 0)
            {
                string s = sb.ToString();
                int cut = s.LastIndexOf('\\');
                return cut >= 0 ? s[(cut + 1)..] : s;
            }
        }

        return type switch
        {
            Native.MEM_IMAGE => "Image",
            Native.MEM_MAPPED => "Mapped file",
            Native.MEM_PRIVATE => "Private",
            _ => "",
        };
    }

    private static bool LooksManaged(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        try
        {
            using var fs = File.OpenRead(path);
            if (fs.Length < 0x200) return false;
            using var br = new BinaryReader(fs);
            if (br.ReadUInt16() != 0x5A4D) return false;          // 'MZ'
            fs.Position = 0x3C;
            int pe = br.ReadInt32();
            if (pe <= 0 || pe + 24 + 96 + 16 * 4 > fs.Length) return false;
            fs.Position = pe;
            if (br.ReadUInt32() != 0x00004550) return false;       // 'PE\0\0'
            fs.Position = pe + 4 + 16;
            ushort optSize = br.ReadUInt16();
            fs.Position = pe + 24;
            ushort magic = br.ReadUInt16();
            if (magic != 0x10B && magic != 0x20B) return false;
            int ddOffset = magic == 0x20B ? 112 : 96;
            fs.Position = pe + 24 + ddOffset + 14 * 8;             // CLR runtime header = data dir #14
            uint clrRva = br.ReadUInt32();
            return clrRva != 0;
        }
        catch
        {
            return false;
        }
    }

    public void Dispose()
    {
        if (Handle != IntPtr.Zero) Native.CloseHandle(Handle);
    }
}
