using System.Runtime.InteropServices;
using System.Text;

namespace DllDumper.Core;

/// <summary>
/// Best-effort PE image dumper: reads a module straight out of another process'
/// memory and rebuilds a file on disk — headers plus every section at its raw
/// file offset. Guarded / no-access pages are skipped (left as zeros) instead of
/// aborting the whole dump.
/// </summary>
public static class ModuleDumper
{
    private const int HeaderRead = 0x1000;
    private const int Chunk = 0x1000;

    /// <summary>Dumps <paramref name="module"/> from the target into <paramref name="outPath"/>.</summary>
    /// <returns>A short summary, e.g. "9 sections · 24 KB".</returns>
    public static string Dump(IntPtr hProcess, ModuleInfo module, string outPath, Action<string>? step = null)
    {
        // ---- read the PE headers out of the target --------------------------
        var hdr = new byte[HeaderRead];
        if (!Native.ReadProcessMemory(hProcess, module.Base, hdr, (nuint)hdr.Length, out nuint got) || got < 0x40)
            throw new InvalidOperationException(
                $"could not read the module headers at {module.BaseHex}: {Native.LastError()}");
        int hdrValid = (int)got;

        if (hdr[0] != 'M' || hdr[1] != 'Z')
            throw new InvalidOperationException("no MZ signature at the module base — not a PE image");

        int pe = BitConverter.ToInt32(hdr, 0x3C);
        if (pe <= 0 || pe + 24 > hdrValid || BitConverter.ToUInt32(hdr, pe) != 0x00004550)
            throw new InvalidOperationException("PE header not found in the module headers");

        ushort sectionCount = BitConverter.ToUInt16(hdr, pe + 6);
        ushort optSize = BitConverter.ToUInt16(hdr, pe + 20);
        int opt = pe + 24;
        int sectionStart = opt + optSize;
        if (sectionStart + 40 * sectionCount > hdrValid)
            throw new InvalidOperationException($"section table ({sectionCount} sections) lies outside the readable headers");

        uint sizeOfHeaders = BitConverter.ToUInt32(hdr, opt + 0x3C);
        if (sizeOfHeaders == 0 || sizeOfHeaders > HeaderRead) sizeOfHeaders = (uint)Math.Min(hdrValid, HeaderRead);

        // ---- lay out the rebuilt file: headers + every section at PointerToRawData ----
        var sections = new List<(int RawPtr, int RawSize, int Va, string Name)>(sectionCount);
        long fileLen = sizeOfHeaders;
        for (int i = 0; i < sectionCount; i++)
        {
            int sh = sectionStart + 40 * i;
            string name = Encoding.ASCII.GetString(hdr, sh, 8).TrimEnd('\0');
            uint rawSize = BitConverter.ToUInt32(hdr, sh + 16);
            uint rawPtr = BitConverter.ToUInt32(hdr, sh + 20);
            uint va = BitConverter.ToUInt32(hdr, sh + 12);
            if (rawSize == 0 || rawPtr == 0) continue;

            sections.Add(((int)rawPtr, (int)rawSize, (int)va, name));
            fileLen = Math.Max(fileLen, rawPtr + rawSize);
        }

        var image = new byte[fileLen];
        Array.Copy(hdr, 0, image, 0, sizeOfHeaders);

        // ---- copy each section from base+VA, skipping unreadable pages -------
        var buf = new byte[Chunk];
        long written = 0, skipped = 0;
        foreach (var s in sections)
        {
            long off = 0;
            while (off < s.RawSize)
            {
                int want = (int)Math.Min(Chunk, s.RawSize - off);
                IntPtr addr = (IntPtr)(module.Base.ToInt64() + s.Va + off);
                if (Native.ReadProcessMemory(hProcess, addr, buf, (nuint)want, out nuint n) && n > 0)
                {
                    Array.Copy(buf, 0, image, s.RawPtr + off, (int)n);
                    written += (long)n;
                    if (n < (nuint)want) skipped += want - (long)n;
                }
                else
                {
                    skipped += want;      // guard / noaccess page — keep zeros
                }
                off += want;
            }
            step?.Invoke($"{s.Name,-8} {MemoryRegion.FormatSize(s.RawSize),9} @ 0x{module.Base.ToInt64() + s.Va:X}");
        }

        File.WriteAllBytes(outPath, image);
        return $"{sections.Count} sections · {MemoryRegion.FormatSize(fileLen)}" +
               (skipped > 0 ? $" · {MemoryRegion.FormatSize(skipped)} unreadable (zero-filled)" : "");
    }

    /// <summary>
    /// Finds a file's image inside the target. Checks the native module list first,
    /// then falls back to the mapped-image scan (mono maps assemblies as MEM_IMAGE
    /// without always registering a native module).
    /// </summary>
    public static ModuleInfo? FindImage(IntPtr hProcess, string fileName, List<ModuleInfo> modules)
    {
        foreach (var m in modules)
            if (m.Name.Equals(fileName, StringComparison.OrdinalIgnoreCase) && m.Size > 0)
                return m;

        return ScanImages(hProcess)
            .FirstOrDefault(i => i.Name.Equals(fileName, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Snapshots every mapped image in the target (allocation base, file name, device
    /// path, image span). Diffing this before Record and after Stop surfaces dlls that
    /// appeared from ANY source — this app's injectors or an external tool's.
    /// </summary>
    public static List<ModuleInfo> ScanImages(IntPtr hProcess)
    {
        int mbiSize = Marshal.SizeOf<Native.MEMORY_BASIC_INFORMATION>();
        long addr = 0;
        var sb = new StringBuilder(512);
        var byBase = new Dictionary<long, ModuleInfo>();

        while (addr >= 0)
        {
            if (Native.VirtualQueryEx(hProcess, (IntPtr)addr, out var mbi, (nuint)mbiSize) == 0)
                break;
            long baseAddr = mbi.BaseAddress.ToInt64();
            long size = mbi.RegionSize.ToInt64();
            if (size <= 0) break;

            if (mbi.State == Native.MEM_COMMIT && mbi.Type == Native.MEM_IMAGE)
            {
                long alloc = mbi.AllocationBase.ToInt64();
                long end = baseAddr + size;

                if (byBase.TryGetValue(alloc, out var img))
                {
                    // same image, later region — grow the span
                    if (end - alloc > img.Size)
                        img.Size = (int)Math.Min(int.MaxValue, end - alloc);
                }
                else
                {
                    sb.Clear();
                    string full = "";
                    string name = $"image_0x{alloc:X}";
                    if (Native.K32GetMappedFileNameW(hProcess, mbi.BaseAddress, sb, (uint)sb.Capacity) > 0)
                    {
                        full = sb.ToString();
                        int cut = full.LastIndexOf('\\');
                        name = cut >= 0 ? full[(cut + 1)..] : full;
                    }
                    byBase[alloc] = new ModuleInfo
                    {
                        Name = name,
                        Path = full,
                        Base = mbi.AllocationBase,
                        Size = (int)Math.Min(int.MaxValue, end - alloc),
                    };
                }
            }

            long next = baseAddr + size;
            if (next <= addr) break;
            addr = next;
        }

        return byBase.Values.ToList();
    }
}
