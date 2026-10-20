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

    // =========================================================================
    // private-memory images: mono loads assemblies from byte arrays
    // (mono_image_open_from_data) straight onto the target's heap — no file
    // mapping, no module entry. The bytes are still there; find the MZ.
    // =========================================================================

    /// <summary>
    /// Scans committed private memory for PE images and returns the managed ones
    /// (valid PE + CLI header). Used to recover mono assemblies that were loaded
    /// from bytes — the usual result of an external mono injector.
    /// </summary>
    public static List<ModuleInfo> ScanPrivateImages(IntPtr hProcess)
    {
        var found = new List<ModuleInfo>();
        int mbiSize = Marshal.SizeOf<Native.MEMORY_BASIC_INFORMATION>();
        long addr = 0;

        while (addr >= 0)
        {
            if (Native.VirtualQueryEx(hProcess, (IntPtr)addr, out var mbi, (nuint)mbiSize) == 0)
                break;
            long baseAddr = mbi.BaseAddress.ToInt64();
            long size = mbi.RegionSize.ToInt64();
            if (size <= 0) break;

            uint protect = mbi.Protect & 0xFF;
            bool readable = mbi.State == Native.MEM_COMMIT
                && mbi.Type == Native.MEM_PRIVATE
                && protect is Native.PAGE_READONLY or Native.PAGE_READWRITE or Native.PAGE_WRITECOPY
                    or Native.PAGE_EXECUTE_READ or Native.PAGE_EXECUTE_READWRITE or Native.PAGE_EXECUTE_WRITECOPY;

            if (readable && size >= 0x200)
            {
                var img = TryReadPrivateImage(hProcess, mbi.BaseAddress, size);
                if (img is not null &&
                    !found.Any(f => f.Name == img.Name && f.Size == img.Size))
                    found.Add(img);
            }

            long next = baseAddr + size;
            if (next <= addr) break;
            addr = next;
        }
        return found;
    }

    /// <summary>Validates a candidate base as a managed PE copy and describes it.</summary>
    private static ModuleInfo? TryReadPrivateImage(IntPtr h, IntPtr baseAddr, long avail)
    {
        try
        {
            var hdr = new byte[0x400];
            if (!Native.ReadProcessMemory(h, baseAddr, hdr, (nuint)hdr.Length, out nuint got) || got < 0x40)
                return null;
            long gotN = (long)got;
            if (hdr[0] != 'M' || hdr[1] != 'Z') return null;

            int pe = BitConverter.ToInt32(hdr, 0x3C);
            if (pe <= 0 || pe + 24 > gotN || BitConverter.ToUInt32(hdr, pe) != 0x00004550) return null;

            ushort optSize = BitConverter.ToUInt16(hdr, pe + 20);
            int opt = pe + 24;
            ushort magic = BitConverter.ToUInt16(hdr, opt);
            if (magic is not (0x10B or 0x20B)) return null;

            // data directory count + CLI header entry (index 14) — must exist and be
            // non-zero: that's what separates a managed assembly from anything else
            int ddCountOff = opt + (magic == 0x20B ? 108 : 92);
            if (ddCountOff + 4 > gotN) return null;
            if (BitConverter.ToUInt32(hdr, ddCountOff) <= 14) return null;
            int cliOff = opt + (magic == 0x20B ? 112 : 96) + 14 * 8;
            if (cliOff + 8 > gotN) return null;
            uint cliRva = BitConverter.ToUInt32(hdr, cliOff);
            uint cliSize = BitConverter.ToUInt32(hdr, cliOff + 4);
            if (cliRva == 0 || cliSize == 0 || cliSize > 0x1000) return null;

            // section table → true file length of the raw copy + rva→file offset map
            ushort sectionCount = BitConverter.ToUInt16(hdr, pe + 6);
            int sectionStart = opt + optSize;
            if (sectionStart + 40 * sectionCount > gotN || sectionCount == 0 || sectionCount > 96) return null;

            long fileLen = BitConverter.ToUInt32(hdr, opt + 60);   // SizeOfHeaders
            uint metaRva = 0;
            var sections = new (uint Va, uint RawPtr, uint RawSize)[sectionCount];
            for (int i = 0; i < sectionCount; i++)
            {
                int s = sectionStart + i * 40;
                uint va = BitConverter.ToUInt32(hdr, s + 12);
                uint rawPtr = BitConverter.ToUInt32(hdr, s + 20);
                uint rawSize = BitConverter.ToUInt32(hdr, s + 16);
                sections[i] = (va, rawPtr, rawSize);
                long end = (long)rawPtr + rawSize;
                if (end > fileLen) fileLen = end;
            }
            if (fileLen < 0x200 || fileLen > 0x2000_0000 || fileLen > avail + 0x10000) return null;

            // CLI header → metadata RVA; translate through the section table to a
            // file offset (the heap copy holds raw file bytes, not mapped ones)
            int cliFile = RvaToFile(sections, cliRva);
            if (cliFile < 0 || cliFile + 16 > gotN) return null;
            var cliBuf = new byte[16];
            if (!Native.ReadProcessMemory(h, (IntPtr)(baseAddr.ToInt64() + cliFile), cliBuf, 16, out got) || got < 16)
                return null;
            metaRva = BitConverter.ToUInt32(cliBuf, 8);
            int metaFile = RvaToFile(sections, metaRva);
            if (metaFile < 0) return null;

            string name = ReadMetadataModuleName(h, baseAddr, metaFile) ?? $"image_0x{baseAddr.ToInt64():X}";

            return new ModuleInfo
            {
                Name = name,
                Path = $"private memory @ {baseAddr.ToInt64():X}",
                Base = baseAddr,
                Size = (int)Math.Min(int.MaxValue, fileLen),
                IsManaged = true,
            };
        }
        catch
        {
            return null;   // unreadable candidate — skip it
        }
    }

    private static int RvaToFile((uint Va, uint RawPtr, uint RawSize)[] sections, uint rva)
    {
        foreach (var (va, rawPtr, rawSize) in sections)
            if (rva >= va && rva < va + rawSize)
                return (int)(rawPtr + (rva - va));
        if (rva < sections[0].Va) return (int)rva;   // header-resident
        return -1;
    }

    /// <summary>
    /// Reads the module name out of the BSJB metadata (#Strings heap, first entry) —
    /// for a compiled assembly that is the original file name, e.g. "MyMod.dll".
    /// </summary>
    private static string? ReadMetadataModuleName(IntPtr h, IntPtr baseAddr, int metaFile)
    {
        var head = new byte[0x100];
        long a = baseAddr.ToInt64() + metaFile;
        if (!Native.ReadProcessMemory(h, (IntPtr)a, head, (nuint)head.Length, out nuint got) || got < 20)
            return null;
        long gotN = (long)got;
        if (head[0] != 'B' || head[1] != 'S' || head[2] != 'J' || head[3] != 'B') return null;

        int verLen = BitConverter.ToInt32(head, 12);
        if (verLen < 0 || verLen > 0x400) return null;
        // layout: version string (padded to 4) → Flags(2) → stream count(2) → headers
        int versionEnd = (16 + verLen + 3) & ~3;
        if (versionEnd + 4 > gotN) return null;
        int streams = BitConverter.ToUInt16(head, versionEnd + 2);

        int p = versionEnd + 4;
        for (int i = 0; i < streams; i++)
        {
            if (p + 9 > gotN) return null;
            uint off = BitConverter.ToUInt32(head, p);
            uint size = BitConverter.ToUInt32(head, p + 4);
            int nameStart = p + 8;
            int end = nameStart;
            while (end < gotN && head[end] != 0) end++;
            string sname = Encoding.ASCII.GetString(head, nameStart, end - nameStart);
            if (sname == "#Strings")
            {
                // the module name (the original file name) is a string in here —
                // not necessarily the first entry (that's the <Module> type), so
                // scan the heap for the first "…​.dll" string
                if (size == 0 || size > 0x100000) return null;
                var buf = new byte[size];
                if (!Native.ReadProcessMemory(h, (IntPtr)(a + off), buf, (nuint)buf.Length, out got))
                    return null;
                gotN = (long)got;
                int q = 0;
                while (q < gotN)
                {
                    if (buf[q] == 0) { q++; continue; }
                    int e = q;
                    while (e < gotN && buf[e] != 0) e++;
                    string s = Encoding.UTF8.GetString(buf, q, e - q);
                    if (s.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                    {
                        foreach (var c in s)
                            if (!(char.IsLetterOrDigit(c) || ".-_ ()".Contains(c)))
                                goto nextString;        // garbage — keep looking
                        return s;
                    }
                nextString:
                    q = e + 1;
                }
                return null;
            }
            p = end + 1;
            p = (p + 3) & ~3;
        }
        return null;
    }

    /// <summary>
    /// Dumps a private-memory image: the heap copy IS the original file bytes,
    /// so this is a straight read of Size bytes from Base (unlike image modules,
    /// which are reconstructed section-by-section).
    /// </summary>
    public static string DumpRaw(IntPtr hProcess, ModuleInfo image, string outPath)
    {
        var buf = new byte[image.Size];
        if (!Native.ReadProcessMemory(hProcess, image.Base, buf, (nuint)buf.Length, out nuint got) || got != (nuint)buf.Length)
            throw new InvalidOperationException(
                $"could not read the full {MemoryRegion.FormatSize(image.Size)} image from {image.Path} " +
                $"(got {MemoryRegion.FormatSize((long)got)}) — the heap copy is not contiguous");
        File.WriteAllBytes(outPath, buf);
        return $"raw copy · {MemoryRegion.FormatSize(buf.Length)}" +
               (image.IsManaged ? " · managed assembly" : "");
    }
}
