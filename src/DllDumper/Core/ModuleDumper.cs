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
}
