using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

namespace DllDumper.Core;

/// <summary>
/// Detects the managed runtime inside a target process (Mono / IL2CPP / CoreCLR),
/// reads its export table, and walks the metadata of every .NET assembly the
/// process has loaded — assemblies, namespaces, types and methods.
/// </summary>
public static class MonoInspector
{
    // -------------------------------------------------------------------------
    // Runtime detection
    // -------------------------------------------------------------------------

    public static MonoRuntime? Detect(IReadOnlyList<ModuleInfo> modules)
    {
        ModuleInfo? mono = null, best = null;
        ModuleInfo? gameAssembly = null, clr = null;

        foreach (var m in modules)
        {
            string name = m.Name;
            if (name.StartsWith("mono", StringComparison.OrdinalIgnoreCase) &&
                name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
            {
                // prefer the real runtime over shims like "MonoBleedingEdge" proxies
                if (best is null || name.Contains("bdwgc", StringComparison.OrdinalIgnoreCase))
                    best = m;
                mono ??= m;
            }
            else if (name.Equals("GameAssembly.dll", StringComparison.OrdinalIgnoreCase))
                gameAssembly = m;
            else if (name.Equals("clr.dll", StringComparison.OrdinalIgnoreCase) ||
                     name.Equals("coreclr.dll", StringComparison.OrdinalIgnoreCase))
                clr = m;
        }

        var mod = best ?? mono ?? gameAssembly ?? clr;
        if (mod is null) return null;

        var kind = (best ?? mono) is not null ? RuntimeKind.Mono
            : gameAssembly is not null ? RuntimeKind.Il2Cpp
            : RuntimeKind.CoreClr;

        return Build(mod, kind);
    }

    private static MonoRuntime Build(ModuleInfo mod, RuntimeKind kind)
    {
        var rt = new MonoRuntime
        {
            Kind = kind,
            ModuleName = mod.Name,
            ModulePath = mod.Path,
            ModuleBase = mod.Base,
        };

        if (string.IsNullOrEmpty(mod.Path) || !File.Exists(mod.Path))
        {
            rt.ExportError = "runtime module file could not be read from disk";
            return rt;
        }

        try
        {
            var exports = PeExports.Read(mod.Path);
            foreach (var (name, rva, forwarded) in exports)
            {
                var e = new MonoExport
                {
                    Name = name,
                    Rva = rva,
                    Forwarded = forwarded,
                    Address = unchecked((ulong)(mod.Base.ToInt64() + rva)),
                };
                rt.Exports.Add(e);
                if (!rt.ByName.ContainsKey(name)) rt.ByName[name] = e;
            }
            rt.Exports.Sort((a, b) => string.CompareOrdinal(a.Name, b.Name));
        }
        catch (Exception ex)
        {
            rt.ExportError = $"export table unreadable: {ex.Message}";
        }

        return rt;
    }

    // -------------------------------------------------------------------------
    // Managed metadata (assemblies → types → methods)
    // -------------------------------------------------------------------------

    /// <summary>Reads the metadata of one file. Returns null if it is not a .NET assembly.</summary>
    public static AssemblyScan? ScanFile(string path)
    {
        try
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return null;
            using var fs = File.OpenRead(path);
            using var pe = new PEReader(fs, PEStreamOptions.LeaveOpen);
            if (!pe.HasMetadata) return null;

            var reader = pe.GetMetadataReader();
            if (!reader.IsAssembly) return null;

            var scan = new AssemblyScan
            {
                Path = path,
                Name = reader.GetString(reader.GetAssemblyDefinition().Name),
            };

            foreach (var th in reader.TypeDefinitions)
            {
                var td = reader.GetTypeDefinition(th);
                string typeName = reader.GetString(td.Name);
                if (typeName == "<Module>") continue;

                string ns = reader.GetString(td.Namespace);
                var ts = new TypeScan { FullName = string.IsNullOrEmpty(ns) ? typeName : ns + "." + typeName };

                foreach (var mh in td.GetMethods())
                {
                    var md = reader.GetMethodDefinition(mh);
                    ts.Methods.Add(reader.GetString(md.Name));
                }

                scan.TypeCount++;
                scan.MethodCount += ts.Methods.Count;
                scan.Types.Add(ts);
            }

            return scan;
        }
        catch
        {
            return null;   // native DLL, truncated file, locked file, ...
        }
    }

    /// <summary>Scans every not-yet-scanned file in <paramref name="newPaths"/>.</summary>
    public static MonoScanResult ScanAssemblies(IEnumerable<string> newPaths)
    {
        var result = new MonoScanResult();
        foreach (var path in newPaths)
        {
            var scan = ScanFile(path);
            if (scan is null) continue;
            result.Assemblies.Add(scan);
            result.TotalTypes += scan.TypeCount;
            result.TotalMethods += scan.MethodCount;
        }
        return result;
    }

    // -------------------------------------------------------------------------
    // PE export table (manual parse — PEReader does not expose exports)
    // -------------------------------------------------------------------------

    public static class PeExports
    {
        /// <summary>Returns (name, rva, isForwarded) triples sorted by name.</summary>
        public static List<(string Name, uint Rva, bool Forwarded)> Read(string path)
        {
            var list = new List<(string, uint, bool)>();
            using var fs = File.OpenRead(path);
            using var br = new BinaryReader(fs);

            if (fs.Length < 0x40) return list;
            if (br.ReadUInt16() != 0x5A4D) return list;                 // 'MZ'

            fs.Position = 0x3C;
            int pe = br.ReadInt32();
            if (pe <= 0 || pe + 24 > fs.Length) return list;

            fs.Position = pe;
            if (br.ReadUInt32() != 0x00004550) return list;             // 'PE\0\0'

            fs.Position = pe + 4 + 2;
            ushort sectionCount = br.ReadUInt16();
            fs.Position = pe + 4 + 16;
            ushort optSize = br.ReadUInt16();

            fs.Position = pe + 24;
            ushort magic = br.ReadUInt16();
            bool pe32Plus = magic == 0x20B;
            if (!pe32Plus && magic != 0x10B) return list;

            int ddOffset = pe32Plus ? 112 : 96;
            fs.Position = pe + 24 + ddOffset;                           // data directory #0 = exports
            uint expRva = br.ReadUInt32();
            uint expSize = br.ReadUInt32();
            if (expRva == 0) return list;

            // section table
            var sections = new (uint VirtAddr, uint VirtSize, uint RawPtr, uint RawSize)[sectionCount];
            long sectionTable = pe + 24 + optSize;
            for (int i = 0; i < sectionCount; i++)
            {
                fs.Position = sectionTable + i * 40;
                br.ReadBytes(8);                                       // name
                uint vsize = br.ReadUInt32();
                uint vaddr = br.ReadUInt32();
                uint rawsize = br.ReadUInt32();
                uint rawptr = br.ReadUInt32();
                sections[i] = (vaddr, vsize, rawptr, rawsize);
            }

            long RvaToOffset(uint rva)
            {
                foreach (var s in sections)
                {
                    uint span = Math.Max(s.VirtSize, s.RawSize);
                    if (span == 0) continue;
                    if (rva >= s.VirtAddr && rva < s.VirtAddr + span)
                        return s.RawPtr + (rva - s.VirtAddr);
                }
                return -1;
            }

            long expOff = RvaToOffset(expRva);
            if (expOff < 0 || expOff + 40 > fs.Length) return list;

            fs.Position = expOff;
            br.ReadUInt32(); br.ReadUInt32();                           // signature + timestamp
            br.ReadUInt16(); br.ReadUInt16();                           // versions
            br.ReadUInt32();                                           // name rva
            br.ReadUInt32();                                           // ordinal base
            uint numFuncs = br.ReadUInt32();
            uint numNames = br.ReadUInt32();
            uint addrFuncs = br.ReadUInt32();
            uint addrNames = br.ReadUInt32();
            uint addrOrds = br.ReadUInt32();

            if (numNames > 200_000 || numFuncs > 200_000) return list;

            long funcsOff = RvaToOffset(addrFuncs);
            long namesOff = RvaToOffset(addrNames);
            long ordsOff = RvaToOffset(addrOrds);
            if (funcsOff < 0 || namesOff < 0 || ordsOff < 0) return list;

            var funcRvas = new uint[numFuncs];
            fs.Position = funcsOff;
            for (uint i = 0; i < numFuncs; i++) funcRvas[i] = br.ReadUInt32();

            for (uint i = 0; i < numNames; i++)
            {
                fs.Position = namesOff + i * 4;
                uint nameRva = br.ReadUInt32();
                long nameOff = RvaToOffset(nameRva);
                if (nameOff < 0 || nameOff >= fs.Length) continue;

                fs.Position = nameOff;
                var bytes = new List<byte>(32);
                while (fs.Position < fs.Length && bytes.Count < 256)
                {
                    byte b = br.ReadByte();
                    if (b == 0) break;
                    bytes.Add(b);
                }
                string name = System.Text.Encoding.ASCII.GetString(bytes.ToArray());

                fs.Position = ordsOff + i * 2;
                ushort ord = br.ReadUInt16();
                if (ord >= numFuncs) continue;
                uint funcRva = funcRvas[ord];

                // a function RVA that lands inside the export directory is a forwarder string
                bool forwarded = funcRva >= expRva && funcRva < expRva + expSize;
                list.Add((name, funcRva, forwarded));
            }

            list.Sort((a, b) => string.CompareOrdinal(a.Item1, b.Item1));
            return list;
        }
    }
}
