using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace DllDumper.Core;

/// <summary>
/// The three injection engines:
///   1. DLL     — classic LoadLibraryW injection (native + managed payloads that expose DllMain)
///   2. Memory  — raw byte payload written into a fresh allocation, optionally executed
///   3. Mono    — calls the target's own Mono embedding API to open an assembly,
///                resolve a static method and invoke it inside the target runtime
/// </summary>
public static class Injector
{
    private const uint CallTimeoutMs = 30_000;
    private const int MaxInvokeArgs = 32;

    // =========================================================================
    // 1) DLL injection
    // =========================================================================

    public static InjectionResult InjectDll(int pid, string dllPath, Action<string>? step = null)
    {
        var r = new InjectionResult();
        void S(string m) { r.Step(m); step?.Invoke(m); }

        try
        {
            if (!File.Exists(dllPath)) return Fail(r, step, $"payload not found: {dllPath}");
            dllPath = Path.GetFullPath(dllPath);
            S($"mode = DLL · payload = {dllPath} ({MemoryRegion.FormatSize(new FileInfo(dllPath).Length)})");

            IntPtr h = OpenTarget(pid, out string? openErr);
            if (h == IntPtr.Zero) return Fail(r, step, openErr ?? "could not open process");
            try
            {
                if (!Check64Bit(h, out string? archErr)) return Fail(r, step, archErr!);
                S($"process opened · rights = 0x{Native.INJECT_RIGHTS:X}");

                // remote copy of the dll path
                byte[] pathBytes = Encoding.Unicode.GetBytes(dllPath + "\0");
                IntPtr remotePath = Native.VirtualAllocEx(h, IntPtr.Zero, (nuint)pathBytes.Length,
                    Native.MEM_COMMIT | Native.MEM_RESERVE, Native.PAGE_READWRITE);
                if (remotePath == IntPtr.Zero) return Fail(r, step, "VirtualAllocEx failed: " + Native.LastError());
                S($"allocated {pathBytes.Length} bytes for the path at {Hex(remotePath)}");

                if (!Native.WriteProcessMemory(h, remotePath, pathBytes, (nuint)pathBytes.Length, out _))
                    return Fail(r, step, "WriteProcessMemory failed: " + Native.LastError());
                S("path written into the target");

                // LoadLibraryW, mapped correctly even when it is forwarded to kernelbase
                IntPtr loadLib = ResolveInRemote(pid, "kernel32.dll", "LoadLibraryW", out string owner);
                S($"LoadLibraryW resolved to {Hex(loadLib)} (owner: {owner})");

                IntPtr thread = Native.CreateRemoteThread(h, IntPtr.Zero, (nuint)0,
                    loadLib, remotePath, 0, IntPtr.Zero);
                if (thread == IntPtr.Zero) return Fail(r, step, "CreateRemoteThread failed: " + Native.LastError());
                S("remote thread started");

                if (!WaitThread(thread, out string? waitErr))
                    return Fail(r, step, waitErr!);
                Native.GetExitCodeThread(thread, out uint exitCode);
                Native.CloseHandle(thread);
                S($"thread finished · LoadLibraryW returned 0x{exitCode:X8}");

                Native.VirtualFreeEx(h, remotePath, (nuint)0, Native.MEM_RELEASE);

                if (exitCode == 0)
                    return Fail(r, step, "LoadLibraryW returned NULL — the target refused the dll " +
                        "(wrong architecture, missing dependencies, or the file is not a valid module)");

                // the returned HMODULE is truncated to 32 bits by GetExitCodeThread,
                // so read the real 64-bit base back from the module list
                var mod = FindModule(pid, dllPath);
                r.Summary = mod is not null
                    ? $"loaded {mod.Name} at {mod.BaseHex} ({MemoryRegion.FormatSize(mod.Size)})"
                    : $"module handle 0x{exitCode:X8} (full base not visible in module list)";
                S("injection succeeded · " + r.Summary);
                r.Success = true;
                return r;
            }
            finally { Native.CloseHandle(h); }
        }
        catch (Exception ex)
        {
            return Fail(r, step, ex.Message);
        }
    }

    // =========================================================================
    // 2) Memory injection (raw payload)
    // =========================================================================

    public static InjectionResult InjectMemory(int pid, string payloadPath, bool execute, Action<string>? step = null)
    {
        var r = new InjectionResult();
        void S(string m) { r.Step(m); step?.Invoke(m); }

        try
        {
            if (!File.Exists(payloadPath)) return Fail(r, step, $"payload not found: {payloadPath}");
            payloadPath = Path.GetFullPath(payloadPath);
            byte[] payload = File.ReadAllBytes(payloadPath);
            if (payload.Length == 0) return Fail(r, step, "payload file is empty");
            S($"mode = MEMORY · payload = {payloadPath} ({payload.Length} bytes · execute = {execute})");

            IntPtr h = OpenTarget(pid, out string? openErr);
            if (h == IntPtr.Zero) return Fail(r, step, openErr ?? "could not open process");
            try
            {
                if (!Check64Bit(h, out string? archErr)) return Fail(r, step, archErr!);
                S($"process opened · rights = 0x{Native.INJECT_RIGHTS:X}");

                IntPtr remote = Native.VirtualAllocEx(h, IntPtr.Zero, (nuint)payload.Length,
                    Native.MEM_COMMIT | Native.MEM_RESERVE, Native.PAGE_READWRITE);
                if (remote == IntPtr.Zero) return Fail(r, step, "VirtualAllocEx failed: " + Native.LastError());
                S($"allocated {payload.Length} bytes at {Hex(remote)} (PAGE_READWRITE)");

                if (!Native.WriteProcessMemory(h, remote, payload, (nuint)payload.Length, out nuint written))
                    return Fail(r, step, "WriteProcessMemory failed: " + Native.LastError());
                S($"wrote {written} of {payload.Length} bytes");

                if (!execute)
                {
                    r.Summary = $"payload resident at {Hex(remote)} · {payload.Length} bytes written (not executed)";
                    S("memory-only injection done · " + r.Summary);
                    r.Success = true;
                    return r;
                }

                if (!Native.VirtualProtectEx(h, remote, (nuint)payload.Length,
                        0x40 /*PAGE_EXECUTE_READWRITE*/, out _))
                    return Fail(r, step, "VirtualProtectEx failed: " + Native.LastError());
                Native.FlushInstructionCache(h, remote, (nuint)payload.Length);
                S("protection changed to PAGE_EXECUTE_READWRITE · instruction cache flushed");

                IntPtr thread = Native.CreateRemoteThread(h, IntPtr.Zero, (nuint)0,
                    remote, IntPtr.Zero, 0, IntPtr.Zero);
                if (thread == IntPtr.Zero) return Fail(r, step, "CreateRemoteThread failed: " + Native.LastError());
                S("remote thread started at payload entry point");

                if (!WaitThread(thread, out string? waitErr))
                    return Fail(r, step, waitErr!);
                Native.GetExitCodeThread(thread, out uint exitCode);
                Native.CloseHandle(thread);
                S($"thread finished · exit code 0x{exitCode:X8}");

                r.Summary = $"payload at {Hex(remote)} · {payload.Length} bytes · executed · exit 0x{exitCode:X8}";
                S("memory injection succeeded · " + r.Summary);
                r.Success = true;
                return r;
            }
            finally { Native.CloseHandle(h); }
        }
        catch (Exception ex)
        {
            return Fail(r, step, ex.Message);
        }
    }

    // =========================================================================
    // 3) Mono injection (open assembly + resolve + invoke inside the runtime)
    // =========================================================================

    public static InjectionResult InjectMono(int pid, string dllPath, string ns, string cls,
        string method, int? paramCount, Action<string>? step = null)
    {
        var r = new InjectionResult();
        void S(string m) { r.Step(m); step?.Invoke(m); }
        var allocs = new List<IntPtr>();

        try
        {
            if (!File.Exists(dllPath)) return Fail(r, step, $"payload not found: {dllPath}");
            dllPath = Path.GetFullPath(dllPath);
            S($"mode = MONO · payload = {dllPath} ({MemoryRegion.FormatSize(new FileInfo(dllPath).Length)})");
            S($"entry = {(string.IsNullOrEmpty(ns) ? "(global)" : ns)}.{cls}.{method}" +
              (paramCount is null ? " (param count: auto)" : $" (param count: {paramCount})"));

            IntPtr h = OpenTarget(pid, out string? openErr);
            if (h == IntPtr.Zero) return Fail(r, step, openErr ?? "could not open process");
            try
            {
                if (!Check64Bit(h, out string? archErr)) return Fail(r, step, archErr!);

                // --- locate the runtime ---------------------------------------
                var modules = GetModules(pid);
                var rt = MonoInspector.Detect(modules);
                if (rt is null)
                    return Fail(r, step, "no managed runtime module found in the target " +
                        "(mono*.dll / GameAssembly.dll / coreclr.dll). " +
                        "This looks like a native process — use DLL or Memory mode.");

                S($"runtime = {rt.KindName} · module = {rt.ModuleName} at {Hex(rt.ModuleBase)} " +
                  $"· {rt.Exports.Count} exports" +
                  (string.IsNullOrEmpty(rt.ExportError) ? "" : $" ({rt.ExportError})"));

                if (rt.Kind == RuntimeKind.Il2Cpp)
                    return Fail(r, step, "this target is IL2CPP — the mono_* API does not exist. " +
                        "Use DLL mode (native plugin) or Memory mode instead.");
                if (rt.Kind == RuntimeKind.CoreClr)
                    return Fail(r, step, "this target is CoreCLR/.NET, not Mono — use DLL mode instead.");

                // --- resolve the API we need ----------------------------------
                ulong Need(string name)
                {
                    var a = rt.AddressOf(name);
                    if (a is null)
                        throw new InvalidOperationException(
                            $"the target's {rt.ModuleName} does not export \"{name}\" — cannot continue");
                    return a.Value;
                }
                bool Has(string name) => rt.AddressOf(name) is not null;

                ulong
                    fnRootDomain = Need("mono_get_root_domain"),
                    fnAttach = Need("mono_thread_attach"),
                    fnGetImage = Need("mono_assembly_get_image"),
                    fnClassFromName = Need("mono_class_from_name"),
                    fnRuntimeInvoke = Need("mono_runtime_invoke");

                bool hasDomainOpen = Has("mono_domain_assembly_open");
                bool hasPlainOpen = Has("mono_assembly_open");
                if (!hasDomainOpen && !hasPlainOpen)
                    throw new InvalidOperationException(
                        "neither mono_domain_assembly_open nor mono_assembly_open is exported");

                S("mono API resolved: get_root_domain, thread_attach, assembly_open, " +
                  "get_image, class_from_name, runtime_invoke" +
                  (Has("mono_class_get_methods") ? ", class_get_methods" : "") +
                  (Has("mono_method_signature") ? ", method_signature" : ""));

                // --- remote string helpers ------------------------------------
                IntPtr Alloc(int size)
                {
                    IntPtr p = Native.VirtualAllocEx(h, IntPtr.Zero, (nuint)size,
                        Native.MEM_COMMIT | Native.MEM_RESERVE, Native.PAGE_READWRITE);
                    if (p == IntPtr.Zero) throw new InvalidOperationException("VirtualAllocEx failed: " + Native.LastError());
                    allocs.Add(p);
                    return p;
                }
                IntPtr AllocString(string s)
                {
                    byte[] b = Encoding.UTF8.GetBytes(s + "\0");
                    IntPtr p = Alloc(b.Length);
                    if (!Native.WriteProcessMemory(h, p, b, (nuint)b.Length, out _))
                        throw new InvalidOperationException("WriteProcessMemory(string) failed: " + Native.LastError());
                    return p;
                }
                ulong ReadU64(IntPtr addr)
                {
                    var buf = new byte[8];
                    if (!Native.ReadProcessMemory(h, addr, buf, 8, out _)) return 0;
                    return BitConverter.ToUInt64(buf, 0);
                }
                uint ReadU32(IntPtr addr)
                {
                    var buf = new byte[4];
                    if (!Native.ReadProcessMemory(h, addr, buf, 4, out _)) return 0;
                    return BitConverter.ToUInt32(buf, 0);
                }
                string? ReadUtf8(IntPtr addr, int max = 512)
                {
                    if (addr == IntPtr.Zero) return null;
                    var buf = new byte[max];
                    if (!Native.ReadProcessMemory(h, addr, buf, (nuint)max, out nuint read)) return null;
                    int len = 0;
                    while (len < (int)read && buf[len] != 0) len++;
                    return Encoding.UTF8.GetString(buf, 0, len);
                }

                IntPtr pDll = AllocString(dllPath);
                IntPtr pNs = AllocString(ns ?? "");
                IntPtr pCls = AllocString(cls ?? "");
                IntPtr pMeth = AllocString(method ?? "");
                S($"payload path copied into target at {Hex(pDll)}");

                // --- the call chain -------------------------------------------
                ulong domain = Call(h, Need("mono_get_root_domain"), S);
                if (domain == 0) return Fail(r, step, "mono_get_root_domain() returned NULL");
                S($"mono_get_root_domain() → 0x{domain:X}");

                ulong attach = Call(h, Need("mono_thread_attach"), S, domain);
                S($"mono_thread_attach(0x{domain:X}) → 0x{attach:X} (remote thread attached to the runtime)");

                ulong assembly;
                if (hasDomainOpen)
                {
                    assembly = Call(h, Need("mono_domain_assembly_open"), S, domain, (ulong)pDll);
                    S($"mono_domain_assembly_open(domain, \"{dllPath}\") → 0x{assembly:X}");
                }
                else
                {
                    IntPtr pStatus = Alloc(4);
                    assembly = Call(h, Need("mono_assembly_open"), S, (ulong)pDll, (ulong)pStatus);
                    uint status = ReadU32(pStatus);
                    S($"mono_assembly_open(\"{dllPath}\", &status) → 0x{assembly:X} · status = {status}");
                }

                if (assembly == 0)
                    return Fail(r, step, "the target runtime could not open the assembly — " +
                        "check that the file is a valid managed dll the runtime's profile can read " +
                        "(and that the path is readable by the target process)");

                ulong image = Call(h, Need("mono_assembly_get_image"), S, assembly);
                if (image == 0) return Fail(r, step, "mono_assembly_get_image() returned NULL");
                S($"mono_assembly_get_image() → 0x{image:X}");

                ulong klass = Call(h, fnClassFromName, S, image, (ulong)pNs, (ulong)pCls);
                if (klass == 0)
                    return Fail(r, step, $"type not found: \"{(string.IsNullOrEmpty(ns) ? "" : ns + ".")}{cls}\" — " +
                        "check the namespace and class name exactly as declared in the dll " +
                        "(use the Mono tab search to find it)");
                S($"mono_class_from_name(\"{ns}\", \"{cls}\") → 0x{klass:X}");

                // --- resolve the method ---------------------------------------
                ulong monoMethod = 0;
                var seenNames = new List<string>();

                if (paramCount is int pc && Has("mono_class_get_method_from_name"))
                {
                    monoMethod = Call(h, Need("mono_class_get_method_from_name"), S, klass, (ulong)pMeth, (ulong)(uint)pc);
                    S($"mono_class_get_method_from_name(klass, \"{method}\", {pc}) → 0x{monoMethod:X}");
                }

                if (monoMethod == 0 && Has("mono_class_get_methods") && Has("mono_method_get_name"))
                {
                    IntPtr pIter = Alloc(8);            // void* iter = NULL
                    S("iterating mono_class_get_methods() …");
                    ulong iterFn = Need("mono_class_get_methods");
                    ulong nameFn = Need("mono_method_get_name");
                    for (int i = 0; i < 4096; i++)
                    {
                        ulong m = Call(h, iterFn, S, klass, (ulong)pIter);
                        if (m == 0) break;
                        ulong namePtr = Call(h, nameFn, S, m);
                        string? name = ReadUtf8((IntPtr)unchecked((long)namePtr));
                        if (name is not null && seenNames.Count < 500) seenNames.Add(name);
                        if (name is not null && string.Equals(name, method, StringComparison.Ordinal))
                        {
                            monoMethod = m;
                            break;
                        }
                    }
                }

                if (monoMethod == 0)
                {
                    string hint = seenNames.Count > 0
                        ? " methods on this type: " + string.Join(", ", seenNames.Take(40)) +
                          (seenNames.Count >= 40 ? ", …" : "")
                        : "";
                    return Fail(r, step, $"method \"{method}\" not found on {cls}.{hint}");
                }
                S($"method resolved → 0x{monoMethod:X}");

                // --- must be static: mono_runtime_invoke takes obj = NULL -----
                if (Has("mono_method_get_flags"))
                {
                    IntPtr pAttrs = Alloc(4);
                    Call(h, Need("mono_method_get_flags"), S, monoMethod, (ulong)pAttrs);
                    uint attrs = ReadU32(pAttrs);
                    if (attrs != 0)
                    {
                        if ((attrs & 0x0010) == 0)   // MethodAttributes.Static
                            return Fail(r, step, $"\"{method}\" is an instance method — the entry point " +
                                "must be static (e.g. public static void Load())");
                        S("signature check: method is static ✓");
                    }
                    else
                        S("signature check inconclusive (mono_method_get_flags did not fill attrs) — continuing");
                }

                // --- argument buffer ------------------------------------------
                uint argCount = (uint)(paramCount ?? 0);
                if (Has("mono_method_signature") && Has("mono_signature_get_param_count"))
                {
                    ulong sig = Call(h, Need("mono_method_signature"), S, monoMethod);
                    ulong count = Call(h, Need("mono_signature_get_param_count"), S, sig);
                    argCount = (uint)(count & 0xFFFFFFFF);
                    S($"mono_signature_get_param_count() → {argCount} parameter(s)");
                }
                else if (paramCount is null)
                {
                    S("no signature API available — assuming 0 parameters");
                }

                if (argCount > MaxInvokeArgs)
                    return Fail(r, step, $"method takes {argCount} parameters — Dll Dumper supports up to {MaxInvokeArgs}");

                IntPtr pArgs = argCount == 0 ? IntPtr.Zero : Alloc((int)argCount * 8);   // zeroed void*[n]
                IntPtr pExc = Alloc(8);                                                  // MonoObject* exception
                S($"argument buffer = {(pArgs == IntPtr.Zero ? "NULL (0 params)" : Hex(pArgs))} · exception slot = {Hex(pExc)}");

                // --- invoke -----------------------------------------------------
                ulong ret = Call(h, fnRuntimeInvoke, S, monoMethod, 0UL,
                    (ulong)pArgs, (ulong)pExc);
                S($"mono_runtime_invoke({method}) → 0x{ret:X}");

                ulong exc = ReadU64(pExc);
                if (exc != 0)
                {
                    string excDesc = $"exception object 0x{exc:X}";
                    if (Has("mono_object_get_class") && Has("mono_class_get_name"))
                    {
                        ulong excClass = Call(h, Need("mono_object_get_class"), S, exc);
                        ulong cnamePtr = Call(h, Need("mono_class_get_name"), S, excClass);
                        string? cname = ReadUtf8((IntPtr)unchecked((long)cnamePtr));
                        if (!string.IsNullOrEmpty(cname)) excDesc = cname;
                    }
                    if (Has("mono_object_to_string") && Has("mono_string_to_utf8"))
                    {
                        IntPtr pErr = Alloc(32);
                        ulong strObj = Call(h, Need("mono_object_to_string"), S, exc, (ulong)pErr);
                        if (strObj != 0)
                        {
                            ulong utf8 = Call(h, Need("mono_string_to_utf8"), S, strObj);
                            string? msg = ReadUtf8((IntPtr)unchecked((long)utf8), 2048);
                            if (!string.IsNullOrEmpty(msg)) excDesc += ": " + msg;
                        }
                    }
                    return Fail(r, step, $"the method ran but threw a managed exception — {excDesc}");
                }

                r.Success = true;
                r.Summary = $"invoked {cls}.{method}() inside {rt.KindName} · returned 0x{ret:X}";
                S("mono injection succeeded · " + r.Summary);
                S($"chain: domain=0x{domain:X} assembly=0x{assembly:X} image=0x{image:X} " +
                  $"class=0x{klass:X} method=0x{monoMethod:X} return=0x{ret:X}");
                return r;
            }
            finally
            {
                foreach (var p in allocs)
                    Native.VirtualFreeEx(h, p, (nuint)0, Native.MEM_RELEASE);
                Native.CloseHandle(h);
            }
        }
        catch (Exception ex)
        {
            return Fail(r, step, ex.Message);
        }
    }

    // =========================================================================
    // remote-call trampoline
    // =========================================================================

    /*
     *  The Windows x64 calling convention puts the first four arguments in
     *  rcx, rdx, r8, r9 — but CreateRemoteThread only gives us one (lpParameter).
     *  So we write a 41-byte stub that loads a small argument block and calls
     *  the target function, storing the 64-bit result back into the block:
     *
     *      struct Block { void* fn; void* a0; void* a1; void* a2; void* a3; ulong ret; }  // 48 bytes
     *
     *      push rsi
     *      mov  rsi, rcx            ; block*
     *      mov  rax, [rsi]
     *      mov  rcx, [rsi+8]
     *      mov  rdx, [rsi+16]
     *      mov  r8,  [rsi+24]
     *      mov  r9,  [rsi+32]
     *      sub  rsp, 0x20           ; shadow space (alignment already correct)
     *      call rax
     *      mov  [rsi+40], rax       ; store full 64-bit result
     *      add  rsp, 0x20
     *      pop  rsi
     *      ret
     */
    private static readonly byte[] Stub =
    {
        0x56,
        0x48, 0x89, 0xCE,
        0x48, 0x8B, 0x06,
        0x48, 0x8B, 0x4E, 0x08,
        0x48, 0x8B, 0x56, 0x10,
        0x4C, 0x8B, 0x46, 0x18,
        0x4C, 0x8B, 0x4E, 0x20,
        0x48, 0x83, 0xEC, 0x20,
        0xFF, 0xD0,
        0x48, 0x89, 0x46, 0x28,
        0x48, 0x83, 0xC4, 0x20,
        0x5E,
        0xC3,
    };

    /// <summary>Runs <paramref name="fn"/> inside the target with up to four arguments.</summary>
    private static ulong Call(IntPtr h, ulong fn, Action<string>? step, params ulong[] args)
    {
        if (args.Length > 4) throw new InvalidOperationException("trampoline supports at most 4 arguments");
        if (fn == 0) throw new InvalidOperationException("target function address is NULL");

        IntPtr block = IntPtr.Zero, stub = IntPtr.Zero, thread = IntPtr.Zero;
        try
        {
            block = Native.VirtualAllocEx(h, IntPtr.Zero, 48,
                Native.MEM_COMMIT | Native.MEM_RESERVE, Native.PAGE_READWRITE);
            if (block == IntPtr.Zero) throw new InvalidOperationException("VirtualAllocEx(block) failed: " + Native.LastError());

            var buf = new byte[48];
            BitConverter.GetBytes(fn).CopyTo(buf, 0);
            for (int i = 0; i < args.Length; i++)
                BitConverter.GetBytes(args[i]).CopyTo(buf, 8 + i * 8);
            if (!Native.WriteProcessMemory(h, block, buf, 48, out _))
                throw new InvalidOperationException("WriteProcessMemory(block) failed: " + Native.LastError());

            stub = Native.VirtualAllocEx(h, IntPtr.Zero, (nuint)Stub.Length,
                Native.MEM_COMMIT | Native.MEM_RESERVE, 0x40 /*PAGE_EXECUTE_READWRITE*/);
            if (stub == IntPtr.Zero) throw new InvalidOperationException("VirtualAllocEx(stub) failed: " + Native.LastError());
            if (!Native.WriteProcessMemory(h, stub, Stub, (nuint)Stub.Length, out _))
                throw new InvalidOperationException("WriteProcessMemory(stub) failed: " + Native.LastError());
            Native.FlushInstructionCache(h, stub, (nuint)Stub.Length);

            thread = Native.CreateRemoteThread(h, IntPtr.Zero, (nuint)0, stub, block, 0, IntPtr.Zero);
            if (thread == IntPtr.Zero)
                throw new InvalidOperationException("CreateRemoteThread failed: " + Native.LastError());

            uint wait = Native.WaitForSingleObject(thread, CallTimeoutMs);
            if (wait == Native.WAIT_TIMEOUT)
            {
                Native.TerminateThread(thread, 0);
                throw new TimeoutException(
                    "a call into the target runtime timed out after 30s and was terminated — " +
                    "the target may be unstable, try attaching a debugger");
            }
            if (wait != Native.WAIT_OBJECT_0)
                throw new InvalidOperationException("WaitForSingleObject failed: " + Native.LastError());

            var outBuf = new byte[48];
            if (!Native.ReadProcessMemory(h, block, outBuf, 48, out _))
                throw new InvalidOperationException("ReadProcessMemory(result) failed: " + Native.LastError());
            return BitConverter.ToUInt64(outBuf, 40);
        }
        finally
        {
            if (thread != IntPtr.Zero) { Native.WaitForSingleObject(thread, 500); Native.CloseHandle(thread); }
            if (block != IntPtr.Zero) Native.VirtualFreeEx(h, block, (nuint)0, Native.MEM_RELEASE);
            if (stub != IntPtr.Zero) Native.VirtualFreeEx(h, stub, (nuint)0, Native.MEM_RELEASE);
        }
    }

    // =========================================================================
    // shared helpers
    // =========================================================================

    private static InjectionResult Fail(InjectionResult r, Action<string>? step, string message)
    {
        r.Success = false;
        r.Summary = message;
        r.Step("FAILED · " + message);
        step?.Invoke("FAILED · " + message);
        return r;
    }

    private static IntPtr OpenTarget(int pid, out string? error)
    {
        error = null;
        IntPtr h = Native.OpenProcess(Native.INJECT_RIGHTS, false, pid);
        if (h == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            error = Native.FriendlyError(err);
        }
        return h;
    }

    private static bool Check64Bit(IntPtr h, out string? error)
    {
        error = null;
        if (!Native.IsWow64Process(h, out bool wow64))
        {
            error = "IsWow64Process failed: " + Native.LastError();
            return false;
        }
        if (wow64)
        {
            error = "the target process is 32-bit — this build of Dll Dumper injects into 64-bit processes only. " +
                    "Rebuild the project with <PlatformTarget>x86</PlatformTarget> to target 32-bit processes.";
            return false;
        }
        return true;
    }

    private static bool WaitThread(IntPtr thread, out string? error)
    {
        uint w = Native.WaitForSingleObject(thread, CallTimeoutMs);
        if (w == Native.WAIT_TIMEOUT)
        {
            Native.TerminateThread(thread, 0);
            error = "the remote thread timed out after 30s and was terminated";
            return false;
        }
        if (w != Native.WAIT_OBJECT_0)
        {
            error = "WaitForSingleObject failed: " + Native.LastError();
            return false;
        }
        error = null;
        return true;
    }

    /// <summary>
    /// Finds the remote address of a function: locate it locally (which also resolves
    /// forwarded exports such as kernel32 → kernelbase), then add the delta to the
    /// same module's base inside the target.
    /// </summary>
    private static IntPtr ResolveInRemote(int pid, string moduleName, string func, out string owner)
    {
        IntPtr localMod = Native.GetModuleHandleW(moduleName);
        if (localMod == IntPtr.Zero)
            throw new InvalidOperationException($"GetModuleHandle({moduleName}) failed in this process");
        IntPtr localAddr = Native.GetProcAddress(localMod, func);
        if (localAddr == IntPtr.Zero)
            throw new InvalidOperationException($"GetProcAddress({func}) failed");

        string ownerName = moduleName;
        IntPtr ownerBase = localMod;
        using (var self = Process.GetCurrentProcess())
        {
            foreach (ProcessModule m in self.Modules)
            {
                long b = m.BaseAddress.ToInt64();
                long a = localAddr.ToInt64();
                if (a >= b && a < b + m.ModuleMemorySize)
                {
                    ownerName = m.ModuleName;
                    ownerBase = m.BaseAddress;
                    break;
                }
            }
        }

        long delta = localAddr.ToInt64() - ownerBase.ToInt64();
        foreach (var m in GetModules(pid))
        {
            if (string.Equals(m.Name, ownerName, StringComparison.OrdinalIgnoreCase))
            {
                owner = $"{ownerName} + 0x{delta:X}";
                return (IntPtr)(m.Base.ToInt64() + delta);
            }
        }

        throw new InvalidOperationException($"module {ownerName} is not loaded inside the target process");
    }

    private static List<ModuleInfo> GetModules(int pid)
    {
        var list = new List<ModuleInfo>();
        using var p = Process.GetProcessById(pid);
        foreach (ProcessModule m in p.Modules)
        {
            list.Add(new ModuleInfo
            {
                Name = m.ModuleName ?? "?",
                Path = Safe(() => m.FileName ?? ""),
                Base = m.BaseAddress,
                Size = m.ModuleMemorySize,
            });
        }
        return list;

        static string Safe(Func<string> f) { try { return f(); } catch { return ""; } }
    }

    private static ModuleInfo? FindModule(int pid, string path)
    {
        try
        {
            foreach (var m in GetModules(pid))
                if (string.Equals(m.Path, path, StringComparison.OrdinalIgnoreCase))
                    return m;
        }
        catch { /* process exited */ }
        return null;
    }

    private static string Hex(IntPtr p) => $"0x{p.ToInt64():X}";
}
