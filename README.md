# dll dumper

**A dark little toolbox for picking apart Unity / Mono games — record everything, inject everywhere, pull the dlls back out.**

`dll dumper` is a single-file Windows GUI that attaches to a running process and gives you the
whole picture: the Mono runtime (or CoreCLR), every managed assembly, every export, the full
memory map, and every file the process has loaded. Then it pushes back — inject a native `.dll`,
write shellcode into the target, or fire a C# entry point straight through the Mono runtime.
And when you need the file itself: **stopping a recording automatically pulls every dll that
appeared during it back out of the target's memory** — injected by this app *or by your own
external injector* — and tells you whether it could be recovered.

No NuGet packages. No installer. One `.exe`.

![UI](docs/screenshot.png)

---

## the simple view (default)

The intended flow — record, mod, stop, and it tells you if the dll came back:

1. pick a process on the left
2. hit the big **● RECORD** button — it flips to **■ STOP · 00:06** and counts up live
3. inject while it records: this app's **Inject ▶** row, or **your own external injector** —
   either way, a snapshot of the target's mapped images was taken when recording started
4. hit **■ STOP** — the image map is diffed against that snapshot and every dll that appeared
   during the session is dumped to the `recovered\` folder next to the exe, with the verdict
   right in the status line:
   `Recorded for 00:08 · 246 items · ✓ recovered MyMod.dll (96 KB)`
   or `✗ could not recover MyMod.dll — not found in the target's memory`
5. the three cards answer the only question that matters — **DLL / MEMORY / MONO ★**:
   `— nothing injected yet —` until something lands, then green
   `✓ TestPayload.dll → TestTarget (PID 1234)` (or red `✗` with the reason to chase in the log),
   and after Stop each card also shows `↻ recovered · 96 KB` (or red `↻ recover failed`)
6. the recover row is the manual escape hatch: pick any loaded module → **Recover ▶** → dumped
   to a file you choose. A dll you just injected shows up in the list automatically.

**Advanced ▸** (top-right) opens the full inspector: mono exports & assemblies, memory map,
mapped files, the recorded session log and the injection ledger.

## features

| | |
|---|---|
| **simple by default** | record → inject (ours or yours) → stop → the status line says if the dll could be recovered |
| **process picker** | live list of every running process (name, PID, window title, memory), filterable |
| **mono inspector** | auto-detects **Mono** *and* **CoreCLR** runtimes, dumps `mono_*` exports, every loaded assembly with type + method counts |
| **memory map** | full `VirtualQueryEx` walk — base, size, state, protect, type, owning module |
| **loaded files** | every module in the target with base address and on-disk size |
| **recorder** | click **● Record** and everything above streams into a timestamped log; **Save report** exports it |
| **3 injectors** | `.dll` loader, memory/shellcode, and Mono runtime invoke — each with a step-by-step log |
| **one session folder per recording** | Stop writes a neat timestamped folder — `report.txt` (log + injections + recover verdicts), `mono.txt`, `memory.txt`, `files.txt` and the `recovered\` dlls — zip it and send it as-is |
| **recover a dll** | dump any loaded module (patched, unpacked, or injected) straight out of the target's memory to disk |
| **injection ledger** | every injection is listed with mode, payload, and result (Success / Fail + why) |
| **single file** | self-contained x64 exe, zero dependencies, .NET 10 |

## the three injection modes

### 1. `.dll` — LoadLibraryW
Classic: write the path into the target, resolve `LoadLibraryW` remotely, spin a thread.
Use this for native plugins, bootstraps, and `.dll` menus.

### 2. memory — shellcode
Write arbitrary bytes into an `RX`/`RWX` region and run them on a fresh thread.
Use this for manual mappers and position-independent stubs.

### 3. mono — managed invoke
Builds a remote argument block (`fn, a0..a3, ret`) and a 41-byte x64 trampoline
(`push rsi / mov regs / sub rsp,0x20 / call rax / store rax / add rsp,0x20 / pop rsi / ret`),
then calls any managed entry point inside the target's own Mono runtime — e.g.
`TestPayload.Loader.Load()`. Works by resolving `mono_add_internal_call` /
`mono_runtime_invoke`-style targets from the runtime module in the target.

Leave the class/method empty and it **auto-picks the entry point** by reading the payload's
metadata (prefers names like `Loader.Load`, `Plugin.Init`, `Main`, `Start`).

Every mode logs each step: rights requested, bytes allocated, remote address, thread exit code,
module handle — so when something fails you know exactly where.

## recover a dll

### automatic — on stop

When you hit **■ STOP**, the target's mapped-image map is diffed against the snapshot taken at
record start. Every image that appeared during the session — whether it landed through this
app's injectors or **through your own injector, which the app never sees** — is read out of
memory and written to the session's `recovered\` subfolder, alongside the exported logs and
data. The status line reports each one: `✓ recovered MyMod.dll (96 KB)` or
`✗ could not recover …` with the reason. Mono-mapped assemblies are found through the memory
map even when they never appear in the native module list.

### manual — any module

Pick a module in the **recover** dropdown (a dll you just injected lands there automatically)
and hit **Recover ▶**. The module is read page-by-page out of the target's memory — guarded
pages become zeros instead of killing the dump — and rebuilt as a PE file on disk: headers
plus every section at its raw offset, metadata intact. Works for patched modules, unpacked
sections, injected payloads — anything mapped in the target.

## quick start

```powershell
# build
dotnet build DllDumper.slnx -c Release

# run
DllDumper.exe

# or launch with a process + tab preselected (handy for testing)
DllDumper.exe TestTarget Recorded
```

1. pick the target in the left list
2. hit the big **● RECORD**, let it run
3. inject — this app (**Inject ▶**, mono mode auto-picks the entry point) or your own injector
4. hit **■ STOP** — the status line reports whether the dll was recovered, and everything lands
   in one neat folder: `sessions\2026-10-20_152016_YourGame\` containing `report.txt` (full log,
   injections, recover verdicts), `mono.txt`, `memory.txt`, `files.txt` and `recovered\*.dll`.
   Zip that folder and send it to whoever is helping you — **Open folder** (next to Recover)
   jumps straight to it
5. **Advanced ▸** holds the full detail: **Mono / Memory / Files / Recorded / Injected** tabs

### samples

`samples/TestTarget` — a tiny x64 console app to practice on.
`samples/TestPayload` — a managed payload exposing `TestPayload.Loader.Load()` for mono-mode tests.

```powershell
dotnet run --project samples/TestTarget -c Release
DllDumper.exe TestTarget
```

## using it with Unity games (Mono builds)

1. start the game and let it reach the main menu
2. select the game in **dll dumper**
3. the **Advanced ▸ Mono** tab shows `mono-2.0-bdwgc.dll` (or similar) with its `mono_*` exports,
   plus every `Assembly-CSharp` / plugin assembly with live type & method counts
4. **● Record** before you mod — you now have a full baseline of the game's state
5. inject your loader `.dll` (mode 1) or a managed entry point (mode 3) — the ★ **MONO** card
   tells you whether the managed side landed. Using your own injector? That works too — the
   record-time baseline makes any new mapping visible regardless of how it got there
6. **■ STOP** — the dll that appeared during the session is pulled back out of the game's
   memory into `recovered\`, and the status line tells you if it worked
7. need a specific module on your own terms? the manual **recover** row dumps anything mapped

> IL2CPP builds have no embedded Mono runtime — those will show the file/module list only.
> That's still useful: you can see every mapped file and the memory layout.

## requirements

- Windows 10/11 x64
- for injecting into processes you don't own: run **as administrator**
- .NET 10 runtime *only if you run from source* — the published exe is self-contained

## building from source

```powershell
git clone <this-repo>
cd dll-dumper
dotnet build DllDumper.slnx -c Release
# single-file exe:
dotnet publish src/DllDumper/DllDumper.csproj -c Release -r win-x64 `
  --self-contained true -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true
```

## disclaimer

This tool is for **your own software** — reverse-engineering, debugging, and instrumenting
processes you own or have permission to test. Injecting into online games will trip anti-cheat
(EAC, BattlEye, Vanguard…) and can get your accounts banned; don't do it. The authors take no
responsibility for misuse.

## license

MIT — see [LICENSE](LICENSE).
