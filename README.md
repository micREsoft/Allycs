# Allycs

## About

**Allycs** is a modernized [Scylla](https://github.com/NtQuery/Scylla) rebuild that leverages the [SysCaller SDK](https://github.com/SysCallerSDK/SysCaller) to perform PE import reconstruction using native syscalls.

---

## Build Requirements

* **Visual Studio 2022** (C++20 toolset)
* **SysCaller** build SysCaller with the proper resolver and indirect syscall support (see Build Instructions).
* **vcpkg** (for dependencies used by Allycs)

Install required packages with vcpkg:

```bash
vcpkg install distorm:x64-windows-static tinyxml2:x64-windows-static wtl:x64-windows-static
```

---

## Quick Overview: Indirect syscalls

Allycs now uses SysCaller's indirect syscall mode by default, which then resolves syscall numbers at runtime and issues indirect calls into `ntdll` (or a resolved trampoline). This improves compatibility across Windows builds compared to hardcoded syscall numbers.

> If you want to use direct or inline syscalls instead, modify the Allycs src, SysCaller build settings, and adjust `syscaller_config.h` accordingly.

---

## Build Instructions

### Step 1 — Build SysCaller (required)

1. Download `Bind.exe` (the official BuildTools GUI) from the SysCaller releases page and open it. (PY BuildTools are deprecated.)
2. In Bind → Settings → General:

   * Enable Bindings.
   * Select Indirect syscall mode under *Syscall Mode*.
3. Under the Integrity tab ensure the syscall stubs listed under *Required Syscalls* are selected (see the list below).
4. Build SysCaller in Visual Studio 2022 (C++20).

   * Use **Release** for default (non-obfuscated) stubs.
   * If you want obfuscated stubs then build in **Debug** (Note: obfuscated stubs currently only work reliably in Debug mode for Allycs (see notes below)).
5. Ensure the following preprocessor definitions are set in `syscaller_config.h` before building:

```cpp
#define SYSCALLER_INDIRECT
#define SYSCALLER_BINDINGS
#define SYSCALLER_RESOLVER_PEB_LDR
```

6. Build the SysCaller project as .dll to produce `SysCaller.dll` and `SysCaller.lib`.

**Required syscall stubs (select these in Bind → Integrity):**

```
SysIndirectAllocateVirtualMemoryEx
SysIndirectClose
SysIndirectCreateThreadEx
SysIndirectFreeVirtualMemory
SysIndirectOpenProcess
SysIndirectOpenSymbolicLinkObject
SysIndirectProtectVirtualMemory
SysIndirectQueryInformationProcess
SysIndirectQuerySymbolicLinkObject
SysIndirectQuerySystemInformation
SysIndirectQueryVirtualMemory
SysIndirectResumeProcess
SysIndirectSetInformationThread
SysIndirectSuspendProcess
SysIndirectTerminateProcess
SysIndirectUnmapViewOfSection
```

---

### Step 2 — Integrate SysCaller into Allycs

Copy the following build outputs/files from your SysCaller build into the Allycs repo before building Allycs:

```
SysCaller.lib     → sdk/SysCaller/lib
SysCaller.dll     → path/to/Allycs.exe (same folder as final binary)
SysFunctions.h    → sdk/SysCaller/include/Sys
```

**Note:** Place `SysCaller.dll` next to `Allycs.exe` (or ensure it is discoverable in the same directory or via PATH) so the Allycs executable can load it at runtime.

---

### Step 3 — Build Allycs

1. Open `Allycs.sln` in Visual Studio 2022.
2. Set the platform to **x64** and configuration to **Release** (unless using obfuscated stubs which in that case follow the steps for obfuscated stubs).
3. Build the `Allycs` project.

---

## Integration with x64dbg

If you want to integrate Allycs into x64dbg (replace Scylla):

1. Convert Allycs to a DLL:

   * In Visual Studio project settings, change the output type from **Console Application** to **Dynamic Link Library** (set `Configuration Type` to `Dynamic Library (.dll)`).
2. Add an export definition file `allycs_export_definitions.def` with the required exports:

```def
LIBRARY Allycs
EXPORTS
    DumpProcessW @ 1
    AllycsDumpCurrentProcessW @2
    AllycsDumpCurrentProcessA @3
    AllycsDumpProcessW        @4
    AllycsDumpProcessA        @5
    AllycsRebuildFileW        @6
    AllycsRebuildFileA        @7
    AllycsVersionInformationW @8
    AllycsVersionInformationA @9
    AllycsVersionInformationDword @10
    AllycsStartGui            @11
    AllycsIatSearch           @12
    AllycsIatFixAutoW         @13
```

3. Link the `.def` file:

   * Project → Properties → Linker → Input → *Module Definition File* → `allycs_export_definitions.def`
4. Build the DLL and load it in x64dbg in place of Scylla.

---

## Dev Notes

* Allycs and SysCaller only support x64.
* Obfuscated stubs in SysCaller currently require Debug configuration to be used with Allycs. This is a known config edge case, for Release builds use the default (non obfuscated) stubs.
* Make sure `SysCaller.dll` is present next to `Allycs.exe` at runtime.
* Be mindful that runtime behaviors like PEB walking, export parsing, and RWX allocations can be flagged by defensive tooling in some environments.

---

## License

This project is released under the **GNU General Public License v3.0 (GPL-3.0)**. See the `LICENSE` file for full details.

---

## Disclaimer

Allycs is intended **strictly for educational and research use**. The maintainers assume no responsibility for misuse or damage resulting from the use of this software.

---

<p align="center">
  <i>Built on the foundation of Scylla. Reinforced with native syscalls.</i>
</p>
