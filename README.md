<h1 align="center">Allycs</h1>
<p align="center"><i>Import Table Reconstructor powered by SysCaller (Scylla rebuild)</i></p>

---

## About

**Allycs** is a modernized Scylla rebuild using [SysCaller](https://github.com/SysCallerSDK/SysCaller) for native syscall powered PE import reconstruction. It avoids traditional API hooks by directly invoking syscalls, making it useful for stealthy dumping.

---

## Features

Whats new: 
- (SysCaller only supports x64)
- Native syscall usage (WinAPI-less execution)
- Added "Dont Compact Raw Data"
- Removed alot of bloat
- Powered by [SysCaller SDK](https://github.com/SysCallerSDK/SysCaller)

---

## Requirements

### Visual Studio 2022  
Ensure you have C++20 toolset enabled.

### [SysCaller](https://github.com/SysCallerSDK/SysCaller)
You will need to build SysCaller with the proper syscalls, more info below.

### [vcpkg](https://github.com/microsoft/vcpkg)
Install vcpkg if not already installed, then run:

```bash
vcpkg install distorm:x64-windows-static tinyxml2:x64-windows-static wtl:x64-windows-static
```

---

## Build Instructions

### Step 1. Build Requires Syscalls via SysCaller

1. Download and open the [Bind.exe](https://github.com/micREsoft/SysCaller/releases) (PY BuildTools are deprecated) 

2. Ensure the following syscall stubs are selected under the Integrity Tab:

```plaintext
SysAllocateVirtualMemoryEx
SysClose
SysCreateSection
SysCreateThreadEx
SysDuplicateObject
SysFreeVirtualMemory
SysGetContextThread
SysMapViewOfSection
SysOpenProcess
SysOpenSymbolicLinkObject
SysOpenThread
SysProtectVirtualMemory
SysQueryInformationFile
SysQueryInformationProcess
SysQueryInformationThread
SysQueryObject
SysQuerySymbolicLinkObject
SysQuerySystemInformation
SysQueryVirtualMemory
SysResumeProcess
SysResumeThread
SysSetContextThread
SysSetInformationThread
SysSuspendProcess
SysSuspendThread
SysTerminateProcess
SysUnmapViewOfSection
SysWriteVirtualMemory
```

3. After that run the Validation/Compatibility checks.

4. **Important**: When building SysCaller use the default (non obfuscated) stubs in Release mode.
Obfuscated stubs currently work only in Debug mode, due to unresolved configuration conflicts in Allycs.

5. Now open SysCaller.sln via Visual Studio 2022

6. Set build to `Release` if using default stubs, `Debug` if using obfuscated stubs, and C++ standard to **C++20** (If not already)

7. Build the project to generate `SysCaller.lib`

---

### Step 2. Integrate SysCaller Output

- Copy the built files from SysCaller into Allycs:

    ```
    SysCaller.lib     → sdk/SysCaller/lib
    SysFunctions.h    → sdk/SysCaller/include/Sys
    ```

---

### Step 3. Build Allycs

- Open `Allycs.sln` in Visual Studio 2022
- Set to `x64` & `Release` Mode if not already  
- Build the `Allycs` project  
- Output binary: `build\x64\Release\Allycs.exe`

---

## Usage

Run Allycs and have fun! Enjoy this modern rebuild of Scylla with Syscalls.

---

### Notes

If you want to integrate **Allycs into x64dbg**, you’ll need to modify x64dbg to call Allycs instead of Scylla. (After doing so follow along below)

#### Step 1. Convert Allycs from `.exe` to `.dll`

1. Open the Allycs project in Visual Studio 2022
2. In the project settings:
    - Change the output type from **Console Application** to **Dynamic Link Library**
    - Set `Configuration Type` to `Dynamic Library (.dll)`

#### Step 2. Create Allycs Export Definition File

Create a new file in your project root named:

- allycs_export_definitions.def

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

#### Step 3. Link the .def File in Visual Studio

1. Right click the Allycs project > Properties

2. Navigate to: Linker > Input

3. Set the Module Definition File to:

```plaintext
allycs_export_definitions.def
```

- Build the DLL. Now you can now load Allycs.dll from x64dbg in place of Scylla.dll!

## License

This project is licensed under **GNU General Public License v3.0** — see [LICENSE](LICENSE) for details.

---

## Disclaimer

Allycs is intended **strictly for educational and research use**.  
The author assumes no responsibility for any misuse or damage caused by this software.

---

<p align="center">
  <i>Built on the foundation of Scylla. Reinforced with native syscalls.</i>
</p>
