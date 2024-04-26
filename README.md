# KexecDD-gdrv-loader
This is the same KExecDD exploit (https://github.com/floesen/KExecDD).

Rather than having to find the correct NTOSKRNL_WRITE_GADGET and CI_OPTIONS using a debugger for Kernel debugging on the target system, this comes together with a modified version of https://github.com/v1k1ngfr/gdrv-loader to calculate these offsets on the target system. A lot of the `gdrv-loader` code base is left untouched and not really needed.

Note: the stubs for `nt!FsRtlInitializeFileLock` and `ci!CiInitialize` might change in newer versions which might break the offset calculation.
This has been tested on a Windows 10 (Build 19045.4191).

## Usage

Coming soon


## More information

Coming soon
