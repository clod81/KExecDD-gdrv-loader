#include <Windows.h>
#include <psapi.h>
#include <stdio.h>

void main() {
    LPVOID DriverBases[1024];
    CHAR DriverName[100];
    DWORD Needed;
    ULONG i, DriverCount;
    if (!EnumDeviceDrivers(DriverBases, sizeof(DriverBases), &Needed) || (Needed >= sizeof(DriverBases))) {
        printf("nope\n");
        return;
    }
    DriverCount = Needed / sizeof(DriverBases[0]);
    printf("driver count %i\n", DriverCount);
    for (i = 0; i < DriverCount; i++) {
        if (!GetDeviceDriverBaseNameA(DriverBases[i], DriverName, sizeof(DriverName))) {
            continue;
        }
        printf("driver name %s - %p\n", DriverName, DriverBases[i]);
    }
}
