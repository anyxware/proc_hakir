#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

static const int PATH_BUFFER_SIZE = 256;

DWORD getProcessId(const char *processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot) {
        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &entry)) {
            do {
                if (!strcmp(entry.szExeFile, processName)) {
                    return entry.th32ProcessID;
                }
            } while (Process32Next(hSnapshot, &entry));
        }
    }
    else {
        return 0;
    }
}

int main(int argc, char *argv[]) {
/*
    if (argc != 3) {
        printf("Cannot find require parameters\n");
        printf("Usage: dll-injector.exe <process name> <path to DLL>\n");
        exit(0);
    }
*/
    char dllLibFullPath[256];

    LPCSTR processName = "mspaint.exe";//argv[1];
    LPCSTR dllLibName = "libpaint_killer.dll";//argv[2];

    DWORD processId = getProcessId(processName);
    if (!processId) {
        printf("[x] Cannot find process %s\n", processName);
        exit(1);
    }
    printf("[*] Found process %s(PID = %lu)\n", processName, processId);

    if (!GetFullPathName(dllLibName, sizeof(dllLibFullPath), dllLibFullPath, NULL)) {
        printf("[x] Cannot get full path to %s\n", dllLibName);
        exit(1);
    }
    printf("[*] DLL library %s was successfully found\n", dllLibFullPath);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL) {
        printf("[x] Cannot open process with id %lu\n", processId);
        exit(1);
    }

    LPVOID dllAllocatedMemory = VirtualAllocEx(hProcess, NULL, strlen(dllLibFullPath), MEM_RESERVE | MEM_COMMIT,
                                               PAGE_EXECUTE_READWRITE);
    if (dllAllocatedMemory == NULL) {
        printf("[x] Cannot allocate memory for DLL-library\n");
        exit(1);
    }
    printf("[*] Allocated %llu bytes at %#08x region\n", strlen(dllLibFullPath), dllAllocatedMemory);

    if (!WriteProcessMemory(hProcess, dllAllocatedMemory, dllLibFullPath, strlen(dllLibFullPath) + 1, NULL)) {
        printf("[x] Cannot write process memory\n");
        exit(1);
    }

    LPVOID loadLibrary = (LPVOID) GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

    printf("[*] Starting remote thread at process %s(PID = %lu)\n", processName, processId);
    HANDLE remoteThreadHandler = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE) loadLibrary,
                                                    dllAllocatedMemory, 0, NULL);
    if (remoteThreadHandler == NULL) {
        printf("[-] Cannot create remote thread in process with id %lu\n", processId);
        exit(1);
    }

    CloseHandle(hProcess);

    return 0;
}