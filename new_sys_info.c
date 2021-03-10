#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <winbase.h>
#include <psapi.h>
#include <stdio.h>
#include <winver.h>
#include <string.h>
#include <securitybaseapi.h>
#include "list.h"
#define delay 1000


typedef struct{
    PROCESSENTRY32 pe32;
    int status;
    float load;
    float kBytes;
    PROCESS_MEMORY_COUNTERS pmc; // pmc.PagefileUsage/1024.0/1024.0
    int pmc_flag;
    TCHAR  infoBuf[32767];
    int infoBuf_flag;
    char* processDescription;
    int OpenProcess_flag;
    unsigned long long prevProcessTime;
    unsigned long long prevTotalBytes;
}ProcessDATA;

typedef struct {
    int count;
    float cpuUsage;
    float memoryUsage;
    float memoryTotal;
    float dProcessorTime;
    unsigned long long prevProcessorTime;
    unsigned long long prevIdleTime;
}ProcessorDATA;

BOOL SetPrivilege(
        HANDLE hToken,          // access token handle
        LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
        BOOL bEnablePrivilege   // to enable or disable privilege
)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if ( !LookupPrivilegeValue(
            NULL,            // lookup privilege on local system
            lpszPrivilege,   // privilege to lookup
            &luid ) )        // receives LUID of privilege
    {
        //printf("LookupPrivilegeValue error: %u\n", GetLastError() );
        return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;
    if ( !AdjustTokenPrivileges(
            hToken,
            FALSE,
            &tp,
            sizeof(TOKEN_PRIVILEGES),
            (PTOKEN_PRIVILEGES) NULL,
            (PDWORD) NULL) ){
        //printf("AdjustTokenPrivileges error: %u\n", GetLastError() );
        return FALSE;
    }
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED){
        printf("The token does not have the specified privilege. \n");
        return FALSE;
    }
    return TRUE;
}

static unsigned long long FileTimeToInt64(const FILETIME ft) {
    return (((unsigned long long)(ft.dwHighDateTime))<<32)|((unsigned long long)ft.dwLowDateTime);
}

void t(char* test){
    printf("%s\n", test);
}

void* in_list(LIST* Data, int ID){
    ITEM* ptr = Data->head;
    while(ptr && ((ProcessDATA *)(ptr->data))->pe32.th32ProcessID != ID) ptr = ptr->next;
    if(!ptr) return NULL;
    return ptr->data;
}

void delete_unused(LIST* Data, int status){
    ITEM* ptr = Data->head, *ptr_prev = NULL;
    while(ptr){
        if(((ProcessDATA *)(ptr->data))->status != status){
            if (ptr == Data->head) Data->head = ptr->next;
            if (ptr == Data->tail) Data->tail = ptr_prev;
            if (ptr_prev) ptr_prev->next = ptr->next;
            free(ptr);
            if(ptr_prev) ptr = ptr_prev->next;
            else return;
        }else{
            ptr_prev = ptr;
            ptr = ptr->next;
        }
    }
}

void print_data(LIST* Data, ProcessorDATA processorData){
    ITEM* ptr = Data->head;
    ProcessDATA* data;
    int count = 0;
    while(ptr){
        count -= -1;
        data = (ProcessDATA*)(ptr->data);
        printf("%d\t%s\t", data->pe32.th32ProcessID,data->pe32.szExeFile);
        if(!(data->OpenProcess_flag)){
            printf("cant OpenProcess\n");
            ptr = ptr->next;
            continue;
        }
        if(data->load||1) printf("%.2f%%\t", data->load);
        if(data->kBytes||1) printf("%.2fkB/s\t", data->kBytes);
        if(data->pmc_flag||1) printf("%.2fMB\t", data->pmc.PagefileUsage/1024.0/1024.0);
        if(data->infoBuf_flag||1) printf(TEXT("%s\t"), data->infoBuf);
        if(data->processDescription||1) printf(TEXT("%s\t"), data->processDescription);
        printf("\n");
        ptr = ptr->next;
    }
    printf("CPU: %.2f%%\t", processorData.cpuUsage);
    printf("Memory: %.2fMB(%.2f%%)\t", processorData.memoryUsage / 1024 / 1024, processorData.memoryUsage / processorData.memoryTotal * 100);
    printf("Number of processes: %d\t", processorData.count);
    printf("\n");
}

char* description(char* filename){
    int versionInfoSize = GetFileVersionInfoSizeA(filename, NULL);
    if (!versionInfoSize) {
        return NULL;
    }
    char versionInfo[versionInfoSize];
    if (!GetFileVersionInfoA(filename, 0, versionInfoSize, versionInfo)) {
        return NULL;
    }
    DWORD *langCodeArray;
    UINT aLen;
    VerQueryValue(versionInfo, TEXT("\\VarFileInfo\\Translation"),
                  (LPVOID *) &langCodeArray, &aLen);
    TCHAR subBlock[25];
    wsprintf(subBlock, TEXT("\\StringFileInfo\\%04x%04x\\FileDescription"),
            LOWORD(langCodeArray[0]), HIWORD(langCodeArray[0]));
    UINT bufLen;
    char *tempBuf = NULL;
    VerQueryValue(versionInfo, subBlock, (LPVOID *) (&tempBuf), &bufLen);
    char* retBuf = (char*)malloc(bufLen);
    memcpy(retBuf, tempBuf, bufLen);
    return retBuf;
}

void GETCpuUsage(ProcessorDATA* processorData){
    unsigned long long intProcessorTime, intIdleTime;
    float dProcessorTime, dIdleTime;
    float cpuUsage;
    FILETIME idleTime, kernelTime, userTime;
    MEMORYSTATUSEX statex;

    statex.dwLength = sizeof (statex);
    GlobalMemoryStatusEx (&statex);

    GetSystemTimes(&idleTime, &kernelTime, &userTime);

    intProcessorTime = FileTimeToInt64(kernelTime) + FileTimeToInt64(userTime);
    intIdleTime = FileTimeToInt64(idleTime);

    dProcessorTime = (float)(intProcessorTime - processorData->prevProcessorTime);
    dIdleTime = (float )(intIdleTime - processorData->prevIdleTime);

    cpuUsage = (dProcessorTime ? 1.0f - dIdleTime/dProcessorTime : 0) * 100;

    processorData->cpuUsage = cpuUsage;
    processorData->memoryUsage = statex.ullTotalPhys - statex.ullAvailPhys;
    processorData->memoryTotal = statex.ullTotalPhys;
    processorData->count = 0;
    processorData->dProcessorTime = dProcessorTime;
    processorData->prevProcessorTime = intProcessorTime;
    processorData->prevIdleTime = intIdleTime;
}

void process_info(HANDLE hProcess, ProcessDATA* processData, ProcessorDATA* processorData){
    unsigned long long intProcessTime;
    unsigned long long TotalBytes;
    float dProcessTime;
    float load;
    float Bytes;
    FILETIME CreationTime, ExitTime, KernelTime, UserTime;
    IO_COUNTERS IoCounters;
    PROCESS_MEMORY_COUNTERS pmc;
    TCHAR  infoBuf[32767];
    DWORD  bufCharCount = 32767;
    TCHAR szModName[MAX_PATH];

    if(GetProcessTimes(hProcess, &CreationTime, &ExitTime, &KernelTime, &UserTime)) {
        intProcessTime = FileTimeToInt64(KernelTime) + FileTimeToInt64(UserTime);
        dProcessTime = (float) (intProcessTime - processData->prevProcessTime);
        load = (processorData->dProcessorTime ? dProcessTime / processorData->dProcessorTime : 0) * 100;
        processData->load = load;
        processData->prevProcessTime = intProcessTime;
    }
    else{
        processData->load = 666;
    }
    if(GetProcessIoCounters(hProcess, &IoCounters)){
        TotalBytes = IoCounters.ReadTransferCount + IoCounters.WriteTransferCount;
        Bytes = (TotalBytes - processData->prevTotalBytes);

        processData->kBytes = Bytes / 1024.0;
        processData->prevTotalBytes = TotalBytes;
    }
    else{
        processData->kBytes = 666;
    }
    if(GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))){
        processData->pmc = pmc;
        //processorData->memoryUsage += pmc.PagefileUsage;
        processData->pmc_flag = 1;
    }
    else{
        processData->pmc_flag = 0;
    }
    if (GetUserName(infoBuf, &bufCharCount)) {
        memcpy(processData->infoBuf, infoBuf, bufCharCount);
        processData->infoBuf_flag = 1;
    }
    else {
        processData->infoBuf_flag = 0;
    }
    //printf("%d\n",processData->pe32.th32ProcessID);
    if(GetModuleFileNameExA(hProcess, NULL, szModName, sizeof(szModName) / sizeof(TCHAR))) {
        processData->processDescription = description(szModName);
    }
    else{
        processData->processDescription = NULL;
    }
}

void update_list(LIST* Data, ProcessorDATA* processorData, int status){
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof( PROCESSENTRY32 );
    HANDLE hProcessSnap, hProcess, hToken;
    ProcessDATA* nowData;
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        CloseHandle(hProcessSnap);
        return;
    }
    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        return;
    }
    do {
        processorData->count += 1;
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
        OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken);
        SetPrivilege(hToken, TEXT("SeDebugPrivilege"), TRUE);
        //DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hProcess);
        nowData = (ProcessDATA*)in_list(Data, pe32.th32ProcessID);
        if(!nowData){
            ProcessDATA newData;
            newData.pe32 = pe32;
            newData.status = status;
            newData.load = 0;
            newData.kBytes = 0;
            newData.prevProcessTime = 0;
            newData.prevTotalBytes  = 0;
            nowData = (ProcessDATA*)list_append(Data, (void*)&newData, sizeof(newData));
        }
        nowData->status = status;
        if(hProcess){
            nowData->OpenProcess_flag = 1;
            process_info(hProcess, nowData, processorData);
        }
        else{
            nowData->OpenProcess_flag = 0;
        }
        //CloseHandle(hToken);
        CloseHandle(hProcess);\
    } while (Process32Next(hProcessSnap, &pe32));
    CloseHandle(hProcessSnap);
    delete_unused(Data, status);
}

int main(void){
    int status = 1;
    ProcessorDATA processorData;
    LIST* processData = list_init();
    for (int i = 0; i < 200; i++){
        GETCpuUsage(&processorData);
        update_list(processData, &processorData, status);
        print_data(processData, processorData);
        status *= -1;
        Sleep(1000);
    }
    list_clear(processData);
    return 0;
}