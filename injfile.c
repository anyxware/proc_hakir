#include <windows.h>
#define DLLEXPORT __declspec(dllexport)

DLLEXPORT BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
        case DLL_THREAD_ATTACH:
            MessageBox(NULL, (LPCSTR) TEXT("Injection"), TEXT("DLL Injection"), 0);
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
return TRUE;
}
