#include <windows.h>

static HINSTANCE s_hinstDLL = NULL;

BOOL WINAPI
DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        s_hinstDLL = hinstDLL;
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
