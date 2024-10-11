// dllmain.c
#include <windows.h>
#include <stdio.h>

// DllMain 함수: DLL로 로드될 때 동작
BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            MessageBox(NULL, "DLL Loaded", "DLL Info", MB_OK);
            break;
        case DLL_PROCESS_DETACH:
            MessageBox(NULL, "DLL Unloaded", "DLL Info", MB_OK);
            break;
    }
    return TRUE;
}

// EXE로 실행될 때 동작하는 main 함수
int main() {
    printf("This is an executable, not just a DLL.\n");
    return 0;
}