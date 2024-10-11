#include <windows.h>
#include <stdio.h>

int main() {
    // DLL 파일 로드
    HINSTANCE hinstLib = LoadLibrary(TEXT("test_hybrid.dll.exe"));
    
    if (hinstLib != NULL) {
        printf("DLL loaded successfully.\n");

        // 필요한 경우, DLL 내에서 특정 함수 호출 가능 (여기서는 생략)

        // DLL 언로드
        BOOL fFreeResult = FreeLibrary(hinstLib);
        if (fFreeResult) {
            printf("DLL unloaded successfully.\n");
        } else {
            printf("Failed to unload DLL.\n");
        }
    } else {
        printf("Failed to load DLL.\n");
    }

    return 0;
}