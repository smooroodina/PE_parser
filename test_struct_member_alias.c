#include <stdio.h>
#include <minwindef.h>

typedef union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;
    } MISC;

typedef struct _section_header {
    union {
        MISC;
        MISC Misc;
    };

} section_header;

int main() {
    section_header header;

    // PhysicalAddress에 값을 할당
    header.PhysicalAddress = 0x12345678;

    // VirtualSize에 값을 할당
    header.VirtualSize = 0x87654321;

    // 두 필드의 값 출력
    printf("PhysicalAddress: 0x%X\n", header.PhysicalAddress);
    printf("VirtualSize: 0x%X\n", header.VirtualSize);
    printf("Misc.PhysicalAddress: 0x%X\n", header.Misc.PhysicalAddress);
    printf("Misc.VirtualSize: 0x%X\n", header.Misc.VirtualSize);
    printf("Misc: 0x%X\n", header.Misc);


    return 0;
}