#include "util.h"
#include "pe_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

int check_pe_file(FILE *file, DOS_HEADER *dos_header) {
    read_dos_header(file, dos_header);
    if (dos_header->e_magic != DOS_SIGNATURE) {
        return 0;
    }
    fseek(file, dos_header->e_lfanew, SEEK_SET);
    DWORD nt_signature;
    fread(&nt_signature, sizeof(DWORD), 1, file);
    if (nt_signature != PE_SIGNATURE) {
        return 0;
    }
    return 1;
}
int print_PE_info(FILE *file, int* is_x64, DOS_HEADER *dos_header, NT_HEADERS *nt_headers) {
    if (dos_header->e_magic != DOS_SIGNATURE) {
        printf("Not a valid PE file (Missing MZ header).\n");
        return -1;
    }
    if (nt_headers->Signature != PE_SIGNATURE) {
        printf("Not a valid PE file (Missing PE signature).\n");
        return -1;
    }
    if (*is_x64 == 0) {
        printf("PE32 (32-bit) executable\n");
    } else if (*is_x64 == 1) {
        printf("PE32+ (64-bit) executable\n");
    } else {
        printf("Unknown PE format.\n");
    }
    return 0;
}

int read_headers(FILE *file, int *is_x64, DOS_HEADER *dos_header, NT_HEADERS *nt_headers, FILE_HEADER *file_header, OPTIONAL_HEADER *optional_header, SECTION_HEADER_TABLE *psection_header_table) {
    fseek(file, 0, SEEK_SET);
    read_dos_header(file, dos_header);
    out_debug("Done: Read DOS Header.\n");
    fseek(file, dos_header->e_lfanew, SEEK_SET);
    read_nt_headers(file, nt_headers);
    out_debug("Done: Read NT Headers.\n");
    if (nt_headers->OptionalHeader.Magic == 0x10B) {
        *is_x64 = 0;
    } else if (nt_headers->OptionalHeader.Magic == 0x20B) {
        *is_x64 = 1;
    } else {
        *is_x64 = -1;
    }
    
    *psection_header_table = (SECTION_HEADER *)malloc(sizeof(SECTION_HEADER) * file_header->NumberOfSections);
    read_section_header_table(file, *psection_header_table, file_header->NumberOfSections);
    out_debug("Done: Read All Section Headers.\n");
}

int read_dos_header(FILE *file, DOS_HEADER *dos_header) {
    fread(dos_header, sizeof(DOS_HEADER), 1, file);
}
int read_nt_headers(FILE *file, NT_HEADERS *nt_headers) {
    fread(nt_headers, sizeof(NT_HEADERS), 1, file);
}
int read_section_header_table(FILE *file, SECTION_HEADER_TABLE section_header_table, WORD numberOfSections) {
    fread(section_header_table, sizeof(SECTION_HEADER) * numberOfSections, 1, file);
}

void print_raw_headers(FILE* file, int* is_x64, DOS_HEADER *dos_header, NT_HEADERS *nt_headers, FILE_HEADER *file_header, OPTIONAL_HEADER *optional_header, SECTION_HEADER_TABLE section_header_table) {
    printf("DOS Header in bytes:\n");
    print_raw_bytes((BYTE *)dos_header, sizeof(DOS_HEADER), 0);
    printf("NT Header in bytes:\n");
    print_raw_bytes((BYTE *)nt_headers, sizeof(NT_HEADERS), 0);
    printf("NT File Header in bytes:\n");
    print_raw_bytes((BYTE *)file_header, sizeof(FILE_HEADER), 0);
    printf("NT Optional Header in bytes:\n");
    print_raw_bytes((BYTE *)optional_header, is_x64?OPTIONAL_HEADER_64_LENGTH:OPTIONAL_HEADER_32_LENGTH, 0);
    printf("Section Header in bytes:\n");
    print_raw_table_bytes((BYTE *)section_header_table, sizeof(SECTION_HEADER), file_header->NumberOfSections, 0);
}

void print_raw_bytes(BYTE *bytes, int length, int crop) {
    if(crop > 0) length = crop;
    for (int i = 0; i < length; i++) {
        printf("%02x ", bytes[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if(crop > 0) printf("...\n");
    printf("\n\n");
}
void print_raw_table_bytes(BYTE *table, int entry_length, int table_length, int crop) {
    if(crop > 0) entry_length = crop;
    for (int i=0; i<table_length; i++) {
        BYTE* entry = table + (i*entry_length);
        for (int j = 0; j < entry_length; j++) {
            printf("%02x ", entry[j]);
            if ((j + 1) % 16 == 0) printf("\n");
        }
        if(crop > 0) printf("...\n");
        printf("\n\n");
    }
    printf("\n\n");
}

void print_data_dictionary_table_info(FILE* file, DATA_DIRECTORY_TABLE *data_dictionary_table) {
    const char* directory_names[] = {
        "Export Directory",
        "Import Directory",
        "Resource Directory",
        "Exception Directory",
        "Security Directory",
        "Base Relocation Directory",
        "Debug Directory",
        "Architecture Directory",
        "Global Pointer Directory",
        "TLS Directory",
        "Load Configuration Directory",
        "Bound Import Directory",
        "IAT Directory",
        "Delay Import Directory",
        "COM Descriptor Directory",
        "Reserved Directory"
    };
    printf("Data Directory Table:\n");
    for(int i=0; i<sizeof(DATA_DIRECTORY_TABLE); i++) {
        DATA_DIRECTORY *current_directory = (DATA_DIRECTORY *)((char *)data_dictionary_table + (sizeof(DATA_DIRECTORY) * i));
        printf("%-30s: Virtual Address: 0x%08X, Size: 0x%08X\n", directory_names[i], current_directory->VirtualAddress, current_directory->Size);
    }
}

void print_section_header(SECTION_HEADER section_header) {
    printf("  Name: %.8s\n", section_header.Name);
    printf("  Physical Address: 0x%08X\n", section_header.PhysicalAddress);
    printf("  Virtual Address: 0x%08X\n", section_header.VirtualAddress);
    printf("  Size Of Raw Data: 0x%08X\n", section_header.SizeOfRawData);
    printf("  Pointer To Raw Data: 0x%08X\n", section_header.PointerToRawData);
}


void print_section_table_info(FILE *file, FILE_HEADER *file_header, SECTION_HEADER_TABLE section_header_table) {
    for(WORD i=0; i<file_header->NumberOfSections; i++) {
        printf("Section %d:\n", i);
        print_section_header(section_header_table[i]);
        fseek(file, section_header_table[i].PhysicalAddress, SEEK_SET);
        BYTE *bytes = (BYTE *)malloc(section_header_table[i].SizeOfRawData);
        fread(bytes, 1, section_header_table[i].SizeOfRawData, file);
        print_raw_bytes(bytes, section_header_table[i].SizeOfRawData, 80);
    }
}

void parse_text_section(FILE *file, SECTION_HEADER *text_section) {
    fseek(file, text_section->PointerToRawData, SEEK_SET);
    BYTE *code = malloc(text_section->SizeOfRawData);
    fread(code, 1, text_section->SizeOfRawData, file);
    
    print_raw_bytes(code, text_section->SizeOfRawData, 0);
    
    free(code);
}

