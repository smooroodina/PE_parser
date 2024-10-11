#include "pe_parser.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <PE file path>\n", argv[0]);
        return 1;
    }
    const char *filename = argv[1];
    FILE *file = fopen(filename, "r");
    if(!file) {
        fprintf(stderr, "Error: The file '%s' does not exist or cannot be opened.\n", filename);
        return 1;
    }
    printf("Analyzing file '%s'...\n", filename);

    int *is_x64 = (int *)malloc(sizeof(int));
    DOS_HEADER *dos_header = (DOS_HEADER *)malloc(sizeof(DOS_HEADER));
    NT_HEADERS *nt_headers = (NT_HEADERS *)malloc(sizeof(NT_HEADERS));
    NT_HEADERS_32 *nt_headers_32 = (NT_HEADERS_32 *)nt_headers;
    NT_HEADERS_64 *nt_headers_64 = (NT_HEADERS_64 *)nt_headers;
    FILE_HEADER *file_header = (FILE_HEADER *)((BYTE *)nt_headers + sizeof(nt_headers->Signature));
    OPTIONAL_HEADER *optional_header = (OPTIONAL_HEADER *)((BYTE *)file_header + sizeof(FILE_HEADER));
    OPTIONAL_HEADER_32 *optional_header_32 = (OPTIONAL_HEADER_32 *)optional_header;
    OPTIONAL_HEADER_64 *optional_header_64 = (OPTIONAL_HEADER_64 *)optional_header;
    DATA_DIRECTORY_TABLE *data_directory_table_32 = (DATA_DIRECTORY_TABLE *)((BYTE *)optional_header + 96);
    DATA_DIRECTORY_TABLE *data_directory_table_64 = (DATA_DIRECTORY_TABLE *)((BYTE *)optional_header + 112);

    SECTION_HEADER_TABLE section_header_table = NULL;

    if (!check_pe_file(file, dos_header)) {
        fprintf(stderr, "Error: Not a valid PE file.\n");
        fclose(file);
        return 1;
    }
    read_headers(file, is_x64, dos_header, nt_headers, file_header, optional_header, &section_header_table);
    if(print_PE_info(file, is_x64, dos_header, nt_headers) == -1) {
        return 1;
    }

    print_raw_headers(file, is_x64, dos_header, nt_headers, file_header, optional_header, section_header_table);
    print_section_table_info(file, file_header, section_header_table);
    print_data_dictionary_table_info(file, is_x64?data_directory_table_64:data_directory_table_32);
    return 0;
}