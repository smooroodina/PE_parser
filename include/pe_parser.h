#include "util.h"
#include <stdio.h>

#ifndef PE_PARSER_H
#define PE_PARSER_H



// <DOS Header> 
// - identify the file as a DOS executable
// - (On windows, not important except e_magic, e_lfanew.)
#define DOS_HEADER_LENGTH 64
#define DOS_SIGNATURE 0x5A4D
typedef struct _DOS_header { 
    WORD e_magic;       // ***Magic Number. 0x5a4d ('MZ')
    WORD e_cblp;
    WORD e_cp;
    WORD e_crlc;
    WORD e_cparhdr;
    WORD e_minalloc;
    WORD e_maxalloc;
    WORD e_ss;
    WORD e_sp;
    WORD e_csum;
    WORD e_ip; 
    WORD e_cs;
    WORD e_lfarlc;
    WORD e_ovno;
    WORD e_res[4];
    WORD e_oemid;
    WORD e_oeminfo;
    WORD e_res2[10];
    DWORD e_lfanew;      // ***File address of new exe header. Determine the length of the PE Stub
} DOS_HEADER;

/**  ... DOS Stub ... **/



// <NT Headers>
// - metadata about the PE file
#define NT_HEADERS_32_LENGTH 248
#define NT_HEADERS_64_LENGTH 260
#define PE_SIGNATURE 0x00004550

//   <File Header>
//   - basic information about the PE file
#define FILE_HEADER_LENGTH 20
typedef struct _file_header {
    WORD  Machine;              // target machine architecture
    WORD  NumberOfSections;     // number of sections in the file.
    DWORD TimeDateStamp;        // file creation timestamp
    DWORD PointerToSymbolTable; // offset to the symbol table (usually 0)
    DWORD NumberOfSymbols;      // number of symbols in the symbol table
    WORD  SizeOfOptionalHeader; // size of the optional header
    WORD  Characteristics;      // characteristics of the file (e.g., executable, DLL).
} FILE_HEADER;

//   <Optional Header> 
//   - important information about the executable
//   - (actually, this is not optional but required.)
#define OPTIONAL_HEADER_32_LENGTH 224
#define OPTIONAL_HEADER_64_LENGTH 240
#define OPTIONAL_MAGIC_32 0x010B
#define OPTIONAL_MAGIC_64 0x020B
//       Data Directory
//       - single data directory entry in the PE header
//       - each entry points to specific information or data, which is generally located inside the PE sections area
#define DATA_DIRECTORY_SIZE 8
typedef struct _data_directory {
    DWORD VirtualAddress;   // location of the data directory
    DWORD Size;
} DATA_DIRECTORY;
//       Data Directory Table
//       - structure of multiple data directory entries
//       - allows access to each data directory by name rather then index
#define DATA_DIRECTORY_TABLE_LENGTH 16
typedef struct _data_directory_table {         // (generally) locate in | description
    DATA_DIRECTORY ExportDirectory;             // .text or .edata | functions and data exported by the module to be used by other modules or applications
    DATA_DIRECTORY ImportDirectory;             // .idata | lists the DLLs that the module imports and the functions or variables imported from those DLLs
    DATA_DIRECTORY ResourceDirectory;           // .rsrc | resources used by the application, such as icons, menus, dialogs, and other user interface elements
    DATA_DIRECTORY ExceptionDirectory;          // .pdata | data used for SEH (Structured Exception Handling), including exception handlers and information related to error handling
    DATA_DIRECTORY SecurityDirectory;           // .text | digital signature certificates for the executable, ensuring the authenticity and integrity of the file
    DATA_DIRECTORY BaseRelocationDirectory;     // .reloc | information necessary for relocating the module’s code and data when loaded at a different base address
    DATA_DIRECTORY DebugDirectory;              // .dbg or other section | information for debugging, such as symbol information, which helps debuggers identify variables and source code lines
    DATA_DIRECTORY ArchitectureDirectory;       // optional header | architecture-specific information, such as whether the module is for 32-bit or 64-bit systems
    DATA_DIRECTORY GlobalPtrDirectory;          // handled by runtime | information for managing global pointers, typically used in conjunction with DLLs
    DATA_DIRECTORY TLSDirectory;                // .tls | information related to TLS (Thread Local Storage), enabling each thread to have its own instance of data
    DATA_DIRECTORY LoadConfigurationDirectory;  // .text or configuration data for the loader, including flags and other information that affects how the module is loaded
    DATA_DIRECTORY BoundImportDirectory;        // .idata | information for bound imports, which are DLLs that are statically linked to the executable
    DATA_DIRECTORY IATDirectory;                // .idata | IAT (Import Address Table), which stores the addresses of imported functions once the module is loaded
    DATA_DIRECTORY DelayImportDirectory;        // .idata or other section | information for delayed imports, allowing functions to be resolved at runtime when first accessed, improving startup time and reducing memory usage
    DATA_DIRECTORY COMDescriptorDirectory;      // .text or dedicated COM section | information for Component Object Model (COM) objects, including the GUIDs for the interfaces supported by the module
    DATA_DIRECTORY ReservedDirectory;           // unused entries reserved for future extensions of the PE format
} DATA_DIRECTORY_TABLE;

// 32bit structure:
typedef struct _optional_header {
    // Standard fields:
    WORD    Magic;                  // PE type (0x10B for 32-bit, 0x20B for 64-bit)
    BYTE    MajorLinkerVersion;     // major version of the linker
    BYTE    MinorLinkerVersion;     // minor version of the linker
    DWORD   SizeOfCode;             // size of the code (.text) section
    DWORD   SizeOfInitializedData;      // size of initialized data
    DWORD   SizeOfUninitializedData;    // size of uninitialized data (BSS)
    DWORD   AddressOfEntryPoint;        // address where execution starts
    DWORD   BaseOfCode;             // memory address where the code section starts
    DWORD   BaseOfData;             // memory address where the data section starts (32-bit only)
    // NT additional fields:
    DWORD   ImageBase;              // preferred memory address for the file to be loaded
    DWORD   SectionAlignment;       // alignment of sections in memory
    DWORD   FileAlignment;          // alignment of sections in the file
    WORD    MajorOperatingSystemVersion;    // major OS version required
    WORD    MinorOperatingSystemVersion;    // major OS version required
    WORD    MajorImageVersion;      // major version of the image
    WORD    MinorImageVersion;      // minor version of the image
    WORD    MajorSubsystemVersion;  // major version of the subsystem
    WORD    MinorSubsystemVersion;  // minor version of the subsystem
    DWORD   Win32VersionValue;      // reserved, should be 0
    DWORD   SizeOfImage;            // total size of the loaded image in memory
    DWORD   SizeOfHeaders;          // combined size of all headers and section tables
    DWORD   CheckSum;               // checksum of the file (required for system files)
    WORD    Subsystem;              // target subsystem (e.g., Windows GUI, CUI)
    WORD    DllCharacteristics;     // DLL-specific characteristics
    DWORD   SizeOfStackReserve;     // reserved size for the stack
    DWORD   SizeOfStackCommit;      // committed size for the stack
    DWORD   SizeOfHeapReserve;      // reserved size for the heap
    DWORD   SizeOfHeapCommit;       // committed size for the heap
    DWORD   LoaderFlags;            // flags used by the loader (usually 0)
    DWORD   NumberOfRvaAndSizes;            // number of data directories
    DATA_DIRECTORY_TABLE DataDirectories;  // of data directories
} OPTIONAL_HEADER_32;
// 64bit structure:
typedef struct _optional_header_64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase; // 64-bit
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve; // 64-bit
    ULONGLONG   SizeOfStackCommit; // 64-bit
    ULONGLONG   SizeOfHeapReserve; // 64-bit
    ULONGLONG   SizeOfHeapCommit; // 64-bit
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    DATA_DIRECTORY_TABLE DataDirectories;
} OPTIONAL_HEADER_64;
// common base:
typedef struct _optional_header_common {
    WORD Magic;
    BYTE padding[238];
} OPTIONAL_HEADER;


// 32bit structure:
typedef struct _NT_headers {
    DWORD Signature;    //PE signature. 0x00004550 ('PE\0\0')
    FILE_HEADER FileHeader;
    OPTIONAL_HEADER_32 OptionalHeader32;
} NT_HEADERS_32;
// 64bit structure:
typedef struct _NT_headers_64 {
    DWORD Signature;    //PE signature. 0x00004550 ('PE\0\0')
    FILE_HEADER FileHeader;
    OPTIONAL_HEADER_64 OptionalHeader64;
} NT_HEADERS_64;
// common base:
typedef struct _NT_headers_common {
    DWORD Signature;    //PE signature. 0x00004550 ('PE\0\0')
    FILE_HEADER FileHeader;
    OPTIONAL_HEADER OptionalHeader;
} NT_HEADERS;


// <Section Headers>
// - metadata about each section in the PE file
// - describes how to interpret the raw data in each section, allowing the operating system to understand how to load and execute the code properly
#define SECTION_HEADER_LENGTH 40
typedef union {     // allows access to the same memory as either 'PhysicalAddress' or 'VirtualSize' depending on the context
    DWORD PhysicalAddress;  // used when the section is stored in a file
    DWORD VirtualSize;      // The total size of the section when loaded in memory (with null padding)
} MISC;
typedef struct _section_header {
  BYTE Name[8];  // section name (8-byte identifier)
  union {
    MISC;       // anonymous union; allows direct access
    MISC Misc;  // named union; allows access through the name 'Misc' (as in the winnt.h implementation)
  };
  DWORD VirtualAddress;         // memory address where the section will be loaded
  DWORD SizeOfRawData;          // size of the section's data in the file
  DWORD PointerToRawData;       // file offset to the section's data
  DWORD PointerToRelocations;   // file offset to relocations (if applicable)
  DWORD PointerToLinenumbers;   // file offset to line number information (if present)
  WORD  NumberOfRelocations;    // number of relocation entries for this section
  WORD  NumberOfLinenumbers;    // number of line number entries for this section
  DWORD Characteristics;        // flags describing the characteristics of the section (e.g., executable, readable)
} SECTION_HEADER, *SECTION_HEADER_TABLE;



// <Section Body>
// - contains the actual code and data for each section defined in the section headers
// - various types of sections exist optionally according to need:
//      .text, .data, .bss, .rdata, .idata, .edata, .rsrc, .reloc, ...

// .edata
//   <Emport Directory>
//   - DataDirectory[0] points to this
//   - managed as a single structure that provides information about the export details in a PE file
//   - includes information about the functions exported from this DLL to other modules, used during both compilation and runtime
typedef struct _export_directory {
    DWORD Characteristics;      // reserved, should be 0
    DWORD TimeDateStamp;        // time/date when the export data was created
    WORD MajorVersion;          // major version number
    WORD MinorVersion;          // minor version number
    DWORD Name;                 // RVA to DLL name
    DWORD Base;                 // starting ordinal number
    DWORD NumberOfFunctions;    // number of exported functions
    DWORD NumberOfNames;        // mumber of exported names
    DWORD AddressOfFunctions;   // RVA to an array of function pointers
    DWORD AddressOfNames;       // RVA to an array of names (for name lookup)
    DWORD AddressOfNameOrdinals;// RVA to an array of ordinals (to associate names with ordinals)
} EXPORT_DIRECTORY;


// .idata
//   <Import Directory Table (IDT)>
//   - DataDirectory[1] points to this
//   - not a fixed sized table, and the end of the table can be known as the first field of last descriptor of the array is filled with zero
#define IMPORT_DESCRIPTOR_LENTGH 40
typedef struct _import_directory_table_entry {
    union {
        DWORD Characteristics;      // 0 for terminating null import descriptor
        DWORD OriginalFirstThunk;   // RVA (Relative Virtual Address) to the ILT (Import Lookup Table); used for resolving function names during the linking process
    };
    DWORD TimeDateStamp;    // time/date the import data was created
    DWORD ForwarderChain;   // index into the forwarder chain
    DWORD Name;             // RVA to the DLL name
    DWORD FirstThunk;       // RVA to IAT (Import Address Table); the actual addresses of the functions used at runtime
} IMPORT_DIRECTORY_TABLE_ENTRY, *IMPORT_DIRECTORY_TABLE;

//   <Import Lookup Table (ILT) == Import Name Table (INT)>
//   - this table lists the actual functions or symbols that the executable needs to import
//   - contains references to function names (or ordinals) in the respective DLLs
typedef struct _import_lookup_table_entry {
    union {
        DWORD Ordinal;  // function ordinal
        DWORD NameRVA;  // RVA to the function name
    };
} IMPORT_LOOKUP_TABLE_ENTRY, *IMPORT_LOOKUP_TABLE;

//   <Import Address Table (IAT)>
//   - DataDirectory[12] points to this
//   - loader writes to this table the actual memory addresses of the imported functions once the DLLs are loaded
typedef struct _import_address_table_entry {
    DWORD FunctionAddress;            // Address of the imported function
} IMPORT_ADDRESS_TABLE_ENTRY, *IMPORT_ADDRESS_TABLE;


// .rsrc
//   <Resource Directory Table>
//   - DataDirectory[2] points to this
//   - information about resources (icons, images, strings, etc.)
//       <Resource Table Header>
#define RESOURCE_TABLE_HEADER_LENGTH 12
typedef struct resource_directory_table_header {
    DWORD   Characteristics;        // resource characteristics
    DWORD   TimeDateStamp;          // time/date the resource data was created
    WORD    MajorVersion;           // major version number
    WORD    MinorVersion;           // minor version number
    WORD    NumberOfNamedEntries;   // number of named entries
    WORD    NumberOfIdEntries;      // number of ID entries
} RESOURCE_TABLE_HEADER;
//       <Resource Directory Entry>
//       - each entry can point to a different resource directory (subdirectory) or to resource data directly
#define RESOURCE_TABLE_DIRECTORY_ENTRY_LENGTH 8
typedef struct _resource_table_directory_entry {
    union {
	    struct {
	        DWORD NameOffset:31;
	        DWORD NameIsString:1;
	    };
	    DWORD Name;
	    WORD Id;
    };
    union {
    	DWORD OffsetToData;
	    struct {
	        DWORD OffsetToDirectory:31;
	        DWORD DataIsDirectory:1;
	    };
    };
} RESOURCE_TABLE_DIRECTORY_ENTRY;
//       <Resource Data Entry>
//       - contains information about actual resource data
//       - points to the real data located within the .rsrc section
#define RESOURCE_TABLE_DATA_ENTRY_LENGTH 16
typedef struct _resource_data_entry {
    DWORD OffsetToData;  // RVA of actual resource data
    DWORD Size;          // size of the resource data in bytes
    DWORD CodePage;      // code page used to decode resource data
    DWORD Reserved;      // reserved, must be 0
} RESOURCE_TABLE_DATA_ENTRY;

typedef struct _resource_table {
    RESOURCE_TABLE_HEADER Header;                   // metadata
    RESOURCE_TABLE_DIRECTORY_ENTRY* DirectoryList;  // list of all entries (Named and ID entries together, listed sequentially)
    RESOURCE_TABLE_DATA_ENTRY* DataList;            // list of actual resource data entries
} RESOURCE_TABLE;


// .pdata
//   <Exception Table>
//   - DataDirectory[3] points to this
//   - represents the exception handling information for a PE file
//   - provides the necessary data for the operating system to handle exceptions properly
#define EXCEPTION_TABLE_ENTRY_LENGTH 12
typedef struct _exception_table_entry {
    DWORD NumberOfHandlers;     // number of exception handlers in the directory
    DWORD AddressOfHandlers;    // RVA to an array of exception handler records
    DWORD AddressOfAction;      // RVA to an action table, if applicable
} EXCEPTION_TABLE_ENTRY, *EXCEPTION_TABLE;
//   <Exception Handler>
//   - represents a single exception handler in the directory
//   - contains the address of the handler and its associated data
#define EXCEPTION_HANDLER_LENGTH 8
typedef struct _EXCEPTION_HANDLER {
    DWORD HandlerAddress;   // address of the exception handler
    DWORD Filter;           // filter used for the handler, if applicable
} EXCEPTION_HANDLER, *EXCEPTION_HANDLER_LIST;


// .reloc
//   <Relocation Table>
//   - DataDirectory[5] points to this
//   - contains entries that specify how to adjust addresses in the image
//   - used when the executable is loaded at a different base address than preferred
//       <Relocation Entry>
//       - each entry describes a single relocation that needs to be applied
#define RELOCATION_ENTRY_LENGTH 2
typedef struct _relocation_entry {
    WORD Offset:12; // offset within the section where the relocation is to be applied
    WORD Type:4;    // type of relocation (e.g., IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_HIGH, etc.)
} RELOCATION_ENTRY;
//      <Base Relocation Block>
//       - contains the starting address where relocation is needed and a list of relocation entries
//       - multiple relocation blocks may exist, allowing for efficient relocation of different parts of the image
typedef struct _base_relocation_block  {
    DWORD VirtualAddress;   // starting address in the image where the relocation is needed
    DWORD SizeOfBlock;      // size of this relocation block, including the header
    RELOCATION_ENTRY* RelocEntryList;
} BASE_RELOCATION_BLOCK;
typedef struct {
    BASE_RELOCATION_BLOCK* BaseBlocks;
} BASE_RELOCATION_TABLE;


// Function Declaration
int check_pe_file(FILE *file, DOS_HEADER *dos_header);
int read_headers(FILE *file, int *is_x64, DOS_HEADER *dos_header, NT_HEADERS *nt_headers, FILE_HEADER *file_header, OPTIONAL_HEADER *optional_header, SECTION_HEADER_TABLE *dsection_header_table);
int read_dos_header(FILE *file, DOS_HEADER *dos_header);
int read_nt_headers(FILE *file, NT_HEADERS *nt_headers);
int read_section_header_table(FILE *file, SECTION_HEADER_TABLE section_header_table, WORD NumberOfSections);


int print_PE_info(FILE *file, int *is_x64, DOS_HEADER *dos_header, NT_HEADERS *nt_headers);
void print_raw_headers(FILE* file, int* is_x64, DOS_HEADER *dos_header, NT_HEADERS *nt_headers, FILE_HEADER *file_header, OPTIONAL_HEADER *optional_header, SECTION_HEADER_TABLE section_header_table);
void print_raw_bytes(BYTE *header, int header_length, int crop);
void print_raw_table_bytes(BYTE *table, int entry_length, int table_length, int crop);

void print_data_dictionary_table_info(FILE* file, DATA_DIRECTORY_TABLE *data_dictionary_table);

void print_section_header(SECTION_HEADER section_header);
void print_section_table_info(FILE *file, FILE_HEADER *file_header, SECTION_HEADER_TABLE section_header_table);

void disassemble_code(BYTE *code, size_t length);
void parse_text_section(FILE *file, SECTION_HEADER *text_section);

#endif  // PE_PARSER