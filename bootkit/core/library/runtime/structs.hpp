#pragma once

extern "C"
{
    #include <Uefi.h>
    #include <Library/UefiLib.h>
    #include <Library/UefiBootServicesTableLib.h>
    #include <Library/BaseLib.h>
    #include <sal.h>
}


typedef long long LONGLONG;
typedef unsigned long long ULONGLONG;
typedef void* PVOID;
typedef unsigned long long SIZE_T;
typedef long NTSTATUS;
typedef unsigned long ULONG;
typedef VOID* PEPROCESS;
typedef VOID* HANDLE;
typedef unsigned char UCHAR;

struct MM_COPY_ADDRESS
{
    PHYSICAL_ADDRESS PhysicalAddress;
};

#define RESTRICTED_POINTER

struct nt_list_entry_t
{
  struct nt_list_entry_t* Flink;
  struct nt_list_entry_t* Blink;
};

typedef nt_list_entry_t NT_LIST_ENTRY;
typedef NT_LIST_ENTRY* PNT_LIST_ENTRY;
typedef PNT_LIST_ENTRY RESTRICTED_POINTER PRNT_LIST_ENTRY;

typedef unsigned short USHORT;
typedef char CHAR;
typedef wchar_t WCHAR;

typedef CHAR* PCHAR, * LPCH, * PCH;
typedef WCHAR* PWCHAR, * LPWCH, * PWCH;

typedef struct _STRING {
  USHORT Length;
  USHORT MaximumLength;
#ifdef MIDL_PASS
  [size_is(MaximumLength), length_is(Length)]
#endif // MIDL_PASS
    _Field_size_bytes_part_opt_(MaximumLength, Length) PCHAR Buffer;
} STRING;

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
#ifdef MIDL_PASS
  [size_is(MaximumLength / 2), length_is((Length) / 2)] USHORT* Buffer;
#else // MIDL_PASS
  _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH   Buffer;
#endif // MIDL_PASS
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
  ULONG Length;
  BOOLEAN Initialized;
  PVOID SsHandle;
  NT_LIST_ENTRY ModuleListLoadOrder;
  NT_LIST_ENTRY ModuleListMemoryOrder;
  NT_LIST_ENTRY ModuleListInitOrder;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
  UCHAR InheritedAddressSpace;
  UCHAR ReadImageFileExecOptions;
  UCHAR BeingDebugged;
  UCHAR BitField;
  PVOID Mutant;
  PVOID ImageBaseAddress;
  PPEB_LDR_DATA Ldr;
} PEB, * PPEB;

typedef NTSTATUS(*MmCopyMemory_t)(PVOID, MM_COPY_ADDRESS, SIZE_T, ULONG, SIZE_T*);
typedef PVOID(*MmMapIoSpaceEx_t)(PHYSICAL_ADDRESS, SIZE_T, ULONG);
typedef void(*MmUnmapIoSpace_t)(PVOID, SIZE_T);
typedef NTSTATUS(*PsLookup_t)(HANDLE pid, PEPROCESS* out);
typedef PVOID(*PsGetBase_t)(PEPROCESS process);
typedef PPEB(*PsGetPeb_t)(PEPROCESS process);
typedef PVOID(*KeGetCurrentThread_t)();
typedef int(__fastcall* blp_arch_switch_context)(int);
typedef void(__fastcall* RtlInitAnsiString_t)(STRING* DestinationString, const char* SourceString);
typedef NTSTATUS(__fastcall* RtlAnsiStringToUnicodeString_t)(UNICODE_STRING* DestinationString, const STRING* SourceString, bool AllocateDestinationString);

typedef STRING ANSI_STRING;

namespace hook_handler
{
    struct cmd_t
    {
        enum operations : int
        {
            write_physical = 0x0,
            read_physical = 0x1,
            get_cr3 = 0x2,
            get_base = 0x3,
            get_module_base = 0x4,
        };

        int operation;
        UINT64 address;
        UINT64 value;
        UINT64 pid;
        UINT64 magic;
        UINT64 buffer;
        UINT64 size;
        UINT64 base;
        UINT64 cr3;
        const char* module_name;
    };
}

//0x10 bytes (sizeof)
struct unicode_string_t
{
    unsigned short length;                                                          //0x0
    unsigned short max_length;                                                   //0x2
    CHAR16* buffer;                                                          //0x8
}; 

struct PHYSICAL_MEMORY_RUN
{
    PHYSICAL_ADDRESS BaseAddress;
    PHYSICAL_ADDRESS NumberOfBytes;
};

typedef PHYSICAL_MEMORY_RUN* (*MmGetPhysicalMemoryRanges_t)();

typedef struct _LDR_DATA_TABLE_ENTRY
{
  NT_LIST_ENTRY InLoadOrderLinks;
  NT_LIST_ENTRY InMemoryOrderModuleList;
  NT_LIST_ENTRY InInitializationOrderModuleList;
  PVOID DllBase;
  PVOID EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
  ULONG Flags;
  USHORT LoadCount;
  USHORT TlsIndex;
  union
  {
    NT_LIST_ENTRY HashLinks;
    PVOID SectionPointer;
  };
  ULONG CheckSum;
  union
  {
    ULONG TimeDateStamp;
    PVOID LoadedImports;
  };
  PVOID EntryPointActivationContext;
  PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

union virt_addr_t
{
    void* value;
    struct
    {
        unsigned long long offset : 12;
        unsigned long long pt_index : 9;
        unsigned long long pd_index : 9;
        unsigned long long pdpt_index : 9;
        unsigned long long pml4_index : 9;
        unsigned long long reserved : 16;
    };
};

struct MMPFN_U4
{
    union
    {
        struct
        {
            unsigned long long PteFrame : 40;
            unsigned long long ResidentPage : 1;
            unsigned long long Unused1 : 1;
            unsigned long long Unused2 : 1;
            unsigned long long Partition : 10;
            unsigned long long FileOnly : 1;
            unsigned long long PfnExists : 1;
            unsigned long long NodeFlinkHigh : 5;
            unsigned long long PageIdentity : 3;
            unsigned long long PrototypePte : 1;
        };
        unsigned long long EntireField;
    };
};

struct _MMPFN
{
    unsigned char pad[0x28];
    MMPFN_U4 u4;
};

static_assert(sizeof(_MMPFN) == 0x30, "_MMPFN size mismatch");
static_assert(OFFSET_OF(_MMPFN, u4) == 0x28, "_MMPFN.u4 offset mismatch");

struct kldr_data_table_entry_t
{
    LIST_ENTRY in_load_order_links;                                //0x0
    void* exception_table;                                          //0x10
    unsigned long exception_table_size;                             //0x18
    void* gp_value;                                                 //0x20
    struct _NON_PAGED_DEBUG_INFO* non_paged_debug_info;            //0x28
    void* dll_base;                                                  //0x30
    void* entry_point;                                              //0x38
    unsigned long size_of_image;                                    //0x40
    struct unicode_string_t full_dll_name;                          //0x48
    struct unicode_string_t base_dll_name;                          //0x58
    unsigned long flags;                                            //0x68
    unsigned short load_count;                                      //0x6c
    union
    {
        unsigned short signature_level:4;                           //0x6e
        unsigned short signature_type:3;                            //0x6e
        unsigned short unused:9;                                    //0x6e
        unsigned short entire_field;                                //0x6e
    } u1;                                                           //0x6e
    void* section_pointer;                                          //0x70
    unsigned long check_sum;                                        //0x78
    unsigned long coverage_section_size;                            //0x7c
    void* coverage_section;                                         //0x80
    void* loaded_imports;                                           //0x88
    void* spare;                                                    //0x90
    unsigned long size_of_image_not_rounded;                        //0x98
    unsigned long time_date_stamp;                                  //0x9c
};

//0x160 bytes (sizeof)
struct loader_parameter_block_t
{
    unsigned long os_major_version;                                                   //0x0
    unsigned long os_minor_version;                                                   //0x4
    unsigned long size;                                                             //0x8
    unsigned long os_loader_security_version;                                          //0xc
    LIST_ENTRY load_order_list_head;                                   //0x10
    LIST_ENTRY memory_descriptor_list_head;                            //0x20
    LIST_ENTRY boot_driver_list_head;                                  //0x30
    LIST_ENTRY elam_list_head;                                         //0x40
    LIST_ENTRY core_driver_list_head;                                  //0x50
    LIST_ENTRY core_extensions_driver_list_head;                        //0x60
    LIST_ENTRY tpm_core_driver_list_head;                              //0x70
    unsigned long long kernel_stack;                                                  //0x80
    unsigned long long prcb;                                                         //0x88
    unsigned long long process;                                                      //0x90
    unsigned long long thread;                                                       //0x98
    unsigned long kstack_size;                                                  //0xa0
    unsigned long registry_len;                                                   //0xa4
    void* registry_base;                                                     //0xa8
    struct _CONFIGURATION_COMPONENT_DATA* configuration_root;                //0xb0
    char* arc_boot_device_name;                                                //0xb8
    char* arc_hal_device_name;                                                 //0xc0
    char* nt_boot_path_name;                                                   //0xc8
    char* nt_hal_path_name;                                                    //0xd0
    char* load_options;                                                      //0xd8
    struct _NLS_DATA_BLOCK* nls_data;                                        //0xe0
    struct _ARC_DISK_INFORMATION* arc_disk_info;                       //0xe8
    struct _LOADER_PARAMETER_EXTENSION* extension;                          //0xf0

    char* os_boot_stat_path_name;                                               //0x148
    char* arc_os_data_device_name;                                              //0x150
    char* arc_windows_sys_part_name;                                            //0x158
}; 


