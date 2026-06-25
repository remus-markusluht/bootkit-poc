#pragma once
#include "global.hpp"
#include "structs.hpp"
#include "log.hpp"

extern "C" 
{
    #include <Library/BaseMemoryLib.h>
    #include <Library/BaseLib.h>
    #include <intrin.h>
    #include <IndustryStandard/PeImage.h>
    #include <Protocol/LoadedImage.h>
}

#ifndef IMAGE_FIRST_SECTION
#define IMAGE_FIRST_SECTION(ntheader) \
    ((EFI_IMAGE_SECTION_HEADER*)((uint8_t*)(ntheader) + \
    sizeof(UINT32) + \
    sizeof(EFI_IMAGE_FILE_HEADER) + \
    ((EFI_IMAGE_NT_HEADERS64*)(ntheader))->FileHeader.SizeOfOptionalHeader))
#endif

#define CONTAINING_RECORD(address, type, field) ((type *)( \
                                                  (char*)(address) - \
                                                  (UINT64)(&((type *)0)->field)))

namespace tools
{
  static inline uint64_t get_export(uint64_t base, const char* name)
  {
    EFI_IMAGE_DOS_HEADER* dos = (EFI_IMAGE_DOS_HEADER*)base;
    EFI_IMAGE_NT_HEADERS64* nt = (EFI_IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);

    uint32_t export_rva = nt->OptionalHeader.DataDirectory[0].VirtualAddress;
    if (!export_rva) return 0;

    EFI_IMAGE_EXPORT_DIRECTORY* exports =
      (EFI_IMAGE_EXPORT_DIRECTORY*)(base + export_rva);

    uint32_t* names = (uint32_t*)(base + exports->AddressOfNames);
    uint16_t* ordinals = (uint16_t*)(base + exports->AddressOfNameOrdinals);
    uint32_t* functions = (uint32_t*)(base + exports->AddressOfFunctions);

    for (uint32_t i = 0; i < exports->NumberOfNames; i++)
    {
      const char* export_name = (const char*)(base + names[i]);
      // simple strcmp since no CRT
      bool match = true;
      for (int j = 0; ; j++)
      {
        if (export_name[j] != name[j]) { match = false; break; }
        if (name[j] == 0) break;
      }
      if (match)
        return base + functions[ordinals[i]];
    }
    return 0;
  }
    static inline uint64_t get_base_from_address(uint64_t address)
    {
        address &= ~0xfffull;
    
        while (true)
        {
            if (*(uint16_t*)address == 0x5A4D)
                return address;
            address -= 0x1000;
        }
    }

    static inline kldr_data_table_entry_t get_base_from_list(LIST_ENTRY* list, const CHAR16* name)
    {
        for (LIST_ENTRY* entry = list->ForwardLink; entry != list; entry = entry->ForwardLink)
        {
            kldr_data_table_entry_t* module = CONTAINING_RECORD(entry, kldr_data_table_entry_t, in_load_order_links);

            if (module && StrnCmp(name, module->base_dll_name.buffer, module->base_dll_name.length) == 0)
                return *module;
        }

        kldr_data_table_entry_t result;
        SetMem(&result, sizeof(result), 0);
        return result;
    }

    static _declspec(noinline) uintptr_t attach_process(uintptr_t process, uint64_t* data)
    {
      if (!process || !data || !data[9])
        return 0;

      auto ke_get_current_thread = (KeGetCurrentThread_t)data[9];
      auto current_thread = (uintptr_t)ke_get_current_thread();
      if (!current_thread)
        return 0;

      auto apc_state = *(uintptr_t*)(current_thread + 0x98);
      if (!apc_state)
        return 0;

      auto old_process = *(uintptr_t*)(apc_state + 0x20);
      if (!old_process)
        return 0;

      *(uintptr_t*)(apc_state + 0x20) = process;
      auto dir_table_base = *(uintptr_t*)(process + 0x28);
      if (!dir_table_base)
        return 0;

      __writecr3(dir_table_base);
      return old_process;
    }


    static inline uint64_t find_nt_filter_boot_option_by_scan(uint64_t ntoskrnl_base)
    {
      // NtFilterBootOption is unique in that it:
      // 1. starts with a standard prologue
      // 2. within ~50 bytes contains a sub rsp, 0x40 or similar
      // 3. has exactly 5 parameters (pushed to home space)
      // scan for prologue then verify by checking nearby bytes

      uint8_t pat1[] = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x10, 0x48, 0x89, 0x70, 0x18, 0x4C, 0x89, 0x48, 0x20, 0x89, 0x48, 0x08 };
      uint8_t pat2[] = { 0x4C, 0x89, 0x4C, 0x24, 0x20, 0x44, 0x89, 0x44, 0x24, 0x18, 0x89, 0x54, 0x24, 0x10, 0x89, 0x4C, 0x24, 0x08 };

      struct { uint8_t* bytes; int len; } patterns[] = {
          { pat1, sizeof(pat1) },
          { pat2, sizeof(pat2) },
      };

      EFI_IMAGE_DOS_HEADER* dos = (EFI_IMAGE_DOS_HEADER*)ntoskrnl_base;
      EFI_IMAGE_NT_HEADERS64* nt = (EFI_IMAGE_NT_HEADERS64*)(ntoskrnl_base + dos->e_lfanew);
      EFI_IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);

      for (auto& pat : patterns)
      {
        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
        {
          UINT32 chars = sections[i].Characteristics;
          if (!(chars & 0x20000000)) continue;
          if (!(chars & 0x20))       continue;
          if (chars & 0x02000000)    continue;

          uint8_t* start = (uint8_t*)(ntoskrnl_base + sections[i].VirtualAddress);
          uint64_t size = sections[i].Misc.VirtualSize;

          for (uint64_t j = 0; j < size - pat.len; j++)
          {
            bool match = true;
            for (int k = 0; k < pat.len; k++)
            {
              if (start[j + k] != pat.bytes[k]) { match = false; break; }
            }
            if (!match) continue;

            // verify: within 60 bytes must have PUSH of callee-saved regs
            // NtFilterBootOption saves r14, r15 etc due to 5 params
            bool verified = false;
            for (int v = pat.len; v < 60; v++)
            {
              // look for push r14 (41 56) or push r15 (41 57)
              // or sub rsp, 40 (48 83 EC 40)
              if (start[j + v] == 0x41 && (start[j + v + 1] == 0x56 || start[j + v + 1] == 0x57))
              {
                verified = true; break;
              }
              if (start[j + v] == 0x48 && start[j + v + 1] == 0x83 &&
                start[j + v + 2] == 0xEC && start[j + v + 3] == 0x40)
              {
                verified = true; break;
              }
            }
            if (!verified) continue;

            uint64_t candidate = ntoskrnl_base + sections[i].VirtualAddress + j;
            log::serial_fmt("[Twizzy] NtFilterBootOption via scan: %p\r\n", candidate);
            return candidate;
          }
        }
      }

      log::serial_fmt("[Twizzy] NtFilterBootOption not found\r\n");
      return 0;
    }

}
