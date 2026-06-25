#pragma once
#include "global.hpp"
#include <tools.hpp>

inline unsigned long long get_base(unsigned long long pid)
{
  auto data = (uint64_t*)g_runtime_data_ptr;
  if (!data) return 0;

  auto ps_lookup = (PsLookup_t)data[2];
  auto ps_getbase = (PsGetBase_t)data[3];

  PEPROCESS process = nullptr;
  if (!NT_SUCCESS(ps_lookup((HANDLE)pid, &process))) return 0;

  unsigned long long base = (unsigned long long)ps_getbase(process);

  return base;
}
inline unsigned long long get_module_base(unsigned long long pid, const char* module_name)
{
  auto data = (uint64_t*)g_runtime_data_ptr;
  if (!data || !module_name) return 0;

  uintptr_t out = 0;
  uintptr_t o_process = 0;
  auto rtl_init_ansi_string = (RtlInitAnsiString_t)data[11];
  auto rtl_ansi_to_unicode = (RtlAnsiStringToUnicodeString_t)data[12];
  auto ps_lookup = (PsLookup_t)data[2];
  auto ps_get_process_peb = (PsGetPeb_t)data[10];
  auto rtl_compare_unicode = (int(__fastcall*)(PCUNICODE_STRING, PCUNICODE_STRING, bool))data[13];
  auto rtl_free_unicode = (void(__fastcall*)(PUNICODE_STRING))data[14];

  if (!rtl_init_ansi_string || !rtl_ansi_to_unicode || !ps_lookup ||
      !ps_get_process_peb || !rtl_compare_unicode || !rtl_free_unicode)
    return 0;

  ANSI_STRING ansi_name;
  rtl_init_ansi_string(&ansi_name, module_name);

  UNICODE_STRING compare_name{};
  if (!NT_SUCCESS(rtl_ansi_to_unicode(&compare_name, &ansi_name, TRUE)))
    return 0;

  PEPROCESS process = nullptr;
  if (!NT_SUCCESS(ps_lookup((HANDLE)pid, &process)))
    goto cleanup;

  o_process = tools::attach_process((uintptr_t)process, data);
  if (!o_process)
    goto cleanup;

  PPEB pPeb = ps_get_process_peb(process);
  if (pPeb)
  {
    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;
    if (pLdr)
    {
      for (PNT_LIST_ENTRY listEntry = (PNT_LIST_ENTRY)pLdr->ModuleListLoadOrder.Flink;
        listEntry != &pLdr->ModuleListLoadOrder;
        listEntry = (PNT_LIST_ENTRY)listEntry->Flink) {
        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (rtl_compare_unicode(&pEntry->BaseDllName, &compare_name, TRUE) == 0)
        {
          out = (uint64_t)pEntry->DllBase;
          break;
        }
      }
    }
  }

cleanup:
  if (o_process)
    tools::attach_process(o_process, data);

  rtl_free_unicode(&compare_name);

  return out;
}
