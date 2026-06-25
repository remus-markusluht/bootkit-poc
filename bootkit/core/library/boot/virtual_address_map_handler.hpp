#pragma once
#include "tools.hpp"
#include "hook.hpp"
#include "ebs.hpp"

namespace va_map_handler
{
  EFI_EVENT set_va_map_handler_ptr = 0;

  void EFIAPI set_va_map_handler(EFI_EVENT event, void* ctx)
  {
    log::serial("[Twizzy] VA Change - finalizing kernel hook\r\n");

    if (!ebs::pending_runtime_data || !ebs::pending_function_ptr || !ebs::pending_hook_address)
    {
      log::serial("[Twizzy] no pending EBS hook state, skipping\r\n");
      return;
    }

    uint64_t* runtime_data = (uint64_t*)ebs::pending_runtime_data;
    log::serial_fmt("[Twizzy] C++ handler before VA convert: %p\r\n", runtime_data[15]);
    globals::system_table->RuntimeServices->ConvertPointer(0, (void**)&runtime_data[15]);
    log::serial_fmt("[Twizzy] C++ handler after VA convert: %p\r\n", runtime_data[15]);

    g_runtime_data_ptr = (uint64_t)runtime_data;
    *(uint64_t*)(ebs::pending_hook_address + ebs::SC_RUNTIME_PTR) = (uint64_t)runtime_data;
    log::serial_fmt("[Twizzy] runtime ptr patched in cave: %p\r\n", (uint64_t)runtime_data);

    if (!runtime_data[1])
    {
      log::serial("[Twizzy] NtFilterBootOption not found, hook skipped\r\n");
      return;
    }

    hook::create_hook(ebs::pending_function_ptr, ebs::pending_hook_address);

    log::serial("[Twizzy] Kernel hook installed from EBS state\r\n");
  }

  void create_handler()
  {
    globals::system_table->BootServices->CreateEvent(
      EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE,
      TPL_NOTIFY,
      set_va_map_handler,
      0,
      &set_va_map_handler_ptr);
  }
}
