#include "hook_handler.hpp"
#include "physical_memory.hpp"
#include "address_translation.hpp"
#include "module_lookup.hpp"
#include "directory_table.hpp"
#include "log.hpp"

inline uint64_t get_runtime_data_ptr()
{
  return g_runtime_data_ptr;
}
extern "C"
long __fastcall RuntimeRequestHandler(
  hook_handler::cmd_t* cmd,
  uint64_t runtime_data_ptr)
{
  if (!runtime_data_ptr)
    return 0xC000000D;

  g_runtime_data_ptr = runtime_data_ptr;

  if (!cmd || cmd->magic != 0x12E7A12D)
    return 0xC000000D;

  SIZE_T bytes = 0;

  switch (cmd->operation)
  {
  case hook_handler::cmd_t::read_physical:
  {
    // mirrors Features::read_memory ? translate VA->PA per page, then read
    unsigned long long offset = 0;
    unsigned long long remaining = cmd->size;

    while (remaining > 0)
    {
      unsigned long long phys = translate_linear(cmd->cr3, cmd->address + offset);
      if (!phys) return 0xC0000001L;

      unsigned long long chunk = PAGE_SIZE - (phys & 0xFFF);
      if (chunk > remaining) chunk = remaining;

      NTSTATUS st = read_memory(phys, (void*)(cmd->buffer + offset), chunk, &bytes);
      if (!NT_SUCCESS(st)) return st;

      offset += chunk;
      remaining -= chunk;
    }
    break;
  }

  case hook_handler::cmd_t::write_physical:
  {
    unsigned long long offset = 0;
    unsigned long long remaining = cmd->size;

    while (remaining > 0)
    {
      unsigned long long phys = translate_linear(cmd->cr3, cmd->address + offset);
      if (!phys) return 0xC0000001L;

      unsigned long long chunk = PAGE_SIZE - (phys & 0xFFF);
      if (chunk > remaining) chunk = remaining;

      NTSTATUS st = write_memory(phys, (void*)(cmd->buffer + offset), chunk, &bytes);
      if (!NT_SUCCESS(st)) return st;

      offset += chunk;
      remaining -= chunk;
    }
    break;
  }

  case hook_handler::cmd_t::get_base:
    cmd->base = get_base(cmd->pid);
    break;
  case hook_handler::cmd_t::get_module_base:
    cmd->base = get_module_base(cmd->pid, cmd->module_name);
    break;

  case hook_handler::cmd_t::get_cr3:
    cmd->cr3 = get_process_dtb(cmd->pid);
    break;
  }

  return 0;
}
