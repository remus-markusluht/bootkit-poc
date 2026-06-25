#pragma once
#include "structs.hpp"
#include <cstdint>

namespace globals
{
  extern EFI_SYSTEM_TABLE* system_table;
  extern uint64_t winload_base;
  extern uint64_t ntoskrnl_base;
}

// Global pointer to runtime data inside the code cave
extern uint64_t g_runtime_data_ptr;
