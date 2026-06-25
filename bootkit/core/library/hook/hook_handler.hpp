#pragma once
#include "global.hpp"

// Updated declaration - takes pointer to data in cave
extern "C" long __fastcall RuntimeRequestHandler(
  hook_handler::cmd_t* cmd,
  uint64_t runtime_data_ptr);
