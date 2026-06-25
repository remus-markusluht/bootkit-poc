#pragma once
#include "tools.hpp"

namespace hook
{
  void create_hook(uint64_t function_ptr, uint64_t hook_handler)
  {
    uint8_t shellcode[12] = {
        0x48, 0xB8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xE0
    };

    CopyMem(shellcode + 2, (uint8_t*)&hook_handler, 8);

    UINTN cr0 = AsmReadCr0();
    UINTN cr4 = AsmReadCr4();

    log::serial_fmt("[Twizzy] cr0: %p cr4: %p\r\n", cr0, cr4);

    AsmWriteCr4(cr4 & ~0x100000ULL); // disable SMEP
    AsmWriteCr0(cr0 & ~0x10000ULL);  // disable WP
    _mm_sfence();

    CopyMem((uint8_t*)function_ptr, shellcode, sizeof(shellcode));

    _mm_sfence();
    AsmWriteCr0(cr0);
    AsmWriteCr4(cr4);

    log::serial_fmt("[Twizzy] hook written\r\n");
  }
}
