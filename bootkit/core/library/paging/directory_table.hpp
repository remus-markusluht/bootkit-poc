#pragma once
#include "physical_memory.hpp"
#include "structs.hpp"

// mirrors pml4::dirbase_from_base_address from your ioctl driver
// now uses data from cave via g_runtime_data_ptr

static void* g_pfn_database = nullptr;

static bool init_pfn_database()
{
  auto data = (uint64_t*)g_runtime_data_ptr;
  if (!data || !data[7]) {
    return false;
  } 

  // scan MmGetVirtualForPhysical for the PFN database pointer
  static const unsigned char pattern[] = {
      0x48, 0x8B, 0xC1,
      0x48, 0xC1, 0xE8, 0x0C,
      0x48, 0x8D, 0x14, 0x40,
      0x48, 0x03, 0xD2,
      0x48, 0xB8,
  };

  unsigned char* fn = (unsigned char*)data[7];  // mm_get_virtual_for_physical
  if (!fn) {
    return false;
  }

  for (int i = 0; i < 0x20; i++)
  {
    bool match = true;
    for (int j = 0; j < (int)sizeof(pattern); j++)
      if (fn[i + j] != pattern[j]) { match = false; break; }

    if (match)
    {
      g_pfn_database = *(void**)(fn + i + sizeof(pattern));
      g_pfn_database = (void*)((unsigned long long)g_pfn_database & ~0xFFFull);
      return true;
    }
  }

  return false;
}

inline unsigned long long get_process_dtb(unsigned long long pid)
{
  auto data = (uint64_t*)g_runtime_data_ptr;
  if (!data) {
    return 0;
  }

  auto ps_lookup = (PsLookup_t)data[2];
  auto ps_getbase = (PsGetBase_t)data[3];

  PEPROCESS process = nullptr;
  NTSTATUS lookup_status = ps_lookup((HANDLE)pid, &process);
  if (!NT_SUCCESS(lookup_status)) {
    return 0;
  }

  void* base = ps_getbase(process);
  if (!base) {
    return 0;
  }

  if (!init_pfn_database()) {
    return 0;
  }

  virt_addr_t virt_base{};
  virt_base.value = base;

  auto get_ranges = (PHYSICAL_MEMORY_RUN * (*)())data[8];  // mm_get_physical_memory_ranges
  auto ranges = get_ranges();
  if (!ranges) {
    return 0;
  }

  SIZE_T n = 0;

  for (int i = 0; ; i++)
  {
    auto elem = &ranges[i];
    if (!elem->BaseAddress && !elem->NumberOfBytes) break;

    unsigned long long current_phys = elem->BaseAddress;

    for (int j = 0; j < (elem->NumberOfBytes / 0x1000); j++, current_phys += 0x1000)
    {
      auto pfn = (_MMPFN*)((unsigned long long)g_pfn_database
        + (current_phys >> 12) * sizeof(_MMPFN));

      if (pfn->u4.PteFrame != (current_phys >> 12)) continue;

      unsigned long long pml4e = 0;
      if (!NT_SUCCESS(read_memory(current_phys + 8 * virt_base.pml4_index, &pml4e, 8, &n)))
        continue;
      if (!(pml4e & 1)) continue;

      unsigned long long p_mask = ((~0xFull << 8) & 0xFFFFFFFFFull);
      unsigned long long pdpte = 0;
      if (!NT_SUCCESS(read_memory((pml4e & p_mask) + 8 * virt_base.pdpt_index, &pdpte, 8, &n)))
        continue;
      if (!(pdpte & 1)) continue;

      unsigned long long pde = 0;
      if (!NT_SUCCESS(read_memory((pdpte & p_mask) + 8 * virt_base.pd_index, &pde, 8, &n)))
        continue;
      if (!(pde & 1)) continue;

      unsigned long long pte = 0;
      if (!NT_SUCCESS(read_memory((pde & p_mask) + 8 * virt_base.pt_index, &pte, 8, &n)))
        continue;
      if (!(pte & 1)) continue;

      return current_phys;
    }
  }

  return 0;
}
