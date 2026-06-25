#pragma once
#include "physical_memory.hpp"

// mirrors Features::translate_linear from your ioctl driver
inline unsigned long long translate_linear(unsigned long long directory_base,
  unsigned long long address)
{
  directory_base &= ~0xFull;

  auto virt_off = address & 0xFFF;
  auto pte_idx = (address >> 12) & 0x1FF;
  auto pt_idx = (address >> 21) & 0x1FF;
  auto pd_idx = (address >> 30) & 0x1FF;
  auto pdp_idx = (address >> 39) & 0x1FF;
  auto p_mask = ((~0xFull << 8) & 0xFFFFFFFFFull);

  SIZE_T n = 0;
  unsigned long long pdpe = 0;
  read_memory(directory_base + 8 * pdp_idx, &pdpe, 8, &n);
  if (!(pdpe & 1)) return 0;

  unsigned long long pde = 0;
  read_memory((pdpe & p_mask) + 8 * pd_idx, &pde, 8, &n);
  if (!(pde & 1)) return 0;

  if (pde & 0x80) // 1GB large page
    return (pde & (~0ull << 42 >> 12)) + (address & ~(~0ull << 30));

  unsigned long long pte_val = 0;
  read_memory((pde & p_mask) + 8 * pt_idx, &pte_val, 8, &n);
  if (!(pte_val & 1)) return 0;

  if (pte_val & 0x80) // 2MB large page
    return (pte_val & p_mask) + (address & ~(~0ull << 21));

  unsigned long long page = 0;
  read_memory((pte_val & p_mask) + 8 * pte_idx, &page, 8, &n);
  page &= p_mask;
  return page ? page + virt_off : 0;
}
