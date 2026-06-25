#pragma once
#include "hook_handler.hpp"
#include "global.hpp"

#define MM_COPY_MEMORY_PHYSICAL 0x1
#define PAGE_READWRITE          0x4
#define PAGE_SIZE               0x1000
#define STATUS_SUCCESS          ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL     ((NTSTATUS)0xC0000001L)
#define NT_SUCCESS(s)           ((s) >= 0)

inline NTSTATUS read_memory(ULONGLONG physical_address, PVOID buffer, SIZE_T size, SIZE_T* bytes)
{
  auto data = (uint64_t*)g_runtime_data_ptr;
  if (!data || !data[4]) return STATUS_UNSUCCESSFUL; // mm_copy_memory offset

  auto fn = (MmCopyMemory_t)data[4];
  MM_COPY_ADDRESS src{};
  src.PhysicalAddress = (PHYSICAL_ADDRESS)physical_address;
  return fn(buffer, src, size, MM_COPY_MEMORY_PHYSICAL, bytes);
}

inline NTSTATUS write_memory(ULONGLONG physical_address, PVOID buffer, SIZE_T size, SIZE_T* bytes)
{
  auto data = (uint64_t*)g_runtime_data_ptr;
  if (!data || !data[5] || !data[6]) return STATUS_UNSUCCESSFUL;

  auto map_fn = (MmMapIoSpaceEx_t)data[5];
  auto unmap_fn = (MmUnmapIoSpace_t)data[6];

  PHYSICAL_ADDRESS pa = (PHYSICAL_ADDRESS)physical_address;

  PVOID mapped = map_fn(pa, size, PAGE_READWRITE);
  if (!mapped) return STATUS_UNSUCCESSFUL;

  auto* dst = (volatile unsigned char*)mapped;
  auto* src = (volatile unsigned char*)buffer;
  for (SIZE_T i = 0; i < size; i++)
    dst[i] = src[i];

  *bytes = size;
  unmap_fn(mapped, size);
  return STATUS_SUCCESS;
}
