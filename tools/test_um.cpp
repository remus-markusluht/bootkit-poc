#include <Windows.h>
#include <TlHelp32.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cwchar>

namespace bootkit_um
{
  static constexpr uint64_t kMagic = 0x12E7A12D;

  struct cmd_t
  {
    enum operations : int
    {
      write_physical = 0x0, // name is legacy: handler treats address as VA + cr3
      read_physical = 0x1,  // name is legacy: handler treats address as VA + cr3
      get_cr3 = 0x2,
      get_base = 0x3,
      get_module_base = 0x4,
    };

    int      operation;
    uint64_t address;
    uint64_t value;
    uint64_t pid;
    uint64_t magic;
    uint64_t buffer;
    uint64_t size;
    uint64_t base;
    uint64_t cr3;
    const char* module_name;
  };

  static_assert(offsetof(cmd_t, operation) == 0x00);
  static_assert(offsetof(cmd_t, address) == 0x08);
  static_assert(offsetof(cmd_t, value) == 0x10);
  static_assert(offsetof(cmd_t, pid) == 0x18);
  static_assert(offsetof(cmd_t, magic) == 0x20);
  static_assert(offsetof(cmd_t, buffer) == 0x28);
  static_assert(offsetof(cmd_t, size) == 0x30);
  static_assert(offsetof(cmd_t, base) == 0x38);
  static_assert(offsetof(cmd_t, cr3) == 0x40);
  static_assert(offsetof(cmd_t, module_name) == 0x48);

  using nt_filter_boot_option_t = long (NTAPI*)(int, int, int, void*, int);

  const char* operation_name(int operation)
  {
    switch (operation)
    {
    case cmd_t::write_physical: return "write";
    case cmd_t::read_physical:  return "read";
    case cmd_t::get_cr3:        return "get_dtb";
    case cmd_t::get_base:       return "get_base";
    case cmd_t::get_module_base: return "get_module_base";
    default:                    return "unknown";
    }
  }

  void dump_cmd(const char* label, long status, const cmd_t& cmd)
  {
    std::printf(
      "[%s] status=0x%08lX op=%s(%d) pid=%llu addr=0x%llX buffer=0x%llX size=0x%llX base=0x%llX cr3=0x%llX module=%s magic=0x%llX\n",
      label,
      status,
      operation_name(cmd.operation),
      cmd.operation,
      static_cast<unsigned long long>(cmd.pid),
      static_cast<unsigned long long>(cmd.address),
      static_cast<unsigned long long>(cmd.buffer),
      static_cast<unsigned long long>(cmd.size),
      static_cast<unsigned long long>(cmd.base),
      static_cast<unsigned long long>(cmd.cr3),
      cmd.module_name ? cmd.module_name : "",
      static_cast<unsigned long long>(cmd.magic));
  }

  class client_t
  {
  public:
    bool init()
    {
      HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
      if (!ntdll)
        ntdll = LoadLibraryW(L"ntdll.dll");

      if (!ntdll)
        return false;

      syscall_ = reinterpret_cast<nt_filter_boot_option_t>(
        GetProcAddress(ntdll, "NtFilterBootOption"));

      return syscall_ != nullptr;
    }

    long invoke(const char* label, cmd_t& cmd) const
    {
      cmd.magic = kMagic;
      long status = syscall_(0, 0, 0, &cmd, 0);
      dump_cmd(label, status, cmd);
      return status;
    }

    long get_base(uint32_t pid, uint64_t& out_base) const
    {
      cmd_t cmd{};
      cmd.operation = cmd_t::get_base;
      cmd.pid = pid;

      long status = invoke("get_base", cmd);
      out_base = cmd.base;
      return status;
    }

    long get_module_base(uint32_t pid, const char* module_name, uint64_t& out_base) const
    {
      cmd_t cmd{};
      cmd.operation = cmd_t::get_module_base;
      cmd.pid = pid;
      cmd.module_name = module_name;

      long status = invoke("get_module_base", cmd);
      out_base = cmd.base;
      return status;
    }

    long get_dtb(uint32_t pid, uint64_t& out_dtb) const
    {
      cmd_t cmd{};
      cmd.operation = cmd_t::get_cr3;
      cmd.pid = pid;

      long status = invoke("get_dtb", cmd);
      out_dtb = cmd.cr3;
      return status;
    }

    bool read(uint64_t dtb, uint64_t address, void* buffer, uint64_t size) const
    {
      cmd_t cmd{};
      cmd.operation = cmd_t::read_physical;
      cmd.cr3 = dtb;
      cmd.address = address;
      cmd.buffer = reinterpret_cast<uint64_t>(buffer);
      cmd.size = size;

      long status = invoke("read", cmd);
      return status >= 0;
    }

    bool write(uint64_t dtb, uint64_t address, const void* buffer, uint64_t size) const
    {
      cmd_t cmd{};
      cmd.operation = cmd_t::write_physical;
      cmd.cr3 = dtb;
      cmd.address = address;
      cmd.buffer = reinterpret_cast<uint64_t>(buffer);
      cmd.size = size;

      long status = invoke("write", cmd);
      return status >= 0;
    }

    template <typename T>
    bool read_value(uint64_t dtb, uint64_t address, T& out) const
    {
      out = {};
      return read(dtb, address, &out, sizeof(T));
    }

  private:
    nt_filter_boot_option_t syscall_ = nullptr;
  };

  bool expected_module_base(uint32_t pid, const char* module_name, uint64_t& out_base)
  {
    out_base = 0;

    wchar_t module_name_w[MAX_PATH]{};
    if (!MultiByteToWideChar(CP_ACP, 0, module_name, -1, module_name_w, MAX_PATH))
      return false;

    HANDLE snapshot = CreateToolhelp32Snapshot(
      TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
      pid);

    if (snapshot == INVALID_HANDLE_VALUE)
      return false;

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    bool found = false;
    if (Module32FirstW(snapshot, &entry))
    {
      do
      {
        if (_wcsicmp(entry.szModule, module_name_w) == 0)
        {
          out_base = reinterpret_cast<uint64_t>(entry.modBaseAddr);
          found = true;
          break;
        }
      } while (Module32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return found;
  }
}

int main(int argc, char** argv)
{
  bootkit_um::client_t bootkit;
  if (!bootkit.init())
  {
    std::printf("failed to resolve NtFilterBootOption\n");
    return 1;
  }

  if (argc != 1 && argc != 3)
  {
    std::printf("usage: %s [pid module_name]\n", argv[0]);
    return 1;
  }

  if (argc == 3)
  {
    uint32_t pid = static_cast<uint32_t>(std::strtoul(argv[1], nullptr, 0));
    const char* module_name = argv[2];

    uint64_t base = 0;
    long status = bootkit.get_module_base(pid, module_name, base);

    uint64_t expected = 0;
    bool has_expected = bootkit_um::expected_module_base(pid, module_name, expected);

    std::printf("module base: 0x%llX expected: %s0x%llX\n",
      static_cast<unsigned long long>(base),
      has_expected ? "" : "unavailable/",
      static_cast<unsigned long long>(expected));

    if (status < 0 || !base)
      return 1;

    return has_expected && base == expected ? 0 : 1;
  }

  uint32_t pid = GetCurrentProcessId();
  std::printf("pid: %lu\n", pid);

  uint64_t base = 0;
  long base_status = bootkit.get_base(pid, base);
  uint64_t expected_base = reinterpret_cast<uint64_t>(GetModuleHandleW(nullptr));
  std::printf("base: 0x%llX expected: 0x%llX\n",
    static_cast<unsigned long long>(base),
    static_cast<unsigned long long>(expected_base));

  if (base_status < 0 || !base)
  {
    std::printf("failed to get image base\n");
    return 1;
  }

  uint64_t dtb = 0;
  long dtb_status = bootkit.get_dtb(pid, dtb);
  std::printf("dtb: 0x%llX\n", static_cast<unsigned long long>(dtb));

  if (dtb_status < 0)
  {
    std::printf("get_dtb returned failure status: 0x%08lX\n", dtb_status);
    return 1;
  }

  if (!dtb)
  {
    std::printf("get_dtb returned success, but dtb is zero\n");
    return 1;
  }

  uint16_t mz = 0;
  if (!bootkit.read_value(dtb, base, mz))
  {
    std::printf("failed to read MZ header\n");
    return 1;
  }

  std::printf("MZ: 0x%04X\n", mz);
  if (mz != 0x5A4D)
  {
    std::printf("unexpected image header\n");
    return 1;
  }

  volatile uint64_t target = 0x1122334455667788ull;
  uint64_t original = 0;
  uint64_t replacement = 0xAABBCCDDEEFF0011ull;
  uint64_t readback = 0;

  uint64_t target_address = reinterpret_cast<uint64_t>(&target);
  if (!bootkit.read_value(dtb, target_address, original))
  {
    std::printf("failed to read stack target\n");
    return 1;
  }

  std::printf("original: 0x%llX\n", static_cast<unsigned long long>(original));

  if (!bootkit.write(dtb, target_address, &replacement, sizeof(replacement)))
  {
    std::printf("failed to write stack target\n");
    return 1;
  }

  if (!bootkit.read_value(dtb, target_address, readback))
  {
    std::printf("failed to read back stack target\n");
    return 1;
  }

  std::printf("written/readback: 0x%llX direct: 0x%llX\n",
    static_cast<unsigned long long>(readback),
    static_cast<unsigned long long>(target));

  bootkit.write(dtb, target_address, &original, sizeof(original));
  std::printf("restored: 0x%llX\n", static_cast<unsigned long long>(target));

  return readback == replacement ? 0 : 1;
}
