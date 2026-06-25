#pragma once

extern "C" {
    #include <Uefi.h>
    #include <Library/SerialPortLib.h>
    #include <Library/UefiLib.h>
    #include <Library/PrintLib.h>
}

namespace log
{
    inline void serial(const char* msg)
    {
        if (!msg)
            return;

        uint64_t len = 0;
        while (msg[len])
            len++;

        SerialPortWrite((uint8_t*)msg, len);
    }
    inline void serial_fmt(const char* fmt, ...)
    {
      char buf[256];
      VA_LIST args;
      VA_START(args, fmt);
      AsciiVSPrint(buf, sizeof(buf), fmt, args);
      VA_END(args);
      log::serial(buf);
    }

    template<typename... Args>
    void print(const wchar_t* fmt, Args... args)
    {
        Print((const CHAR16*)L"[ Twizzy Bootkit ] ");
        Print((const CHAR16*)fmt, args...);
    }
}
