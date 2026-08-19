# BootkitPkg

BootkitPkg is an EDK II proof-of-concept package for UEFI boot-flow research on Windows systems. It contains a DXE runtime driver, an embedded UEFI loader, build automation, and supporting lab assets for studying pre-OS execution, runtime event handling, and controlled Secure Boot test environments.

This project is intended for authorized research in disposable virtual machines or dedicated lab hardware. It is not designed for production systems.

## Table of Contents

1. [Overview](#overview)
2. [Project Layout](#project-layout)
3. [Components](#components)
4. [Build Process](#build-process)
5. [Development Environment](#development-environment)
6. [Lab Usage](#lab-usage)
7. [Roadmap](#roadmap)
8. [License](#license)

## Overview

BootkitPkg is structured as a standalone EDK II package. The Visual Studio solutions provide a convenient editing and build entry point, while EDK II remains the authoritative firmware build system.

The package builds two EFI images:

- `bootkit.efi` - a DXE runtime driver that registers boot/runtime handlers.
- `embedded_loader.efi` - a UEFI application that embeds and loads the driver image.

The build pipeline assembles the hook-handler payload, generates C/C++ headers from binary assets, builds the EFI modules, signs the resulting images when local lab signing material is available, and writes the final outputs into the EDK II build directory.

## Project Layout

```text
BootkitPkg/
  root.sln
  bootkit/
    bootkit.sln
    bootkit.vcxproj
    impl/
    core/
      include/
      library/
        boot/
        diagnostics/
        hook/
        memory/
        modules/
        paging/
        runtime/
  embedded_loader/
    embedded_loader.sln
    embedded_loader.vcxproj
    impl/
  edk2/
    BootkitPkg.dsc
    asm/
    generated/
  esp/
  scripts/
  tools/
```

## Components

### Bootkit Driver

The bootkit module is built as a DXE runtime driver from `bootkit/impl/bootkit.inf`. Its implementation initializes shared runtime state, registers hook handling, and installs the virtual address map transition handler used during the boot flow.

Relevant source areas:

- `bootkit/impl/bootkit.cpp`
- `bootkit/core/library/boot/`
- `bootkit/core/library/hook/`
- `bootkit/core/library/memory/`
- `bootkit/core/library/paging/`
- `bootkit/core/library/runtime/`

### Embedded Loader

The embedded loader is built as a UEFI application from `embedded_loader/impl/embedded_loader.inf`. It consumes generated headers from `edk2/generated/`, performs lab Secure Boot state checks, and loads the embedded driver image from memory.

Relevant source areas:

- `embedded_loader/impl/embedded_loader.cpp`
- `edk2/generated/bootkit_embedded.hpp`
- `edk2/generated/keys.hpp`

### Generated Assets

The package uses generated headers to keep binary payloads available to the EFI modules at build time:

- `edk2/generated/hook_handler_shellcode.hpp` is generated from `edk2/asm/hook_handler.nasm`.
- `edk2/generated/bootkit_embedded.hpp` is generated from the built `bootkit.efi` image.
- `edk2/generated/keys.hpp` contains lab Secure Boot authentication data consumed by the loader.

## Build Process

The root build scripts are the preferred entry points:

```bat
scripts\build_bootkit.bat
scripts\build_embedded_loader.bat
scripts\build_all.bat
```

Use the full build when changing the driver payload:

```bat
scripts\build_all.bat
```

Use `RELEASE` for a release target:

```bat
scripts\build_all.bat RELEASE
```

The full build performs the following steps:

1. Assemble `edk2/asm/hook_handler.nasm`.
2. Generate `edk2/generated/hook_handler_shellcode.hpp`.
3. Build `bootkit.efi`.
4. Sign `bootkit.efi` when local signing material and signing tools are available.
5. Embed `bootkit.efi` into `edk2/generated/bootkit_embedded.hpp`.
6. Build `embedded_loader.efi`.
7. Sign `embedded_loader.efi` when local signing material and signing tools are available.

Typical output directory:

```text
E:\edk2\Build\BootkitPkg\DEBUG_VS2022\X64\
  bootkit.efi
  embedded_loader.efi
```

## Development Environment

Expected toolchain:

- Windows
- Visual Studio 2022 C++ build tools
- EDK II workspace
- NASM
- Python launcher `py -3`
- Windows SDK signing tools
- OpenSSL for local PFX generation when needed

The package should live inside an EDK II workspace:

```text
E:\edk2\
  edksetup.bat
  BootkitPkg\
```

The build script can discover common Visual Studio, NASM, Windows SDK, and EDK II locations. The workspace root can also be supplied through `EDK2_WORKSPACE`.

## Visual Studio

Open `root.sln` to work with both EFI targets from one solution.

Target-specific solutions are also available:

- `bootkit/bootkit.sln`
- `embedded_loader/embedded_loader.sln`

The project files are Makefile-style wrappers around `tools/build-edk2.ps1`.

## Lab Usage

Use this project only in an isolated research environment. A disposable VM is the safest default because firmware variables, boot entries, Secure Boot state, and generated EFI images can affect boot behavior.

Recommended lab practices:

- Take a VM snapshot before testing firmware or Secure Boot changes.
- Keep private signing keys outside the source tree.
- Treat generated EFI images as lab artifacts.
- Review generated headers after rebuilds when validating payload changes.
- Use serial output and console messages for early boot diagnostics.

## Roadmap

- Improve generated-asset validation before module builds.
- Add cleaner test harness documentation for `tools/test_um.cpp`.
- Add reproducible VM setup notes for common firmware test environments.
- Separate checked-in lab certificates from private signing material more clearly.
- Add build output verification for signed EFI images.

## License

No license has been declared. Treat all rights as reserved unless a license is added.
