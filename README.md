# BootkitPkg

This repository is an EDK II package with two isolated EFI wrapper projects:

- `bootkit`
- `embedded_loader`

Open `root.sln` to see both projects in Visual Studio. Open `bootkit\bootkit.sln` or `embedded_loader\embedded_loader.sln` when you only want one project.

EDK II is still the real build system. The Visual Studio projects are Makefile wrappers around `tools\build-edk2.ps1`.

## Layout

```text
BootkitPkg/
  root.sln
  scripts/
  bootkit/
    bootkit.sln
    bootkit.vcxproj
    core/
      include/
        include.hpp
      library/
        boot/
        diagnostics/
        hook/
        memory/
        modules/
        paging/
        process/
        requests/
        runtime/
        utility/
    deps/
    impl/
    docs/
  embedded_loader/
    embedded_loader.sln
    embedded_loader.vcxproj
    core/
    deps/
    impl/
    docs/
  edk2/
    BootkitPkg.dsc
    generated/
    asm/
  tools/
```

## Build

### Prerequisites

- Windows with Visual Studio 2022 C++ build tools
- EDK II checkout with this folder placed inside the workspace, for example:

```text
E:\edk2\
  edksetup.bat
  BootkitPkg\
```

- NASM available on `PATH`, or installed at `C:\Program Files\NASM\nasm.exe`
- Windows 10 SDK signing tools for `signtool.exe`
- Python launcher `py -3`
- OpenSSL if the Secure Boot signing PFX needs to be generated

The build script auto-detects Visual Studio 2022, NASM, the Windows SDK, and the EDK II workspace in the common locations. You can also set `EDK2_WORKSPACE` to the root of your EDK II checkout.

### Commands

```bat
scripts\build_bootkit.bat
scripts\build_embedded_loader.bat
scripts\build_all.bat
```

Pass `RELEASE` as the first argument for release builds:

```bat
scripts\build_all.bat RELEASE
```

`build_all.bat` is the normal command when changing the bootkit payload. It builds and signs `bootkit.efi`, embeds that image into `edk2\generated\bootkit_embedded.hpp`, then builds and signs `embedded_loader.efi`.

Build outputs are written under the EDK II workspace:

```text
E:\edk2\Build\BootkitPkg\DEBUG_VS2022\X64\
  bootkit.efi
  embedded_loader.efi
```

## GitHub Private Repository

Create an empty private repository on GitHub, then push this package as its own repository from `BootkitPkg`:

```powershell
cd E:\edk2\BootkitPkg
git init
git add .
git commit -m "Initial BootkitPkg import"
git branch -M main
git remote add origin https://github.com/<user-or-org>/<repo>.git
git push -u origin main
```

Or with GitHub CLI:

```powershell
cd E:\edk2\BootkitPkg
gh repo create <user-or-org>/<repo> --private --source . --remote origin --push
```

Do not commit private signing keys. The `.gitignore` excludes `tools\secure-boot-keys\*.key` and `tools\secure-boot-keys\*.pfx`; keep those backed up outside GitHub.
