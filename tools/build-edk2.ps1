param(
    [ValidateSet("DEBUG", "RELEASE")]
    [string]$Target = "DEBUG",

    [ValidateSet("VS2019", "VS2022")]
    [string]$Toolchain = "VS2022",

    [ValidateSet("All", "Bootkit", "EmbeddedLoader")]
    [string]$Module = "All",

    [switch]$Clean
)

$ErrorActionPreference = "Stop"

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$workspace = $env:EDK2_WORKSPACE

if (-not $workspace) {
    $probe = $projectRoot
    while ($probe) {
        if (Test-Path (Join-Path $probe "edksetup.bat")) {
            $workspace = $probe
            break
        }
        $parent = Split-Path -Parent $probe
        if ($parent -eq $probe) { break }
        $probe = $parent
    }
}

if (-not $workspace -or -not (Test-Path (Join-Path $workspace "edksetup.bat"))) {
    throw "Set EDK2_WORKSPACE to your edk2 checkout, or place this folder inside an edk2 workspace."
}

$workspace = (Resolve-Path $workspace).Path

if (-not $projectRoot.StartsWith($workspace, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "This folder must be inside the EDK II workspace. Move it under '$workspace' before building."
}

function Set-Edk2VisualStudioEnvironment {
    if ($Toolchain -ne "VS2022") {
        return
    }

    $expectedCl = if ($env:VS2022_PREFIX) {
        Join-Path $env:VS2022_PREFIX "bin\Hostx86\x64\cl.exe"
    } else {
        $null
    }

    if (-not $expectedCl -or -not (Test-Path $expectedCl)) {
        $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
        if (-not (Test-Path $vswhere)) {
            throw "Unable to locate vswhere.exe. Install Visual Studio 2022 with the C++ toolchain."
        }

        $vsInstall = & $vswhere -latest -version "[17.0,18.0)" -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if (-not $vsInstall) {
            throw "Unable to locate a Visual Studio 2022 C++ toolchain."
        }

        $msvcRoot = Join-Path $vsInstall "VC\Tools\MSVC"
        $msvcToolset = Get-ChildItem -LiteralPath $msvcRoot -Directory |
            Sort-Object Name -Descending |
            Select-Object -First 1

        if (-not $msvcToolset) {
            throw "No MSVC toolset found under $msvcRoot."
        }

        $env:VS2022_PREFIX = "$($msvcToolset.FullName)\"
        $expectedCl = Join-Path $env:VS2022_PREFIX "bin\Hostx86\x64\cl.exe"
    }

    if (-not (Test-Path $expectedCl)) {
        throw "VS2022_PREFIX is invalid. Expected compiler not found: $expectedCl"
    }

    if (-not $env:WINSDK_PATH_FOR_RC_EXE -or -not (Test-Path (Join-Path $env:WINSDK_PATH_FOR_RC_EXE "rc.exe"))) {
        $sdkBinRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
        $sdkBin = Get-ChildItem -LiteralPath $sdkBinRoot -Directory |
            Where-Object { Test-Path (Join-Path $_.FullName "x86\rc.exe") } |
            Sort-Object Name -Descending |
            Select-Object -First 1

        if ($sdkBin) {
            $env:WINSDK10_PREFIX = "$($sdkBin.FullName)\"
            $env:WINSDK_PATH_FOR_RC_EXE = Join-Path $sdkBin.FullName "x86"
        }
    }

    Write-Host "VS2022_PREFIX: $env:VS2022_PREFIX" -ForegroundColor Gray
}

Set-Edk2VisualStudioEnvironment

$nasm = Get-Command "nasm.exe" -ErrorAction SilentlyContinue
if (-not $nasm) {
    $nasmCandidates = @(
        $(if ($env:NASM_PREFIX) { Join-Path $env:NASM_PREFIX "nasm.exe" }),
        (Join-Path $env:ProgramFiles "NASM\nasm.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "NASM\nasm.exe")
    )

    $nasmPath = $nasmCandidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
    if ($nasmPath) {
        $nasmDir = Split-Path -Parent $nasmPath
        $env:NASM_PREFIX = "$nasmDir\"
        $env:PATH = "$nasmDir;$env:PATH"
    }
}

if (-not (Get-Command "nasm.exe" -ErrorAction SilentlyContinue)) {
    throw "NASM is required for X64 EDK II builds. Install NASM 2.15.05 or later and add nasm.exe to PATH, or set NASM_PREFIX to the folder containing nasm.exe."
}

$relativePath = $projectRoot.Substring($workspace.Length).TrimStart("\", "/") -replace "\\", "/"
$packagePath = $relativePath
$dscPath = "$packagePath/edk2/BootkitPkg.dsc"

$cleanFlag = if ($Clean) { "-c" } else { "" }

function Invoke-Edk2Build {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $true)]
        [string]$Command
    )

    Write-Host $Description
    cmd.exe /c $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE."
    }
}

function Update-HookHandlerShellcode {
    $nasmSource = Join-Path $projectRoot "edk2\asm\hook_handler.nasm"
    $nasmOutput = Join-Path $projectRoot "edk2\asm\hook_handler.bin"
    $generatedDir = Join-Path $projectRoot "edk2\generated"
    $generatedHeader = Join-Path $generatedDir "hook_handler_shellcode.hpp"

    if (-not (Test-Path $nasmSource)) {
        throw "NASM source not found: $nasmSource"
    }

    Write-Host "Assembling hook handler..." -ForegroundColor Cyan
    & nasm.exe -f bin $nasmSource -o $nasmOutput
    if ($LASTEXITCODE -ne 0) {
        throw "Assembling hook_handler.nasm failed with exit code $LASTEXITCODE."
    }

    $bytes = [System.IO.File]::ReadAllBytes($nasmOutput)
    $marker = [byte[]](0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE)
    $runtimePtrOffset = -1

    for ($i = 0; $i -le ($bytes.Length - $marker.Length); $i++) {
        $matched = $true
        for ($j = 0; $j -lt $marker.Length; $j++) {
            if ($bytes[$i + $j] -ne $marker[$j]) {
                $matched = $false
                break
            }
        }

        if ($matched) {
            $runtimePtrOffset = $i
            break
        }
    }

    if ($runtimePtrOffset -lt 0) {
        throw "Unable to find runtime pointer marker in $nasmOutput."
    }

    New-Item -ItemType Directory -Path $generatedDir -Force | Out-Null

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("#pragma once")
    $lines.Add("#include <stdint.h>")
    $lines.Add("")
    $lines.Add("// Auto-generated from edk2/asm/hook_handler.nasm - DO NOT EDIT MANUALLY")
    $lines.Add("namespace ebs")
    $lines.Add("{")
    $lines.Add("  static const uint64_t SC_RUNTIME_PTR = 0x$($runtimePtrOffset.ToString("X"));")
    $lines.Add("")
    $lines.Add("  static uint8_t hook_handler_shellcode[] = {")

    for ($i = 0; $i -lt $bytes.Length; $i += 16) {
        $end = [Math]::Min($i + 15, $bytes.Length - 1)
        $chunk = for ($j = $i; $j -le $end; $j++) {
            "0x{0:X2}" -f $bytes[$j]
        }
        $lines.Add("      $($chunk -join ', '),")
    }

    $lines.Add("  };")
    $lines.Add("}")

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllLines($generatedHeader, $lines, $utf8NoBom)

    Write-Host "Generated $generatedHeader ($($bytes.Length) bytes, runtime pointer offset 0x$($runtimePtrOffset.ToString("X")))." -ForegroundColor Green
}

# ----------------------------------------------------------------
# Function to sign an EFI file using Windows tools
# ----------------------------------------------------------------
function Find-SignTool {
    $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }

    $kitRoots = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin",
        "$env:ProgramFiles\Windows Kits\10\bin"
    )

    foreach ($root in $kitRoots) {
        if (-not (Test-Path $root)) {
            continue
        }

        $candidate = Get-ChildItem -Path $root -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match "\\x64\\signtool\.exe$" } |
            Sort-Object FullName -Descending |
            Select-Object -First 1

        if ($candidate) {
            return $candidate.FullName
        }
    }

    return $null
}

function Find-OpenSsl {
    $cmd = Get-Command openssl.exe -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }

    $candidates = @(
        "$env:ProgramFiles\OpenSSL-Win64\bin\openssl.exe",
        "$env:ProgramFiles\Git\mingw64\bin\openssl.exe",
        "$env:ProgramFiles\Git\usr\bin\openssl.exe",
        "${env:ProgramFiles(x86)}\OpenSSL-Win32\bin\openssl.exe"
    )

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    return $null
}

function Sign-EfiFile {
    param(
        [string]$EfiPath
    )

    if (-not (Test-Path $EfiPath)) {
        Write-Host "??  EFI file not found, skipping signing: $EfiPath" -ForegroundColor Yellow
        return
    }

    $keyDir = Join-Path $PSScriptRoot "secure-boot-keys"
    $keyPath = Join-Path $keyDir "db.key"
    $certPath = Join-Path $keyDir "db.crt"
    $pfxPath = Join-Path $keyDir "db.pfx"

    if (-not (Test-Path $keyPath)) {
        Write-Host "? Key file not found: $keyPath" -ForegroundColor Red
        return
    }

    if (-not (Test-Path $certPath)) {
        Write-Host "? Cert file not found: $certPath" -ForegroundColor Red
        return
    }

    $openssl = Find-OpenSsl
    if (-not $openssl) {
        Write-Host "? Signing skipped: openssl.exe was not found." -ForegroundColor Yellow
        Write-Host "   Install OpenSSL, or Git for Windows with OpenSSL, to create $pfxPath" -ForegroundColor Gray
        return
    }

    $signTool = Find-SignTool
    if (-not $signTool) {
        Write-Host "? Signing skipped: signtool.exe was not found." -ForegroundColor Yellow
        Write-Host "   Install the Windows SDK signing tools." -ForegroundColor Gray
        return
    }

    $pfxNeedsUpdate = -not (Test-Path $pfxPath)
    if (-not $pfxNeedsUpdate) {
        $pfxTime = (Get-Item $pfxPath).LastWriteTimeUtc
        $pfxNeedsUpdate =
            (Get-Item $keyPath).LastWriteTimeUtc -gt $pfxTime -or
            (Get-Item $certPath).LastWriteTimeUtc -gt $pfxTime
    }

    if ($pfxNeedsUpdate) {
        Write-Host "Creating PFX: $pfxPath" -ForegroundColor Cyan
        & $openssl pkcs12 -export -inkey $keyPath -in $certPath -out $pfxPath -passout "pass:"

        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $pfxPath)) {
            Write-Host "? Failed to create PFX from Secure Boot keys." -ForegroundColor Red
            return
        }
    }

    Write-Host "Signing: $EfiPath" -ForegroundColor Cyan
    Write-Host "   Using PFX: $pfxPath" -ForegroundColor Gray
    Write-Host "   Using SignTool: $signTool" -ForegroundColor Gray

    & $signTool sign /fd SHA256 /f $pfxPath $EfiPath

    if ($LASTEXITCODE -eq 0) {
        Write-Host "? Signed successfully: $EfiPath" -ForegroundColor Green
    } else {
        Write-Host "? Signing failed for $EfiPath" -ForegroundColor Red
        Write-Host "   Command: `"$signTool`" sign /fd SHA256 /f `"$pfxPath`" `"$EfiPath`"" -ForegroundColor Gray
    }
}

# ----------------------------------------------------------------
# Determine build output folder
# ----------------------------------------------------------------
$buildFolder = "$workspace\Build\BootkitPkg\$Target`_$Toolchain\X64"
Write-Host "Build folder: $buildFolder" -ForegroundColor Cyan

function Build-Module {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Inf,

        [Parameter(Mandatory = $true)]
        [string]$Output
    )

    $cmd = "cd /d `"$workspace`" && edksetup.bat Rebuild && build $cleanFlag -a X64 -t $Toolchain -b $Target -p `"$dscPath`" -m `"$packagePath/$Inf`""
    Invoke-Edk2Build -Description "Building $Name..." -Command $cmd

    $efi = Join-Path $buildFolder $Output
    Sign-EfiFile -EfiPath $efi

    return
}

if ($Module -eq "All" -or $Module -eq "Bootkit") {
    Update-HookHandlerShellcode
    Build-Module -Name "bootkit" -Inf "bootkit/impl/bootkit.inf" -Output "bootkit.efi"
    $bootkitEfi = Join-Path $buildFolder "bootkit.efi"

    $embedScript = Join-Path $projectRoot "tools\embed_bootkit.py"
    if (Test-Path $embedScript) {
        Write-Host "Embedding bootkit image..." -ForegroundColor Cyan
        py -3 $embedScript $bootkitEfi
        if ($LASTEXITCODE -ne 0) {
            throw "Embedding bootkit image failed with exit code $LASTEXITCODE."
        }
    }
}

if ($Module -eq "All" -or $Module -eq "EmbeddedLoader") {
    Build-Module -Name "embedded_loader" -Inf "embedded_loader/impl/embedded_loader.inf" -Output "embedded_loader.efi" | Out-Null
}

Write-Host "Build completed!" -ForegroundColor Green
