@echo off
setlocal

call "%~dp0setup_env.bat" || exit /b 1
set "TARGET=%~1"
if "%TARGET%"=="" set "TARGET=DEBUG"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%REPO_ROOT%\tools\build-edk2.ps1" -Target "%TARGET%" -Module EmbeddedLoader
exit /b %ERRORLEVEL%
