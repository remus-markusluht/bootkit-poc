@echo off
setlocal

set "REPO_ROOT=%~dp0.."
for %%I in ("%REPO_ROOT%") do set "REPO_ROOT=%%~fI"

if "%EDK2_WORKSPACE%"=="" (
  for %%I in ("%REPO_ROOT%\..") do set "EDK2_WORKSPACE=%%~fI"
)

if not exist "%EDK2_WORKSPACE%\edksetup.bat" (
  echo EDK2_WORKSPACE does not contain edksetup.bat: %EDK2_WORKSPACE%
  exit /b 1
)

endlocal & set "REPO_ROOT=%REPO_ROOT%" & set "EDK2_WORKSPACE=%EDK2_WORKSPACE%"
