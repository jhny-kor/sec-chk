@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "BUILD_PS1=%SCRIPT_DIR%build-koda-windows-installer.ps1"
for %%I in ("%SCRIPT_DIR%..\..\..") do set "REPO_DIR=%%~fI"

if not exist "%BUILD_PS1%" (
  echo build-koda-windows-installer.ps1 was not found.
  echo Extract the full repository, then run platforms\windows\scripts\build-koda-windows-installer.bat.
  pause
  exit /b 1
)

if not exist "%REPO_DIR%\platforms\shared\python\security_scanner\" (
  echo security_scanner folder was not found.
  echo Do not run this build script from inside the compressed ZIP file.
  echo Extract the full repository first, then run platforms\windows\scripts\build-koda-windows-installer.bat.
  pause
  exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%BUILD_PS1%" %*
set "EXIT_CODE=%ERRORLEVEL%"
echo.
if "%EXIT_CODE%"=="0" (
  echo KODA Windows installer build finished.
) else (
  echo KODA Windows installer build failed with exit code %EXIT_CODE%.
)
pause
exit /b %EXIT_CODE%
