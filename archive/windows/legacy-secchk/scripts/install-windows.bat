@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "INSTALL_PS1=%SCRIPT_DIR%install-windows.ps1"
for %%I in ("%SCRIPT_DIR%..") do set "REPO_DIR=%%~fI"

if not exist "%INSTALL_PS1%" (
  echo install-windows.ps1 was not found.
  echo Extract the full sec-chk ZIP or clone the repository, then run scripts\install-windows.bat.
  pause
  exit /b 1
)

if not exist "%REPO_DIR%\security_scanner\" (
  echo security_scanner folder was not found.
  echo Do not run this installer from inside the compressed ZIP file.
  echo Extract the full sec-chk repository first, then run scripts\install-windows.bat.
  pause
  exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%INSTALL_PS1%" %*
set "EXIT_CODE=%ERRORLEVEL%"
echo.
if "%EXIT_CODE%"=="0" (
  echo SecChk installation finished.
) else (
  echo SecChk installation failed with exit code %EXIT_CODE%.
)
pause
exit /b %EXIT_CODE%
