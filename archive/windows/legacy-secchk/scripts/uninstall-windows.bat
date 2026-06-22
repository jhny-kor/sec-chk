@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "UNINSTALL_PS1=%SCRIPT_DIR%uninstall-windows.ps1"

if not exist "%UNINSTALL_PS1%" (
  echo uninstall-windows.ps1 was not found.
  echo Run %%LOCALAPPDATA%%\SecChk\Uninstall-SecChk.ps1 if SecChk is already installed.
  pause
  exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%UNINSTALL_PS1%" %*
set "EXIT_CODE=%ERRORLEVEL%"
echo.
if "%EXIT_CODE%"=="0" (
  echo SecChk uninstall finished.
) else (
  echo SecChk uninstall failed with exit code %EXIT_CODE%.
)
pause
exit /b %EXIT_CODE%
