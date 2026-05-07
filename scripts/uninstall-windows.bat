@echo off
setlocal

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall-windows.ps1" %*
set "EXIT_CODE=%ERRORLEVEL%"
echo.
if "%EXIT_CODE%"=="0" (
  echo SecChk uninstall finished.
) else (
  echo SecChk uninstall failed with exit code %EXIT_CODE%.
)
pause
exit /b %EXIT_CODE%
