@echo off
setlocal

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-windows.ps1" %*
set "EXIT_CODE=%ERRORLEVEL%"
echo.
if "%EXIT_CODE%"=="0" (
  echo SecChk installation finished.
) else (
  echo SecChk installation failed with exit code %EXIT_CODE%.
)
pause
exit /b %EXIT_CODE%
