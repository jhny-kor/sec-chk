@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..\..\..") do set "REPO_DIR=%%~fI"
cd /d "%REPO_DIR%" || (
  echo Failed to enter repository folder: "%REPO_DIR%"
  pause
  exit /b 1
)

if not exist "%REPO_DIR%\platforms\shared\python\security_scanner\" (
  echo security_scanner folder was not found.
  echo Run this launcher from the extracted KODA repository.
  pause
  exit /b 1
)

set "PYTHONPATH=%REPO_DIR%\platforms\shared\python;%PYTHONPATH%"

set "PYTHON_CMD="
where py >nul 2>nul
if not errorlevel 1 (
  py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul
  if not errorlevel 1 set "PYTHON_CMD=py -3"
)

if not defined PYTHON_CMD (
  where python >nul 2>nul
  if not errorlevel 1 (
    python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul
    if not errorlevel 1 set "PYTHON_CMD=python"
  )
)

if not defined PYTHON_CMD (
  echo Python 3.10 or newer was not found.
  echo Install Python from https://www.python.org/downloads/windows/ and run this launcher again.
  pause
  exit /b 1
)

%PYTHON_CMD% -m security_scanner app %*
set "EXIT_CODE=%ERRORLEVEL%"
if not "%EXIT_CODE%"=="0" (
  echo.
  echo KODA stopped with exit code %EXIT_CODE%.
  pause
)
exit /b %EXIT_CODE%
