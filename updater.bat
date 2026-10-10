@echo off
setlocal EnableExtensions

rem ==========================================================================
rem  DiskFree updater -- Windows
rem
rem  A thin launcher: all the logic lives in diskfree\updater.py, which uses
rem  nothing but the Python standard library, so this works on a fresh clone
rem  even before DiskFree's dependencies have been installed.
rem
rem    updater.bat                 fetch, fast-forward, refresh dependencies
rem    updater.bat --check         report what would change, modify nothing
rem    updater.bat --branch main   follow a specific branch
rem    updater.bat --no-deps       update the code only
rem    updater.bat --json          machine-readable report
rem    updater.bat --help          every option
rem
rem  Environment:
rem    DISKFREE_PYTHON   interpreter to use (default: .venv, then py -3/python)
rem
rem  Exit codes: 0 up to date or updated, 1 something failed, 2 bad usage,
rem              127 no usable Python interpreter.
rem
rem  This script never discards local changes, never deletes files, and never
rem  runs the cleaner. Updating DiskFree cannot become a way of running it.
rem ==========================================================================

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
set "UPDATER=%ROOT%\diskfree\updater.py"

if not exist "%UPDATER%" (
    echo error: cannot find %UPDATER% 1>&2
    echo        Run this script from the root of a DiskFree checkout. 1>&2
    exit /b 2
)

rem --- which Python? -------------------------------------------------------
set "PY_CMD="
if defined DISKFREE_PYTHON set "PY_CMD=%DISKFREE_PYTHON%"

if not defined PY_CMD if exist "%ROOT%\.venv\Scripts\python.exe" set "PY_CMD=%ROOT%\.venv\Scripts\python.exe"
if not defined PY_CMD if exist "%ROOT%\venv\Scripts\python.exe" set "PY_CMD=%ROOT%\venv\Scripts\python.exe"
if not defined PY_CMD (
    where py >nul 2>&1
    if not errorlevel 1 set "PY_CMD=py -3"
)
if not defined PY_CMD (
    where python >nul 2>&1
    if not errorlevel 1 set "PY_CMD=python"
)
if not defined PY_CMD (
    where python3 >nul 2>&1
    if not errorlevel 1 set "PY_CMD=python3"
)

if not defined PY_CMD (
    echo error: no Python interpreter found. 1>&2
    echo        DiskFree needs Python 3.11 or newer. 1>&2
    echo        Install it from https://www.python.org/downloads/ and tick 1>&2
    echo        "Add python.exe to PATH", then run this script again. 1>&2
    goto :finish_no_python
)

rem --- run -----------------------------------------------------------------
%PY_CMD% "%UPDATER%" --root "%ROOT%" %*
set "CODE=%ERRORLEVEL%"
goto :finish

:finish_no_python
set "CODE=127"

:finish
rem Pause only when the script was double-clicked from Explorer, so that
rem scheduled tasks and CI are never left waiting for a keypress.
echo %CMDCMDLINE% | find /i "%~nx0" >nul 2>&1
if not errorlevel 1 pause

endlocal & exit /b %CODE%
