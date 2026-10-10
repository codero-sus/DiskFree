@echo off
setlocal EnableExtensions DisableDelayedExpansion

rem ==========================================================================
rem  DiskFree updater -- Windows
rem
rem  A thin launcher: all the logic lives in diskfree\updater.py, which uses
rem  only the Python standard library, so this works before DiskFree's
rem  dependencies have been installed.
rem
rem    updater.bat                 fetch, fast-forward, refresh dependencies
rem    updater.bat --check         fetch remote refs; leave checkout/dependencies untouched
rem    updater.bat --show-python   show the interpreter resolution
rem    updater.bat --branch X      follow a branch other than the default
rem    updater.bat --no-deps       update the code only
rem    updater.bat --json          machine-readable report
rem
rem  Interpreter order (first usable Python 3.11+ wins):
rem    1. DISKFREE_PYTHON environment variable
rem    2. python.env in this folder: DISKFREE_PYTHON, PYTHON, then 2PY2
rem       A plain one-line path is also accepted (same as PYTHON=path).
rem    3. 2PY2 environment variable (the "second Python", not Python 2)
rem    4. .venv\Scripts\python.exe or venv\Scripts\python.exe here
rem    5. py -3, then python3/python from PATH
rem
rem  python.env examples (choose one):
rem    DISKFREE_PYTHON=C:\portable-python\python.exe
rem    2PY2=..\portable-python\python.exe
rem    C:\portable-python\python.exe
rem  Relative paths in python.env are relative to this project folder.
rem
rem  Updates are taken from origin/arena/0392f96c-diskfree unless --branch
rem  says otherwise. This updater never discards local changes, deletes files,
rem  or runs the cleaner.
rem ==========================================================================

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
set "UPDATER=%ROOT%\diskfree\updater.py"
set "PY_ENV_FILE=%ROOT%\python.env"
set "PYTHON_CHECK=import sys;sys.exit(0 if sys.version_info[:2]>=(3,11) else 1)"

if not exist "%UPDATER%" (
    echo error: cannot find %UPDATER% 1>&2
    echo        Run the updater from the root of a DiskFree checkout. 1>&2
    exit /b 2
)

set "PY_EXE="
set "PY_ARGS="
set "PY_SOURCE="

rem --- explicit environment variable ---------------------------------------
if defined DISKFREE_PYTHON (
    set "PY_CANDIDATE=%DISKFREE_PYTHON%"
    set "PY_CAND_SOURCE=DISKFREE_PYTHON (environment)"
    call :try_candidate
)
if defined PY_EXE goto :run

rem --- optional python.env file --------------------------------------------
set "ENV_FILE_DISKFREE_PYTHON="
set "ENV_FILE_PYTHON="
set "ENV_FILE_2PY2="
if exist "%PY_ENV_FILE%" (
    for /f "usebackq tokens=1,* delims==" %%A in ("%PY_ENV_FILE%") do (
        set "ENV_KEY=%%A"
        set "ENV_VALUE=%%B"
        call :read_python_env_line
    )
)

if defined ENV_FILE_DISKFREE_PYTHON (
    set "PY_CANDIDATE=%ENV_FILE_DISKFREE_PYTHON%"
    set "PY_CAND_SOURCE=python.env (DISKFREE_PYTHON)"
    call :try_candidate
)
if defined PY_EXE goto :run

if defined ENV_FILE_PYTHON (
    set "PY_CANDIDATE=%ENV_FILE_PYTHON%"
    set "PY_CAND_SOURCE=python.env (PYTHON or plain path)"
    call :try_candidate
)
if defined PY_EXE goto :run

if defined ENV_FILE_2PY2 (
    set "PY_CANDIDATE=%ENV_FILE_2PY2%"
    set "PY_CAND_SOURCE=python.env (2PY2)"
    call :try_candidate
)
if defined PY_EXE goto :run

rem --- the unusual-but-valid environment variable named "2PY2" -------------
rem  CMD treats %2PY2% as the second batch argument followed by "PY2". Read the
rem  actual environment entry using SET's prefix filter and keep only an exact
rem  key match. This works for env 2PY2=C:\portable\python.exe as well.
set "PY_CANDIDATE="
for /f "tokens=1,* delims==" %%A in ('set 2PY2 2^>nul') do if /i "%%A"=="2PY2" set "PY_CANDIDATE=%%B"
if defined PY_CANDIDATE (
    set "PY_CAND_SOURCE=2PY2 (environment)"
    call :try_candidate
)
if defined PY_EXE goto :run

rem --- virtual environments inside the project ----------------------------
if exist "%ROOT%\.venv\Scripts\python.exe" (
    set "PY_CANDIDATE=%ROOT%\.venv\Scripts\python.exe"
    set "PY_CAND_SOURCE=.venv inside the project"
    call :try_candidate
)
if defined PY_EXE goto :run

if exist "%ROOT%\venv\Scripts\python.exe" (
    set "PY_CANDIDATE=%ROOT%\venv\Scripts\python.exe"
    set "PY_CAND_SOURCE=venv inside the project"
    call :try_candidate
)
if defined PY_EXE goto :run

rem --- PATH: the Windows Python launcher first, then named interpreters -----
set "PY_CANDIDATE=py -3"
set "PY_CAND_SOURCE=the Windows py launcher"
call :try_candidate
if defined PY_EXE goto :run

for %%N in (python3 python) do (
    set "PY_CANDIDATE=%%N"
    set "PY_CAND_SOURCE=PATH (%%N)"
    call :try_candidate
    if defined PY_EXE goto :run
)

echo error: no usable Python 3.11+ interpreter found. 1>&2
echo. 1>&2
echo        Install Python from https://www.python.org/downloads/ and tick 1>&2
echo        "Add python.exe to PATH", or use the py launcher. 1>&2
echo. 1>&2
echo        Then point DiskFree at it in any of these ways: 1>&2
echo          echo C:\portable-python\python.exe ^> "%PY_ENV_FILE%" 1>&2
echo          set "DISKFREE_PYTHON=C:\portable-python\python.exe" 1>&2
echo          set "2PY2=C:\portable-python\python.exe" 1>&2
echo          updater.bat --python C:\portable-python\python.exe 1>&2
set "CODE=127"
goto :finish

rem --- launch ----------------------------------------------------------------
:run
if defined DISKFREE_DEBUG echo DiskFree updater: %PY_EXE% %PY_ARGS% from %PY_SOURCE% 1>&2
if defined PY_ARGS (
    %PY_EXE% %PY_ARGS% "%UPDATER%" --root "%ROOT%" %*
) else (
    "%PY_EXE%" "%UPDATER%" --root "%ROOT%" %*
)
set "CODE=%ERRORLEVEL%"
goto :finish

:finish
rem Pause only when double-clicked from Explorer; CI and scheduled tasks never
rem wait for a keypress. Do not pause if the caller explicitly set NO_PAUSE.
if not defined NO_PAUSE echo %CMDCMDLINE% | find /i "%~nx0" >nul 2>&1
if not defined NO_PAUSE if not errorlevel 1 pause
endlocal & exit /b %CODE%

rem ==========================================================================
rem  Subroutines
rem ==========================================================================

:read_python_env_line
rem FOR /F skips blank lines; this skips comment lines and trims key whitespace.
if not defined ENV_KEY exit /b 0
set "ENV_KEY=%ENV_KEY:"=%"
for /f "tokens=* delims= " %%K in ("%ENV_KEY%") do set "ENV_KEY=%%K"
if "%ENV_KEY:~0,1%"=="#" exit /b 0
if "%ENV_KEY:~0,1%"==";" exit /b 0
if "%ENV_KEY:~0,1%"=="@" exit /b 0
if /i "%ENV_KEY:~0,4%"=="rem " exit /b 0
if /i "%ENV_KEY:~0,7%"=="export " set "ENV_KEY=%ENV_KEY:~7%"
if /i "%ENV_KEY:~0,4%"=="set " set "ENV_KEY=%ENV_KEY:~4%"
set "ENV_KEY=%ENV_KEY:"=%"
set "ENV_KEY=%ENV_KEY: =%"

rem Ignore empty known assignments; otherwise an empty DISKFREE_PYTHON=
rem would be mistaken for a bare path named "DISKFREE_PYTHON".
if not defined ENV_VALUE if /i "%ENV_KEY%"=="DISKFREE_PYTHON" exit /b 0
if not defined ENV_VALUE if /i "%ENV_KEY%"=="PYTHON" exit /b 0
if not defined ENV_VALUE if /i "%ENV_KEY%"=="2PY2" exit /b 0

rem A bare one-line path is equivalent to PYTHON=<path>.
if not defined ENV_VALUE (
    set "ENV_VALUE=%ENV_KEY%"
    set "ENV_KEY=PYTHON"
)
rem Remove optional quotes before FOR /F treats the value as an input string.
set "ENV_VALUE=%ENV_VALUE:"=%"
if "%ENV_VALUE:~0,1%"=="'" if "%ENV_VALUE:~-1%"=="'" set "ENV_VALUE=%ENV_VALUE:~1,-1%"
for /f "tokens=* delims= " %%V in ("%ENV_VALUE%") do set "ENV_VALUE=%%V"
:trim_env_value_right
if not defined ENV_VALUE exit /b 0
if "%ENV_VALUE:~-1%"==" " (
    set "ENV_VALUE=%ENV_VALUE:~0,-1%"
    goto :trim_env_value_right
)
if not defined ENV_VALUE exit /b 0

if /i "%ENV_KEY%"=="DISKFREE_PYTHON" set "ENV_FILE_DISKFREE_PYTHON=%ENV_VALUE%"
if /i "%ENV_KEY%"=="PYTHON" set "ENV_FILE_PYTHON=%ENV_VALUE%"
if /i "%ENV_KEY%"=="2PY2" set "ENV_FILE_2PY2=%ENV_VALUE%"
exit /b 0

:try_candidate
rem Remove optional quoting, surrounding spaces, then resolve project-relative
rem paths before asking PATH. `py -3` is the one supported command+args form.
if not defined PY_CANDIDATE exit /b 1
set "PY_CANDIDATE=%PY_CANDIDATE:"=%"
for /f "tokens=* delims= " %%V in ("%PY_CANDIDATE%") do set "PY_CANDIDATE=%%V"
if "%PY_CANDIDATE:~0,1%"=="'" if "%PY_CANDIDATE:~-1%"=="'" set "PY_CANDIDATE=%PY_CANDIDATE:~1,-1%"
set "PY_EXE="
set "PY_ARGS="

if /i "%PY_CANDIDATE%"=="py -3" (
    set "PY_EXE=py"
    set "PY_ARGS=-3"
) else if /i "%PY_CANDIDATE%"=="py.exe -3" (
    set "PY_EXE=py.exe"
    set "PY_ARGS=-3"
) else (
    set "PY_EXE=%PY_CANDIDATE%"
)

if not defined PY_ARGS if not exist "%PY_EXE%" if exist "%ROOT%\%PY_EXE%" set "PY_EXE=%ROOT%\%PY_EXE%"
if not defined PY_ARGS if not exist "%PY_EXE%" (
    where "%PY_EXE%" >nul 2>&1
    if errorlevel 1 goto :candidate_rejected
)
if defined PY_ARGS (
    where "%PY_EXE%" >nul 2>&1
    if errorlevel 1 goto :candidate_rejected
)

if defined PY_ARGS (
    %PY_EXE% %PY_ARGS% -c "%PYTHON_CHECK%" >nul 2>&1
) else (
    "%PY_EXE%" -c "%PYTHON_CHECK%" >nul 2>&1
)
if errorlevel 1 goto :candidate_rejected
set "PY_SOURCE=%PY_CAND_SOURCE%"
exit /b 0

:candidate_rejected
echo note: %PY_CAND_SOURCE% ("%PY_CANDIDATE%") is not a usable Python 3.11+; trying the next candidate. 1>&2
set "PY_EXE="
set "PY_ARGS="
exit /b 1
