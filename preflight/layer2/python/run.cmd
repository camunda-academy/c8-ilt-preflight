@echo off
rem Layer 2 Python probe entrypoint (invoked by the launcher; also runnable
rem standalone by hand for manual or security review without needing the
rem launcher).
rem
rem Runs BOTH probes and concatenates their fragments on stdout: probe.py
rem (mandatory, SDK-free trust check) and probe_sdk.py (tier 2, the real SDK
rem confirmation -- SKIPs cleanly if the SDK isn't installed and auto-install
rem isn't enabled). Runs the second even if the first reports a FAIL.
setlocal enabledelayedexpansion
set "DIR=%~dp0"
set "PYEXE="
set "PYARGS="
set "PYVER="
set "PYMAJOR="
set "PYMINOR="

rem Minimum Python this probe pair actually needs -- read off the sources, not
rem guessed: probe.py catches ssl.SSLCertVerificationError and probe_sdk.py
rem calls subprocess.run() with capture_output=/text=, and all three of those
rem arrived in 3.7. On anything older the probes die with an AttributeError/
rem TypeError traceback instead of producing a result, so the floor is reported
rem as a SKIP fragment below rather than left to crash in the operator's face.
set "PY_MIN=3.7"
set "PY_MIN_MAJOR=3"
set "PY_MIN_MINOR=7"

if defined CAMUNDA_PYTHON_BIN (
  rem Pinned by the operator (--python-bin, or this env var set directly). Used
  rem for EVERY invocation below, and never falling back to PATH: a trust store
  rem belongs to an installation, so falling back would check a different
  rem interpreter -- with its own certifi CA bundle -- than the one that was
  rem asked for, which is the exact failure mode pinning exists to remove.
  call :pyversion "!CAMUNDA_PYTHON_BIN!"
  if not defined PYVER (
    echo CAMUNDA_PYTHON_BIN is set to: !CAMUNDA_PYTHON_BIN! 1>&2
    echo That is not a usable Python interpreter -- it is missing, not executable, or it does not answer to --version. 1>&2
    echo Refusing to fall back to the python on PATH: that is a different installation with its own certificate 1>&2
    echo bundle, so the result would not describe the interpreter you pinned. Fix the path, or unset it to use PATH. 1>&2
    exit /b 1
  )
  set "PYEXE=!CAMUNDA_PYTHON_BIN!"
) else (
  rem Existing on disk is not the same as being the interpreter: Windows ships
  rem App Execution Alias stubs that are not Python at all -- they exit non-zero
  rem pointing at the Microsoft Store. So a candidate only counts once it has
  rem identified itself, the same rule the launcher applies on its own side.
  call :pyversion "python"
  if defined PYVER set "PYEXE=python"
  if not defined PYEXE (
    call :pyversion "py" "-3"
    if defined PYVER (
      set "PYEXE=py"
      set "PYARGS=-3"
    )
  )
  if not defined PYEXE (
    echo python/py not found on PATH, or what is on PATH does not answer as a working Python -- on Windows that is usually the Microsoft Store placeholder. Pass --python-bin, or set CAMUNDA_PYTHON_BIN, to point at a real interpreter. 1>&2
    exit /b 1
  )
)

rem --- Minimum-version floor. SKIP, not FAIL: this is a machine-setup fact, not
rem a network finding, and the fix may be as small as pointing at a newer
rem interpreter already installed. Only the version numbers are interpolated
rem into the JSON -- the interpreter path is deliberately never put in a
rem fragment, because a Windows path's backslashes are invalid JSON escapes and
rem the launcher silently drops the whole fragment (the same bug already
rem documented in the java run.cmd). No parentheses in the detail string either:
rem unescaped '(' / ')' break echo inside a batch parenthesized block. ---
set "PY_TOO_OLD=0"
if !PYMAJOR! LSS !PY_MIN_MAJOR! set "PY_TOO_OLD=1"
if !PYMAJOR!==!PY_MIN_MAJOR! if !PYMINOR! LSS !PY_MIN_MINOR! set "PY_TOO_OLD=1"
if "!PY_TOO_OLD!"=="1" (
  echo {"runtime":"python","trustStoreExercised":"","target":"runtime-version","verdict":"SKIP","errorClass":"OK","detail":"Python !PYVER! is too old for this check, which needs Python !PY_MIN! or newer. Nothing about your network was tested here. Install a newer Python, or point this check at one you already have with --python-bin / CAMUNDA_PYTHON_BIN."}
  exit /b 0
)

rem `call`, not a bare invocation: a pinned interpreter may be a .cmd/.bat
rem wrapper (a venv or version-manager shim), and running a batch file without
rem `call` TRANSFERS control instead of returning -- everything after it,
rem including the second probe and the exit code, would silently never run.
rem Same reason the java run.cmd calls Maven with `call mvn`.
set RC=0
call "!PYEXE!" !PYARGS! "%DIR%probe.py" %*
if not !ERRORLEVEL!==0 set RC=1
call "!PYEXE!" !PYARGS! "%DIR%probe_sdk.py" %*
if not !ERRORLEVEL!==0 set RC=1
exit /b !RC!

rem --- helper: sets PYVER/PYMAJOR/PYMINOR from a candidate interpreter (%1 = the
rem binary, %2 = an optional extra argument such as -3 for the py launcher), and
rem leaves PYVER empty when the candidate is missing, not executable, or does not
rem answer as Python. Two invocations on purpose: the first checks the EXIT
rem STATUS, which is what actually unmasks the Microsoft Store stub (it prints a
rem localized message starting with the word "Python" and fails), and the second
rem parses the answer. ---
:pyversion
set "PYVER="
set "PYMAJOR="
set "PYMINOR="
call "%~1" %~2 --version >nul 2>nul
if errorlevel 1 goto :eof
for /f "usebackq tokens=1,2" %%a in (`"%~1" %~2 --version 2^>^&1`) do (
  if not defined PYVER if /i "%%a"=="Python" set "PYVER=%%b"
)
if not defined PYVER goto :eof
echo !PYVER! | findstr /r /c:"^[0-9][0-9]*\.[0-9][0-9]*" >nul
if errorlevel 1 (
  set "PYVER="
  goto :eof
)
for /f "tokens=1,2 delims=." %%a in ("!PYVER!") do (
  set "PYMAJOR=%%a"
  set "PYMINOR=%%b"
)
goto :eof
