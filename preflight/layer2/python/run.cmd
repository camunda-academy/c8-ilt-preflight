@echo off
rem Layer 2 Python probe entrypoint (invoked by the launcher; also runnable
rem standalone by hand for manual or security review without needing the
rem launcher).
rem
rem Runs BOTH probes and concatenates their fragments on stdout: probe.py
rem (mandatory, SDK-free trust check) and probe_sdk.py (tier 2, the real SDK
rem confirmation -- SKIPs cleanly if the SDK isn't installed and auto-install
rem isn't enabled). Runs the second even if the first reports a FAIL.
setlocal
set "DIR=%~dp0"
set "PY="

where python >nul 2>nul
if %ERRORLEVEL%==0 set "PY=python"

if not defined PY (
  where py >nul 2>nul
  if %ERRORLEVEL%==0 set "PY=py -3"
)

if not defined PY (
  echo python/py not found on PATH 1>&2
  exit /b 1
)

set RC=0
%PY% "%DIR%probe.py" %*
if not %ERRORLEVEL%==0 set RC=1
%PY% "%DIR%probe_sdk.py" %*
if not %ERRORLEVEL%==0 set RC=1
exit /b %RC%
