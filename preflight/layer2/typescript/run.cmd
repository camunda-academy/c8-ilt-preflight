@echo off
rem Layer 2 TypeScript/Node.js probe entrypoint (invoked by the launcher; also
rem runnable standalone by hand -- some corporate EDR/AV tooling blocks or
rem flags unsigned/unfamiliar binaries, so being able to run this as a plain
rem batch script plus the system node binary, with no compiled artifact of
rem its own, is a deliberate fallback).
rem
rem Runs BOTH tiers and concatenates their fragments on stdout: probe.js
rem (mandatory, SDK-free native trust check) and probe_sdk.js (tier 2, the
rem real @camunda8/orchestration-cluster-api confirmation -- SKIPs cleanly if
rem the SDK isn't installed and auto-install isn't opted in). Runs the second
rem even if the first FAILs.
rem
rem Unlike Java (separate javac compile step + Maven-fetched classpath dance),
rem Node needs neither -- both tiers are plain, already-runnable JS, and
rem probe_sdk.js resolves/installs its own dependency via ordinary
rem node_modules lookup rooted at this directory.
setlocal enabledelayedexpansion
set "DIR=%~dp0"

where node >nul 2>nul
if not %ERRORLEVEL%==0 (
  echo node not found on PATH -- Node.js is required ^(22+ recommended, matching the real Camunda TypeScript SDK's package.json engines field^) 1>&2
  exit /b 1
)

set RC=0

rem --- Tier 1: native trust probe (mandatory, zero dependencies) ---
node "%DIR%probe.js" %*
if not %ERRORLEVEL%==0 set RC=1

rem --- Tier 2: real SDK confirmation (optional -- probe_sdk.js handles its
rem own opt-in `npm ci` against the committed, hash-verified lockfile). ---
node "%DIR%probe_sdk.js" %*
if not !ERRORLEVEL!==0 set RC=1

exit /b %RC%
