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
set "NODEEXE="
set "NODEVER="
set "NODEMAJOR="

rem Minimum Node this check needs -- read off the sources, not guessed: the
rem exact-pinned tier-2 SDK (@camunda8/orchestration-cluster-api 9.1.2 in
rem package.json/package-lock.json) declares engines.node ">=22", npm's own
rem install-time-enforced contract and the same 22+ the PATH-lookup message
rem below already cites. Its lower sub-floors are Node 18 (the global `fetch`
rem the SDK's HTTP client calls -- below it, tier 2 dies with a bare "fetch is
rem not defined") and Node 20.18.1 (the pinned undici behind
rem --ts-proxy-support). Below the floor the version is reported as a SKIP
rem fragment instead.
set "NODE_MIN_MAJOR=22"

if defined CAMUNDA_NODE_BIN (
  rem Pinned by the operator (--node-bin, or this env var set directly). Used
  rem for EVERY invocation below, and never falling back to PATH: Node's CA set
  rem and TLS stack vary between majors, so falling back would check a different
  rem installation than the one that was asked for -- the exact failure mode
  rem pinning exists to remove.
  call :nodeversion "!CAMUNDA_NODE_BIN!"
  if not defined NODEVER (
    echo CAMUNDA_NODE_BIN is set to: !CAMUNDA_NODE_BIN! 1>&2
    echo That is not a usable node binary -- it is missing, not executable, or it does not answer to --version. 1>&2
    echo Refusing to fall back to the node on PATH: a different Node installation has its own TLS stack and bundled 1>&2
    echo CA set, so the result would not describe the Node you pinned. Fix the path, or unset it to use PATH. 1>&2
    exit /b 1
  )
  set "NODEEXE=!CAMUNDA_NODE_BIN!"
) else (
  where node >nul 2>nul
  if not !ERRORLEVEL!==0 (
    echo node not found on PATH -- Node.js is required ^(22+ recommended, matching the real Camunda TypeScript SDK's package.json engines field^) 1>&2
    exit /b 1
  )
  rem Existing on PATH is not the same as being the runtime, so the candidate
  rem only counts once it has identified itself -- the same rule the launcher
  rem applies on its own side.
  call :nodeversion "node"
  if not defined NODEVER (
    echo node is on PATH but does not answer as a working Node.js runtime -- pass --node-bin, or set CAMUNDA_NODE_BIN, to point at a real one 1>&2
    exit /b 1
  )
  set "NODEEXE=node"
)

rem --- Minimum-version floor, for TIER 2 ONLY. Tier 1 uses just tls/net and
rem runs on far older Node than the SDK needs, so it is never gated: withholding
rem it would hide the answer with the long lead time, since upgrading Node is a
rem local job while a firewall change is an IT request measured in weeks. ---
set "TIER2_SUPPORTED=1"
if !NODEMAJOR! LSS !NODE_MIN_MAJOR! set "TIER2_SUPPORTED=0"

rem --- Tier 2's opt-in install shells out to `npm`, which is a SEPARATE
rem executable -- the pinned node binary cannot stand in for it. Keep the npm
rem that BELONGS to the pinned node, its sibling in the same directory, by
rem putting that directory first on PATH, so the install and the run that
rem follows it can never land on two different Node installations. If there is
rem no sibling npm, say so rather than quietly using whichever npm PATH happens
rem to offer. ---
rem Skipped entirely when tier 2 won't run: the npm handling exists only for its
rem optional install, so doing it anyway would emit a misleading warning.
if "!TIER2_SUPPORTED!"=="1" if defined CAMUNDA_NODE_BIN (
  for %%I in ("!CAMUNDA_NODE_BIN!") do set "NODEDIR=%%~dpI"
  if exist "!NODEDIR!npm.cmd" (
    set "PATH=!NODEDIR!;!PATH!"
  ) else (
    echo [typescript probe] no npm.cmd next to the pinned node in !NODEDIR! -- tier 2's optional install step would fall back to whichever npm is on PATH, which may belong to a different Node installation 1>&2
    rem The directory is named on stderr only, never inside the fragment: a
    rem Windows path's backslashes are invalid JSON escapes and the launcher
    rem silently drops the whole fragment (the same bug already documented in
    rem the java run.cmd). No parentheses in the detail string either --
    rem unescaped '(' / ')' break echo inside a batch parenthesized block.
    echo {"runtime":"typescript","trustStoreExercised":"","target":"npm","verdict":"WARN","errorClass":"CONFIG_ERROR","detail":"You pinned a node binary with --node-bin / CAMUNDA_NODE_BIN, but there is no npm next to it -- see stderr for the directory. npm is a separate executable, so tier 2 optional install step would use whichever npm is on PATH, possibly one belonging to a different Node installation, which would install for a runtime other than the one being checked here."}
  )
)

rem `call`, not a bare invocation: a pinned node may be a .cmd/.bat wrapper (a
rem version-manager shim), and running a batch file without `call` TRANSFERS
rem control instead of returning -- everything after it, including tier 2 and
rem the exit code, would silently never run. Same reason the java run.cmd calls
rem Maven with `call mvn`.
set RC=0

rem --- Tier 1: native trust probe (mandatory, zero dependencies) ---
call "!NODEEXE!" "%DIR%probe.js" %*
if not !ERRORLEVEL!==0 set RC=1

rem --- Tier 2: real SDK confirmation (optional -- probe_sdk.js handles its
rem own opt-in `npm ci` against the committed, hash-verified lockfile). ---
if "!TIER2_SUPPORTED!"=="1" (
  call "!NODEEXE!" "%DIR%probe_sdk.js" %*
  if not !ERRORLEVEL!==0 set RC=1
) else (
  rem SKIP, not FAIL: too old a Node is a machine-setup fact, not a network
  rem finding. States that the trust check above still counts, so a valid result
  rem isn't discarded. Only version numbers go into the JSON -- never the node
  rem path, whose backslashes are invalid JSON escapes -- and no parentheses,
  rem which would break echo inside this block.
  echo {"runtime":"typescript","trustStoreExercised":"","target":"sdk","verdict":"SKIP","errorClass":"OK","detail":"Node.js !NODEVER! is too old to run the SDK check, which needs Node.js !NODE_MIN_MAJOR! or newer -- the version the pinned Camunda TypeScript SDK itself requires. The trust check above DID run on this Node and its result stands. To exercise the SDK too, install Node.js !NODE_MIN_MAJOR!+, or point this check at one you already have with --node-bin / CAMUNDA_NODE_BIN."}
)

exit /b !RC!

rem --- helper: sets NODEVER/NODEMAJOR from a candidate node binary (%1), and
rem leaves NODEVER empty when the candidate is missing, not executable, or does
rem not answer as Node.js. Two invocations on purpose: the first checks the EXIT
rem STATUS (a lookalike shim can print something and still fail), the second
rem parses the answer. ---
:nodeversion
set "NODEVER="
set "NODEMAJOR="
call "%~1" --version >nul 2>nul
if errorlevel 1 goto :eof
rem tokens=1, not tokens=*: the first whitespace-delimited token already is the
rem whole answer ("v22.14.0"), and this drops any trailing whitespace that would
rem otherwise land inside the version text of an emitted fragment.
for /f "usebackq tokens=1" %%a in (`"%~1" --version 2^>^&1`) do (
  if not defined NODEVER set "NODEVER=%%a"
)
if not defined NODEVER goto :eof
if /i "!NODEVER:~0,1!"=="v" set "NODEVER=!NODEVER:~1!"
echo !NODEVER! | findstr /r /c:"^[0-9][0-9]*\.[0-9][0-9]*" >nul
if errorlevel 1 (
  set "NODEVER="
  goto :eof
)
for /f "tokens=1 delims=." %%a in ("!NODEVER!") do set "NODEMAJOR=%%a"
goto :eof
