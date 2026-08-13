@echo off
rem Layer 2 C#/.NET probe entrypoint (invoked by the launcher; also runnable
rem standalone by hand).
rem
rem Runs BOTH tiers and concatenates their fragments on stdout: the native
rem trust probe (mandatory, zero NuGet dependencies) and the real
rem Camunda.Orchestration.Sdk confirmation (tier 2 -- SKIPs cleanly if the
rem package isn't restored and auto-install isn't opted in). Runs the second
rem even if the first FAILs.
rem
rem `dotnet build`'s own restore/compile progress messages are redirected to
rem stderr (1>&2) below -- this probe's stdout is a machine-parsed,
rem newline-delimited JSON channel (the contract requires one JSON object on
rem stdout, nothing else), and `dotnet build`
rem prints its own progress lines to stdout by default, which would otherwise
rem corrupt that channel on every run. Only the final `dotnet <tier>.dll`
rem invocation's stdout is left unredirected.
setlocal enabledelayedexpansion
set "DIR=%~dp0"

rem Which dotnet to use. CAMUNDA_DOTNET_BIN (set by the launcher from
rem --dotnet-bin) pins a specific installation; a pin that doesn't work is a hard
rem error rather than a fall back to PATH, because checking a different
rem installation than the one that was asked for -- and reporting it as if it
rem were the same -- is the confusion the pin exists to remove.
rem !VAR! (delayed), never %VAR% (immediate): immediate expansion happens before
rem cmd tokenizes metacharacters, so a value containing " or & would be parsed
rem as command syntax rather than as data. Delayed expansion substitutes after
rem tokenization and is inert.
set "DOTNET=!CAMUNDA_DOTNET_BIN!"
set "DOTNET_PINNED=1"
if not defined DOTNET (
  set "DOTNET=dotnet"
  set "DOTNET_PINNED=0"
)

rem Asking for the version doubles as the check that this dotnet works at all,
rem so there is one mechanism instead of two that could disagree. It also
rem establishes whether the SDK is new enough to BUILD the tier-2 project, which
rem is fixed at net8.0 to keep its lockfile valid: an SDK cannot target a
rem framework newer than itself. Tier 1 is unaffected, deriving its target from
rem whichever SDK is present.
rem
rem `for /f` runs the command in its own cmd instance, which also makes this
rem work when DOTNET is a .cmd/.bat wrapper (a corporate-managed dotnet often
rem is): invoking a batch file directly from a batch file transfers control
rem permanently and never comes back, so every later invocation below uses
rem `call` for the same reason.
set "SDK_MAJOR="
for /f "delims=. tokens=1" %%v in ('"%DOTNET%" --version 2^>nul') do if not defined SDK_MAJOR set "SDK_MAJOR=%%v"

if not defined SDK_MAJOR (
  if "!DOTNET_PINNED!"=="1" (
    echo the .NET SDK selected explicitly ^(!CAMUNDA_DOTNET_BIN!^) is missing or does not report a version; not falling back to PATH, because that would check a different installation than the one requested 1>&2
  ) else (
    echo dotnet not found on PATH -- the .NET SDK is required ^(8.0+^) 1>&2
  )
  exit /b 1
)

set RC=0

rem --- Tier 1: native trust probe (mandatory, zero NuGet dependencies) ---
call "%DOTNET%" build "%DIR%Probe\Probe.csproj" -c Release -o "%DIR%Probe\out" --nologo -v quiet 1>&2
if %ERRORLEVEL%==0 (
  call "%DOTNET%" "%DIR%Probe\out\Probe.dll" %*
  if not !ERRORLEVEL!==0 set RC=1
) else (
  rem A fragment, not just stderr. This tier is mandatory, so a build failure
  rem means the trust check never ran -- and reporting it only on stderr is how
  rem it stayed invisible: the launcher saw the other tier's clean SKIP, found
  rem nothing failing, and printed "All checks passed" for a stack whose check
  rem never executed. No path in the JSON and no parentheses in the detail.
  echo dotnet build of Probe.csproj failed 1>&2
  echo {"runtime":"csharp","trustStoreExercised":"","target":"trust","verdict":"FAIL","errorClass":"PROBE_CRASHED","detail":"the C# trust check could not be built, so it never ran -- see the dotnet build output on stderr. On a restricted network this is usually NuGet being unreachable while the SDK tries to fetch a targeting pack for a .NET version it does not ship with."}
  set RC=1
)

rem --- Tier 2: real SDK confirmation (optional -- needs the
rem Camunda.Orchestration.Sdk NuGet package restored; opt-in fetch, same
rem reasoning as every other language's auto-install). ---
set "SDK_ASSETS=%DIR%SdkProbe\obj\project.assets.json"

rem Fetching the pinned SDK is the DEFAULT, and opting out is explicit. A tier
rem that silently SKIPs answers nothing about whether the real client reaches
rem the cluster, which is the question this tier exists to settle -- and a SKIP
rem sitting among PASS lines reads as "fine" to a participant scanning output.
rem Opt out with --no-install or CAMUNDA_SDK_AUTO_INSTALL=0.
rem /i for a case-insensitive compare, and !VAR! (delayed) so the value is never
rem re-parsed as command syntax the way %VAR% inside a block would be.
set AUTO_INSTALL=1
if /i "!CAMUNDA_SDK_AUTO_INSTALL!"=="0" set AUTO_INSTALL=0
if /i "!CAMUNDA_SDK_AUTO_INSTALL!"=="false" set AUTO_INSTALL=0
if /i "!CAMUNDA_SDK_AUTO_INSTALL!"=="no" set AUTO_INSTALL=0
if /i "!CAMUNDA_SDK_AUTO_INSTALL!"=="off" set AUTO_INSTALL=0
rem A shift-scan over %1, not `for %%A in (%*)`: an unquoted %* in a for-set is
rem expanded before tokenization, so an argument containing & or | would run as
rem a command, and it glob-expands against the working directory. %~1 strips
rem surrounding quotes and never re-parses. `shift` does not affect %*, which is
rem still forwarded intact to the probes below.
:scanArgs
if "%~1"=="" goto :scanArgsDone
rem --install is still accepted so existing muscle memory keeps working; it is
rem now a no-op, since fetching is the default.
if "%~1"=="--no-install" set AUTO_INSTALL=0
shift
goto :scanArgs
:scanArgsDone

set RESTORE_FAILED=0
if not exist "%SDK_ASSETS%" if "%AUTO_INSTALL%"=="1" if !SDK_MAJOR! GEQ 8 (
  echo [csharp sdk-probe] restoring Camunda.Orchestration.Sdk via 'dotnet restore --locked-mode' against the committed packages.lock.json ^(first run only, cached after^)... 1>&2
  call "%DOTNET%" restore "%DIR%SdkProbe\SdkProbe.csproj" --locked-mode 1>&2
  if not !ERRORLEVEL!==0 set RESTORE_FAILED=1
)

if !SDK_MAJOR! LSS 8 (
  rem SDK_MAJOR is a bare integer, so interpolating it into the JSON is safe --
  rem unlike a path, which must never appear here with backslashes (see below).
  echo {"runtime":"csharp","trustStoreExercised":"","target":"sdk","verdict":"SKIP","errorClass":"OK","detail":"the installed .NET SDK (major version !SDK_MAJOR!) is too old to build this check, which targets net8.0 -- an SDK can only build its own framework version or an older one. The mandatory native trust check is unaffected and its result above still stands. Install .NET 8 or newer, or point --dotnet-bin at a newer SDK already on this machine."}
) else if "!RESTORE_FAILED!"=="1" (
  rem RESTORE_FAILED is tested BEFORE the assets file, deliberately: a restore
  rem that fails partway still writes obj/project.assets.json, so treating that
  rem file as proof of success passes a known-broken state to the build step and
  rem turns a clean, explainable SKIP into an opaque failure.
  rem
  rem Forward slashes in the path here, NOT backslashes: a literal backslash
  rem sequence in the JSON is invalid ("\l" is not a valid JSON escape), the
  rem exact pre-existing Windows JSON-escaping bug already found and fixed
  rem in Java's run.cmd -- avoided here from the start.
  echo {"runtime":"csharp","trustStoreExercised":"","target":"sdk","verdict":"SKIP","errorClass":"OK","detail":"Camunda.Orchestration.Sdk auto-install failed (dotnet restore --locked-mode) -- see stderr above; this is often a corporate NuGet mirror/proxy blocking nuget.org, or a lock-file hash mismatch. Manual install: dotnet restore layer2/csharp/SdkProbe/SdkProbe.csproj --locked-mode"}
) else if exist "%SDK_ASSETS%" (
  call "%DOTNET%" build "%DIR%SdkProbe\SdkProbe.csproj" -c Release -o "%DIR%SdkProbe\out" --nologo -v quiet 1>&2
  if !ERRORLEVEL!==0 (
    call "%DOTNET%" "%DIR%SdkProbe\out\SdkProbe.dll" %*
    if not !ERRORLEVEL!==0 set RC=1
  ) else (
    echo dotnet build of SdkProbe.csproj failed 1>&2
    echo {"runtime":"csharp","trustStoreExercised":"","target":"sdk","verdict":"SKIP","errorClass":"OK","detail":"the SDK check could not be built even though its packages resolved -- see the dotnet build output on stderr. On a restricted network this is usually a targeting pack the SDK still needs from nuget.org. The mandatory native trust check above is unaffected and its result stands."}
  )
) else (
  echo {"runtime":"csharp","trustStoreExercised":"","target":"sdk","verdict":"SKIP","errorClass":"OK","detail":"Camunda.Orchestration.Sdk not resolved, so the real .NET SDK was not exercised. Restore it manually with: dotnet restore layer2/csharp/SdkProbe/SdkProbe.csproj --locked-mode. If you passed --no-sdk-install, or set CAMUNDA_SDK_AUTO_INSTALL=0, re-run without it to fetch it automatically."}
)

exit /b %RC%
