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

where dotnet >nul 2>nul
if not %ERRORLEVEL%==0 (
  echo dotnet not found on PATH -- the .NET SDK is required ^(8.0+ recommended, matching the real Camunda C# SDK's target framework; this probe itself targets net9.0 -- see Probe.csproj's comment^) 1>&2
  exit /b 1
)

set RC=0

rem --- Tier 1: native trust probe (mandatory, zero NuGet dependencies) ---
dotnet build "%DIR%Probe\Probe.csproj" -c Release -o "%DIR%Probe\out" --nologo -v quiet 1>&2
if %ERRORLEVEL%==0 (
  dotnet "%DIR%Probe\out\Probe.dll" %*
  if not !ERRORLEVEL!==0 set RC=1
) else (
  echo dotnet build of Probe.csproj failed 1>&2
  set RC=1
)

rem --- Tier 2: real SDK confirmation (optional -- needs the
rem Camunda.Orchestration.Sdk NuGet package restored; opt-in fetch, same
rem reasoning as every other language's auto-install). ---
set "SDK_ASSETS=%DIR%SdkProbe\obj\project.assets.json"

set AUTO_INSTALL=0
if "%CAMUNDA_SDK_AUTO_INSTALL%"=="1" set AUTO_INSTALL=1
if "%CAMUNDA_SDK_AUTO_INSTALL%"=="true" set AUTO_INSTALL=1
for %%A in (%*) do (
  if "%%A"=="--install" set AUTO_INSTALL=1
)

set RESTORE_FAILED=0
if not exist "%SDK_ASSETS%" if "%AUTO_INSTALL%"=="1" (
  echo [csharp sdk-probe] restoring Camunda.Orchestration.Sdk via 'dotnet restore --locked-mode' against the committed packages.lock.json ^(first run only, cached after^)... 1>&2
  dotnet restore "%DIR%SdkProbe\SdkProbe.csproj" --locked-mode 1>&2
  if not !ERRORLEVEL!==0 set RESTORE_FAILED=1
)

if exist "%SDK_ASSETS%" (
  dotnet build "%DIR%SdkProbe\SdkProbe.csproj" -c Release -o "%DIR%SdkProbe\out" --nologo -v quiet 1>&2
  if !ERRORLEVEL!==0 (
    dotnet "%DIR%SdkProbe\out\SdkProbe.dll" %*
    if not !ERRORLEVEL!==0 set RC=1
  ) else (
    echo dotnet build of SdkProbe.csproj failed 1>&2
    set RC=1
  )
) else if "!RESTORE_FAILED!"=="1" (
  rem Forward slashes in the path here, NOT backslashes: a literal backslash
  rem sequence in the JSON is invalid ("\l" is not a valid JSON escape), the
  rem exact pre-existing Windows JSON-escaping bug already found and fixed
  rem in Java's run.cmd -- avoided here from the start.
  echo {"runtime":"csharp","trustStoreExercised":"","target":"sdk","verdict":"SKIP","errorClass":"OK","detail":"Camunda.Orchestration.Sdk auto-install failed (dotnet restore --locked-mode) -- see stderr above; this is often a corporate NuGet mirror/proxy blocking nuget.org, or a lock-file hash mismatch. Manual install: dotnet restore preflight/layer2/csharp/SdkProbe/SdkProbe.csproj --locked-mode"}
) else (
  echo {"runtime":"csharp","trustStoreExercised":"","target":"sdk","verdict":"SKIP","errorClass":"OK","detail":"Camunda.Orchestration.Sdk not resolved -- run: dotnet restore preflight/layer2/csharp/SdkProbe/SdkProbe.csproj --locked-mode, or set CAMUNDA_SDK_AUTO_INSTALL=1 (or pass --install) to fetch it automatically next run"}
)

exit /b %RC%
