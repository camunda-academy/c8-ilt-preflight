@echo off
rem Layer 2 Java probe entrypoint (invoked by the launcher; also runnable
rem standalone by hand, since corporate EDR/monitoring tools may flag the
rem launcher's automated process spawning and an operator may need to run
rem the probe directly instead).
rem
rem Runs BOTH probes and concatenates their fragments on stdout: Probe.java
rem (mandatory, SDK-free trust check) and SdkProbe.java (tier 2, the real
rem vanilla camunda-client-java confirmation -- SKIPs cleanly if Maven/the
rem dependency isn't available). Runs the second even if the first FAILs.
setlocal enabledelayedexpansion
set "DIR=%~dp0"
set "OUT=%DIR%out"

where javac >nul 2>nul
if not %ERRORLEVEL%==0 (
  echo java/javac not found on PATH -- a JDK is required ^(17+ recommended, matching the real Camunda Java SDK^) 1>&2
  exit /b 1
)

if not exist "%OUT%" mkdir "%OUT%"
set RC=0

rem --- Tier 1: native trust probe (mandatory, no dependency) ---
javac -encoding UTF-8 -d "%OUT%" "%DIR%Probe.java" "%DIR%Shared.java"
if %ERRORLEVEL%==0 (
  rem -Dstdout.encoding=UTF-8 / -Dstderr.encoding=UTF-8: without these, Windows'
  rem default platform charset mangles non-ASCII bytes (an em-dash in a
  rem remediation message became a replacement character).
  java -Dstdout.encoding=UTF-8 -Dstderr.encoding=UTF-8 -cp "%OUT%" Probe %*
  if not !ERRORLEVEL!==0 set RC=1
) else (
  echo javac compile of Probe.java failed 1>&2
  set RC=1
)

rem --- Tier 2: real SDK confirmation (optional -- needs Maven to fetch
rem camunda-client-java; opt-in fetch, same reasoning as the Python probe's
rem pip auto-install). Jars are COPIED into sdk\lib\ once and reused, and the
rem classpath is a single "lib\*" wildcard the JVM expands itself.
rem
rem Why copy-dependencies + a wildcard, NOT dependency:build-classpath + a
rem classpath string: the resolved classpath is ~6000
rem chars, and `set /p CP=<file` here silently TRUNCATES it to ~1021 chars,
rem dropping jars deep in the list (slf4j-api among them) and crashing the
rem real client with NoClassDefFoundError: org/slf4j/LoggerFactory. A "lib\*"
rem wildcard is JVM-expanded, has no length limit, and needs no separator
rem handling. ---
set "SDK_DIR=%DIR%sdk"
set "SDK_LIB=%SDK_DIR%\lib"

set AUTO_INSTALL=0
if "%CAMUNDA_SDK_AUTO_INSTALL%"=="1" set AUTO_INSTALL=1
if "%CAMUNDA_SDK_AUTO_INSTALL%"=="true" set AUTO_INSTALL=1
for %%A in (%*) do (
  if "%%A"=="--install" set AUTO_INSTALL=1
)

rem MVN_FAILED distinguishes "Maven ran but resolution FAILED" (a real finding --
rem almost always a broken/misconfigured corporate mirror or a proxy blocking
rem Central) from "Maven wasn't run at all" (absent / not opted in). Collapsing
rem both into the same SKIP made a broken mirror emit "install Maven and set the
rem flag" -- advice the operator had already followed -- and hid a hard training
rem blocker behind a benign-looking SKIP.
set MVN_FAILED=0
if not exist "%SDK_LIB%\*.jar" if "%AUTO_INSTALL%"=="1" (
  where mvn >nul 2>nul
  if !ERRORLEVEL!==0 (
    if not exist "%SDK_LIB%" mkdir "%SDK_LIB%"
    (
      echo ^<project xmlns="http://maven.apache.org/POM/4.0.0"^>
      echo   ^<modelVersion^>4.0.0^</modelVersion^>
      echo   ^<groupId^>local^</groupId^>^<artifactId^>probe^</artifactId^>^<version^>1.0^</version^>
      echo   ^<dependencies^>
      echo     ^<dependency^>
      echo       ^<groupId^>io.camunda^</groupId^>^<artifactId^>camunda-client-java^</artifactId^>^<version^>8.9.11^</version^>
      echo     ^</dependency^>
      echo   ^</dependencies^>
      echo ^</project^>
    ) > "%SDK_DIR%\pom.xml"
    echo [java sdk-probe] resolving io.camunda:camunda-client-java:8.9.11 via Maven ^(first run only, cached after^)... 1>&2
    pushd "%SDK_DIR%"
    call mvn -q -B dependency:copy-dependencies -DoutputDirectory=lib 1>&2
    if not !ERRORLEVEL!==0 set MVN_FAILED=1
    popd
  )
)

if exist "%SDK_LIB%\*.jar" (
  javac -encoding UTF-8 -cp "%SDK_LIB%\*" -d "%OUT%" "%DIR%SdkProbe.java" "%DIR%Shared.java"
  if !ERRORLEVEL!==0 (
    java -Dstdout.encoding=UTF-8 -Dstderr.encoding=UTF-8 -cp "%OUT%;%SDK_LIB%\*" SdkProbe %*
    if not !ERRORLEVEL!==0 set RC=1
  ) else (
    echo javac compile of SdkProbe.java failed against resolved classpath 1>&2
    set RC=1
  )
) else if "!MVN_FAILED!"=="1" (
  rem Maven WAS run and FAILED to resolve -- accurate remediation points at the
  rem mirror/network, NOT "install Maven". WARN, not FAIL: this optional SDK tier
  rem can't isolate mirror-down vs 401 vs artifact-missing vs Central-blocked --
  rem the dedicated Maven dependency-resolution check does that, so defer to it.
  rem No parentheses in the detail string: unescaped '(' / ')' break echo inside
  rem a batch parenthesized block.
  echo {"runtime":"java","trustStoreExercised":"","target":"maven-dependency-resolution","verdict":"WARN","errorClass":"MAVEN_RESOLVE_FAIL","detail":"Maven is installed and ran but could NOT resolve io.camunda:camunda-client-java:8.9.11 -- this is NOT a missing-Maven problem. Likely a corporate Maven mirror such as Nexus or Artifactory that cannot serve the Camunda artifacts -- missing, stale, or 401 -- or a proxy blocking Maven Central. This blocks building the training exercises regardless of cluster connectivity. See the mvn output on stderr above; run the dedicated Maven dependency-resolution check to isolate Central vs mirror."}
) else (
  rem Static, safe JSON -- SKIP, not FAIL: Maven was not run (absent, or
  rem auto-install not opted in), nothing to report yet. The mandatory native
  rem probe above already covers the trust check.
  rem Forward slashes in the path here, NOT backslashes: a literal "sdk\lib\" in
  rem the JSON is invalid ('\l' is not a valid JSON escape), so encoding/json in
  rem the launcher silently drops the whole fragment and this guidance never
  rem reaches the user on Windows (a pre-existing bug).
  echo {"runtime":"java","trustStoreExercised":"","target":"sdk","verdict":"SKIP","errorClass":"OK","detail":"camunda-client-java not resolved -- install Maven and set CAMUNDA_SDK_AUTO_INSTALL=1 (or pass --install) to fetch it automatically, or drop the SDK jars into sdk/lib/ yourself"}
)

rem --- Tier 3: Maven dependency-resolution probe. Stdlib only,
rem compiled on its own -- kept separate from tier 1 so a DepCheck compile issue
rem can never take down the MANDATORY trust probe. Self-gates: emits SKIP unless
rem opted in (--maven-depcheck / CAMUNDA_MAVEN_DEPCHECK / any --maven-* setting),
rem and only then shells out to Maven. ---
javac -encoding UTF-8 -d "%OUT%" "%DIR%DepCheck.java" "%DIR%Shared.java"
if !ERRORLEVEL!==0 (
  java -Dstdout.encoding=UTF-8 -Dstderr.encoding=UTF-8 -cp "%OUT%" DepCheck %*
  if not !ERRORLEVEL!==0 set RC=1
) else (
  echo javac compile of DepCheck.java failed 1>&2
)

exit /b %RC%
