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

rem Which JDK installation this probe uses for EVERY javac/java call below. A
rem trust store belongs to an INSTALLATION -- Java reads the cacerts of whichever
rem JDK ran -- so on a machine with several JDKs, checking the wrong one produces
rem a green result that says nothing about the JDK the exercises actually run on.
rem CAMUNDA_JAVA_HOME is how the launcher forwards an explicit pin (--java-home).
rem
rem A pin is NEVER quietly replaced by a PATH lookup: falling back would check a
rem different installation, and a different trust store, than the one asked for --
rem exactly the confusion pinning exists to remove. So an unusable pin fails
rem loudly and names the path it tried.
rem
rem Unset behaves exactly as before: plain PATH lookup. Deliberately NOT
rem consulting an ambient JAVA_HOME -- the launcher already detects a
rem JAVA_HOME-vs-PATH mismatch and warns about it.
rem
rem !JAVAC! / !JAVA!, not %JAVAC% / %JAVA%, at every use site below: they are
rem assigned inside a parenthesized block here, and %VAR% inside a block is
rem expanded when the block is PARSED, i.e. before this ran.
rem
rem The failure paths `goto` a label and exit at TOP level rather than running
rem `exit /b 1` inline. That is not style: with two sibling `if ... ( exit /b 1 )`
rem blocks inside one outer block, cmd runs the echo and stops the script but
rem hands back exit code 0 -- verified on this cmd.exe -- so the launcher would
rem read a broken pin as success. Do not "simplify" these back inline.
set "JAVAC=javac"
set "JAVA=java"
if not "%CAMUNDA_JAVA_HOME%"=="" (
  set "JAVAC=%CAMUNDA_JAVA_HOME%\bin\javac.exe"
  set "JAVA=%CAMUNDA_JAVA_HOME%\bin\java.exe"
  rem Existence is the only check available here -- Windows has no executable bit.
  if not exist "!JAVAC!" goto :pinNoJavac
  if not exist "!JAVA!" goto :pinNoJava
) else (
  where javac >nul 2>nul
  if not !ERRORLEVEL!==0 goto :noJdkOnPath
)
goto :jdkResolved

:pinNoJavac
echo CAMUNDA_JAVA_HOME is set, but no javac.exe was found at !JAVAC! -- refusing to fall back to the PATH JDK, which would check a different installation and a different trust store than the one requested 1>&2
exit /b 1

:pinNoJava
echo CAMUNDA_JAVA_HOME is set, but no java.exe was found at !JAVA! -- refusing to fall back to the PATH JDK, which would check a different installation and a different trust store than the one requested 1>&2
exit /b 1

:noJdkOnPath
echo java/javac not found on PATH -- a JDK is required ^(17+ recommended, matching the real Camunda Java SDK^) 1>&2
exit /b 1

:jdkResolved

rem Minimum JDK the probe sources compile on: Probe.java calls
rem ByteArrayOutputStream.toString(Charset), added in Java 10. Below the floor,
rem javac would spray a raw "method not applicable" dump at the operator instead
rem of an answer, so say so on the JSON channel and stop. SKIP, not FAIL: a
rem too-old JDK is a machine-setup fact, and the fix may be as small as pointing
rem the check at a newer JDK that is already installed.
rem
rem `javac -version` (NOT --version -- only JDK 9+ accepts the double-dash form)
rem prints either "javac 21.0.8" or, on JDK 8, "javac 1.8.0_401", where a leading
rem 1.x means major x; hence delims=._ and the "is token 1 a literal 1" test. JDK
rem 8 prints it on stderr, so 2>&1 is required to capture it at all. A banner
rem matching neither shape is left alone rather than guessed at: gating on a
rem version that could not be read would block a JDK that is very likely fine.
set "MIN_JDK=10"
set "JDK_VER="
set "JDK_MAJOR="
for /f "usebackq tokens=2" %%V in (`"!JAVAC!" -version 2^>^&1`) do if not defined JDK_VER set "JDK_VER=%%V"
if defined JDK_VER (
  for /f "tokens=1,2 delims=._" %%A in ("!JDK_VER!") do (
    if "%%A"=="1" (set "JDK_MAJOR=%%B") else (set "JDK_MAJOR=%%A")
  )
)
if defined JDK_MAJOR (
  rem findstr guard: LSS compares numerically only when both sides are numbers,
  rem so a non-numeric major must not reach it.
  echo !JDK_MAJOR!|findstr /r /c:"^[0-9][0-9]*$" >nul
  if !ERRORLEVEL!==0 if !JDK_MAJOR! LSS %MIN_JDK% (
    rem No filesystem path and no parentheses in this JSON: a Windows path
    rem carries literal backslashes, which are invalid JSON escapes and make the
    rem launcher drop the whole fragment, and an unescaped '(' / ')' breaks echo
    rem inside a parenthesized block. The version substituted in is
    rem digits/dots/underscores only, by construction of the parse above.
    echo {"runtime":"java","trustStoreExercised":"","target":"jdk-version","verdict":"SKIP","errorClass":"OK","detail":"the JDK this check would use is too old: javac reports version !JDK_VER!, but Java !MIN_JDK! or newer is required to compile the probes, so nothing was checked. Install a newer JDK -- 17 or later matches the real Camunda Java SDK -- or point the check at a newer one already on this machine with --java-home"}
    exit /b 0
  )
)

if not exist "%OUT%" mkdir "%OUT%"
set RC=0

rem --- Tier 1: native trust probe (mandatory, no dependency) ---
"!JAVAC!" -encoding UTF-8 -d "%OUT%" "%DIR%Probe.java" "%DIR%Shared.java"
if %ERRORLEVEL%==0 (
  rem -Dstdout.encoding=UTF-8 / -Dstderr.encoding=UTF-8: without these, Windows'
  rem default platform charset mangles non-ASCII bytes (an em-dash in a
  rem remediation message became a replacement character).
  "!JAVA!" -Dstdout.encoding=UTF-8 -Dstderr.encoding=UTF-8 -cp "%OUT%" Probe %*
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
  "!JAVAC!" -encoding UTF-8 -cp "%SDK_LIB%\*" -d "%OUT%" "%DIR%SdkProbe.java" "%DIR%Shared.java"
  if !ERRORLEVEL!==0 (
    "!JAVA!" -Dstdout.encoding=UTF-8 -Dstderr.encoding=UTF-8 -cp "%OUT%;%SDK_LIB%\*" SdkProbe %*
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
"!JAVAC!" -encoding UTF-8 -d "%OUT%" "%DIR%DepCheck.java" "%DIR%Shared.java"
if !ERRORLEVEL!==0 (
  "!JAVA!" -Dstdout.encoding=UTF-8 -Dstderr.encoding=UTF-8 -cp "%OUT%" DepCheck %*
  if not !ERRORLEVEL!==0 set RC=1
) else (
  echo javac compile of DepCheck.java failed 1>&2
)

exit /b %RC%
