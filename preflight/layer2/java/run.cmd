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
rem Unset means a plain PATH lookup. Deliberately NOT
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
rem hands back exit code 0, so the launcher would read a broken pin as success.
rem Do not "simplify" these back inline.
set "JAVAC=javac"
set "JAVA=java"
rem `if defined`, not `if not "%VAR%"==""`: the quoted-comparison form expands
rem the value before tokenization, so a crafted value can close the quote and
rem inject commands ahead of the existence check below. `if defined` never
rem substitutes the value at all.
if defined CAMUNDA_JAVA_HOME (
  rem !VAR! (delayed), never %VAR%: %VAR% inside a parenthesized block is
  rem substituted when the block is PARSED, before any of it runs, so a value
  rem containing " or & is parsed as command syntax instead of as data.
  set "JAVAC=!CAMUNDA_JAVA_HOME!\bin\javac.exe"
  set "JAVA=!CAMUNDA_JAVA_HOME!\bin\java.exe"
  rem Existence is the only check available here -- Windows has no executable bit.
  if not exist "!JAVAC!" goto :pinNoJavac
  if not exist "!JAVA!" goto :pinNoJava
) else (
  where javac >nul 2>nul
  if not !ERRORLEVEL!==0 goto :noJdkOnPath
)
goto :jdkResolved

rem The labels below report a missing JDK as a FAIL fragment on stdout with
rem errorClass RUNTIME_ABSENT -- the same verdict and class the launcher uses
rem for a runtime that was asked for but is not installed -- not as a bare
rem stderr line, which the launcher can only surface as a crashed probe. Exit 0
rem after it, like the too-old-JDK SKIP below: the fragment is the result. A JRE
rem is the common case: `java` works, so the launcher detects Java and runs this
rem script, but without javac nothing here can be compiled.
rem
rem No filesystem path in these JSON lines: a Windows path carries literal
rem backslashes, which are invalid JSON escapes and make the launcher drop the
rem whole fragment. The path goes to stderr instead.
:pinNoJavac
echo CAMUNDA_JAVA_HOME is set, but no javac.exe was found at !JAVAC! -- refusing to fall back to the PATH JDK, which would check a different installation and a different trust store than the one requested 1>&2
if exist "!JAVA!" (
  echo {"runtime":"java","trustStoreExercised":"","target":"jdk","verdict":"FAIL","errorClass":"RUNTIME_ABSENT","detail":"the Java installation selected with --java-home is a Java runtime, JRE, without a JDK: it has no javac, so the probes cannot be compiled and nothing was checked. Point --java-home at a JDK -- 17 or later recommended; the Camunda Spring Boot Starter requires 17. The path that was tried is on stderr."}
) else (
  echo {"runtime":"java","trustStoreExercised":"","target":"jdk","verdict":"FAIL","errorClass":"RUNTIME_ABSENT","detail":"the Java installation selected with --java-home has neither javac nor java, so nothing was checked. Point --java-home at the folder of a JDK -- the one that contains bin -- 17 or later recommended; the Camunda Spring Boot Starter requires 17. The path that was tried is on stderr."}
)
exit /b 0

:pinNoJava
echo CAMUNDA_JAVA_HOME is set, but no java.exe was found at !JAVA! -- refusing to fall back to the PATH JDK, which would check a different installation and a different trust store than the one requested 1>&2
echo {"runtime":"java","trustStoreExercised":"","target":"jdk","verdict":"FAIL","errorClass":"RUNTIME_ABSENT","detail":"the Java installation selected with --java-home has javac but no java launcher, so nothing was checked. Point --java-home at a complete JDK -- 17 or later recommended; the Camunda Spring Boot Starter requires 17. The path that was tried is on stderr."}
exit /b 0

:noJdkOnPath
rem `java -version` must actually answer, not just exist: only then is this a
rem usable JRE rather than a leftover launcher stub.
where java >nul 2>nul
if not !ERRORLEVEL!==0 goto :noJavaOnPath
java -version >nul 2>nul
if not !ERRORLEVEL!==0 goto :noJavaOnPath
rem The JRE's version, for the detail. Only the line whose second token is
rem "version" counts -- a JAVA_TOOL_OPTIONS banner can come first -- and only a
rem value made of digits, dots and underscores is used, so nothing else can
rem reach the JSON below.
set "JRE_VER="
for /f "usebackq tokens=2,3" %%A in (`java -version 2^>^&1`) do if "%%A"=="version" if not defined JRE_VER set "JRE_VER=%%~B"
set "JRE_DESC="
if defined JRE_VER (
  echo !JRE_VER!|findstr /r /c:"^[0-9][0-9._]*$" >nul
  if !ERRORLEVEL!==0 set "JRE_DESC=, version !JRE_VER!,"
)
echo java found on PATH but no javac -- this is a Java runtime, JRE, not a JDK 1>&2
echo {"runtime":"java","trustStoreExercised":"","target":"jdk","verdict":"FAIL","errorClass":"RUNTIME_ABSENT","detail":"a Java runtime, JRE!JRE_DESC! was found on PATH, but no JDK: javac is missing, so the probes cannot be compiled and nothing was checked. Install a JDK -- 17 or later recommended; the Camunda Spring Boot Starter requires 17 -- or point the check at one already on this machine with --java-home."}
exit /b 0

:noJavaOnPath
echo java/javac not found on PATH 1>&2
echo {"runtime":"java","trustStoreExercised":"","target":"jdk","verdict":"FAIL","errorClass":"RUNTIME_ABSENT","detail":"no Java found: neither javac nor a working java is on PATH, so nothing was checked. Install a JDK -- 17 or later recommended; the Camunda Spring Boot Starter requires 17 -- or point the check at one already on this machine with --java-home."}
exit /b 0

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
    echo {"runtime":"java","trustStoreExercised":"","target":"jdk-version","verdict":"SKIP","errorClass":"OK","detail":"the JDK this check would use is too old: javac reports version !JDK_VER!, but Java !MIN_JDK! or newer is required to compile the probes, so nothing was checked. Install a newer JDK -- 17 or later recommended; the Camunda Spring Boot Starter requires 17 -- or point the check at a newer one already on this machine with --java-home"}
    exit /b 0
  )
)

if not exist "%OUT%" mkdir "%OUT%"
set RC=0

rem --- Tier 1: native trust probe (mandatory, no dependency) ---
"!JAVAC!" -encoding UTF-8 -d "%OUT%" "%DIR%Probe.java" "%DIR%Shared.java"
if %ERRORLEVEL%==0 (
  rem -Dstdout.encoding=UTF-8 / -Dstderr.encoding=UTF-8: without these, Windows'
  rem default platform charset mangles non-ASCII bytes, so any em-dash or
  rem accented character in a remediation message arrives as a replacement
  rem character.
  "!JAVA!" -Dstdout.encoding=UTF-8 -Dstderr.encoding=UTF-8 -cp "%OUT%" Probe %*
  if not !ERRORLEVEL!==0 set RC=1
) else (
  echo javac compile of Probe.java failed 1>&2
  set RC=1
)

rem --- DepCheck.java (stdlib only) is compiled here, ahead of tier 2, because
rem tier 2's SDK fetch runs through it: `DepCheck --fetch-sdk` hands Maven the
rem proxy and the trust store, which means writing a settings.xml with the proxy
rem password in it and building a keystore. Both happen in Java, not here: a
rem proxy password may contain & % ! " or <, and no amount of escaping makes
rem echoing such a value into XML from batch safe. Compiled on its own, after
rem tier 1, so a DepCheck compile issue can never take down the MANDATORY trust
rem probe. ---
set DEPCHECK_OK=0
"!JAVAC!" -encoding UTF-8 -d "%OUT%" "%DIR%DepCheck.java" "%DIR%Shared.java"
if !ERRORLEVEL!==0 (
  set DEPCHECK_OK=1
) else (
  echo javac compile of DepCheck.java failed 1>&2
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

rem MVN_FAILED distinguishes "Maven ran but resolution FAILED" (almost always a
rem broken/misconfigured corporate mirror or a proxy blocking Central) from
rem "Maven wasn't run at all" (absent / not opted in). Collapsing both into the
rem same SKIP would make a broken mirror emit "install Maven and set the flag"
rem -- advice the operator has already followed -- and hide a hard training
rem blocker behind a benign-looking SKIP. MVN_FAILED=2 means the same, but
rem `DepCheck --fetch-sdk` has already emitted the fragment saying so -- with
rem the actual first error, and the proxy retry's outcome -- so nothing is
rem added here.
rem
rem The fetch itself runs through DepCheck --fetch-sdk whenever DepCheck
rem compiled: it tries the operator's own Maven settings first, as before, and
rem when that fails and a proxy is configured, retries once with Maven Central
rem plus that proxy -- Maven reads neither --proxy nor HTTPS_PROXY. It also
rem hands Maven the --trust-ca / --java-truststore trust store. The plain mvn
rem call is the fallback for a DepCheck that did not compile.
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
      echo       ^<groupId^>io.camunda^</groupId^>^<artifactId^>camunda-client-java^</artifactId^>^<version^>8.9.15^</version^>
      echo     ^</dependency^>
      echo   ^</dependencies^>
      echo ^</project^>
    ) > "%SDK_DIR%\pom.xml"
    echo [java sdk-probe] resolving io.camunda:camunda-client-java:8.9.15 via Maven ^(first run only, cached after^)... 1>&2
    if "!DEPCHECK_OK!"=="1" (
      "!JAVA!" -Dstdout.encoding=UTF-8 -Dstderr.encoding=UTF-8 -cp "%OUT%" DepCheck --fetch-sdk "%SDK_DIR%"
      set "FETCH_RC=!ERRORLEVEL!"
      if "!FETCH_RC!"=="2" (
        set MVN_FAILED=2
      ) else if not "!FETCH_RC!"=="0" (
        set MVN_FAILED=1
      )
    ) else (
      pushd "%SDK_DIR%"
      call mvn -q -B dependency:copy-dependencies -DoutputDirectory=lib 1>&2
      if not !ERRORLEVEL!==0 set MVN_FAILED=1
      popd
    )
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
) else if "!MVN_FAILED!"=="2" (
  rem Already reported by DepCheck --fetch-sdk -- see MVN_FAILED above.
  set MVN_FAILED=2
) else if "!MVN_FAILED!"=="1" (
  rem Maven WAS run and FAILED to resolve -- accurate remediation points at the
  rem mirror/network, NOT "install Maven". WARN, not FAIL: this optional SDK tier
  rem can't isolate mirror-down vs 401 vs artifact-missing vs Central-blocked --
  rem the dedicated Maven dependency-resolution check does that, so defer to it.
  rem No parentheses in the detail string: unescaped '(' / ')' break echo inside
  rem a batch parenthesized block.
  echo {"runtime":"java","trustStoreExercised":"","target":"maven-dependency-resolution","verdict":"WARN","errorClass":"MAVEN_RESOLVE_FAIL","detail":"Maven is installed and ran but could NOT resolve io.camunda:camunda-client-java:8.9.15 -- this is NOT a missing-Maven problem. Likely a corporate Maven mirror such as Nexus or Artifactory that cannot serve the Camunda artifacts -- missing, stale, or 401 -- or a proxy blocking Maven Central. This blocks building the training exercises regardless of cluster connectivity. See the mvn output on stderr above; run the dedicated Maven dependency-resolution check to isolate Central vs mirror."}
) else (
  rem Static, safe JSON -- SKIP, not FAIL: Maven was not run (absent, or
  rem auto-install not opted in), nothing to report yet. The mandatory native
  rem probe above already covers the trust check.
  rem Forward slashes in the path here, NOT backslashes: a literal "sdk\lib\" in
  rem the JSON is invalid ('\l' is not a valid JSON escape), so encoding/json in
  rem the launcher silently drops the whole fragment and this guidance never
  rem reaches the user on Windows.
  echo {"runtime":"java","trustStoreExercised":"","target":"sdk","verdict":"SKIP","errorClass":"OK","detail":"camunda-client-java not resolved, so the real Java SDK was not exercised. The automatic fetch needs Maven on PATH -- install Maven and re-run, or drop the SDK jars into sdk/lib/ yourself. If you passed --no-sdk-install, or set CAMUNDA_SDK_AUTO_INSTALL=0, re-run without it to fetch the SDK automatically."}
)

rem --- Tier 3: Maven dependency-resolution probe. Stdlib only, compiled
rem above, before tier 2. Self-gates: emits SKIP unless opted in
rem (--maven-depcheck / CAMUNDA_MAVEN_DEPCHECK / any --maven-* setting), and
rem only then shells out to Maven. A failed compile was already reported
rem above. ---
if "!DEPCHECK_OK!"=="1" (
  "!JAVA!" -Dstdout.encoding=UTF-8 -Dstderr.encoding=UTF-8 -cp "%OUT%" DepCheck %*
  if not !ERRORLEVEL!==0 set RC=1
)

exit /b %RC%
