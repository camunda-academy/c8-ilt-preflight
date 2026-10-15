#!/bin/sh
# Layer 2 Java probe entrypoint (invoked by the launcher; also runnable
# standalone by hand, since corporate EDR/monitoring tools may flag the
# launcher's automated process spawning and an operator may need to run the
# probe directly instead).
#
# Runs BOTH probes and concatenates their fragments on stdout (the launcher
# reads every newline-delimited fragment): Probe.java (mandatory, SDK-free
# trust check, javax.net.ssl only) and SdkProbe.java (tier 2, the real vanilla camunda-client-java
# confirmation -- SKIPs cleanly if Maven/the dependency isn't available).
# Runs the second even if the first reports a FAIL, and vice versa.
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$DIR/out"

# Which JDK installation this probe uses for EVERY javac/java call below. A
# trust store belongs to an INSTALLATION -- Java reads the cacerts of whichever
# JDK ran -- so on a machine with several JDKs, checking the wrong one produces a
# green result that says nothing about the JDK the exercises actually run on.
# CAMUNDA_JAVA_HOME is how the launcher forwards an explicit pin (--java-home).
#
# A pin is NEVER quietly replaced by a PATH lookup: falling back would check a
# different installation, and a different trust store, than the one asked for --
# exactly the confusion pinning exists to remove. So an unusable pin fails loudly
# and names the path it tried.
#
# Unset means a plain PATH lookup. Deliberately NOT consulting
# an ambient JAVA_HOME -- the launcher already detects a JAVA_HOME-vs-PATH
# mismatch and warns about it, so honoring it here would duplicate that logic
# and silently override the runtime the launcher reported.
#
# A missing JDK is reported as a FAIL fragment on stdout with errorClass
# RUNTIME_ABSENT -- the same verdict and class the launcher uses for a runtime
# that was asked for but is not installed -- not as a bare stderr line, which
# the launcher can only surface as a crashed probe. Exit 0 after it, like the
# too-old-JDK SKIP below: the fragment is the result. A JRE is the common case:
# `java` works, so the launcher detects Java and runs this script, but without
# javac nothing here can be compiled. No filesystem path in these JSON lines
# (a path can carry quotes or backslashes, which would break the JSON); the
# path goes to stderr instead.
JDK_ADVICE="17 or later recommended; the Camunda Spring Boot Starter requires 17"
no_jdk_fragment() {
  echo "{\"runtime\":\"java\",\"trustStoreExercised\":\"\",\"target\":\"jdk\",\"verdict\":\"FAIL\",\"errorClass\":\"RUNTIME_ABSENT\",\"detail\":\"$1\"}"
}
if [ -n "${CAMUNDA_JAVA_HOME:-}" ]; then
  JAVAC="$CAMUNDA_JAVA_HOME/bin/javac"
  JAVA="$CAMUNDA_JAVA_HOME/bin/java"
  # -x also resolves a Windows javac.exe/java.exe when this script runs under
  # Git Bash/MSYS, so no separate .exe branch is needed.
  if [ ! -x "$JAVAC" ]; then
    echo "CAMUNDA_JAVA_HOME is set, but no runnable javac was found at $JAVAC -- refusing to fall back to the PATH JDK, which would check a different installation and a different trust store than the one requested" >&2
    if [ -x "$JAVA" ]; then
      no_jdk_fragment "the Java installation selected with --java-home is a Java runtime, JRE, without a JDK: it has no javac, so the probes cannot be compiled and nothing was checked. Point --java-home at a JDK -- $JDK_ADVICE. The path that was tried is on stderr."
    else
      no_jdk_fragment "the Java installation selected with --java-home has neither javac nor java, so nothing was checked. Point --java-home at the folder of a JDK -- the one that contains bin -- $JDK_ADVICE. The path that was tried is on stderr."
    fi
    exit 0
  fi
  if [ ! -x "$JAVA" ]; then
    echo "CAMUNDA_JAVA_HOME is set, but no runnable java was found at $JAVA -- refusing to fall back to the PATH JDK, which would check a different installation and a different trust store than the one requested" >&2
    no_jdk_fragment "the Java installation selected with --java-home has javac but no java launcher, so nothing was checked. Point --java-home at a complete JDK -- $JDK_ADVICE. The path that was tried is on stderr."
    exit 0
  fi
else
  JAVAC=javac
  JAVA=java
  # `-version` must actually answer, not just resolve: macOS ships
  # /usr/bin/java and /usr/bin/javac stubs that exist with no JDK installed and
  # only print an "unable to locate a Java Runtime" message.
  if ! command -v javac >/dev/null 2>&1 || ! javac -version >/dev/null 2>&1 \
      || ! command -v java >/dev/null 2>&1; then
    if command -v java >/dev/null 2>&1 && java -version >/dev/null 2>&1; then
      # Only the "... version "x.y.z"" line counts (a JAVA_TOOL_OPTIONS banner
      # can come first), and only digits/dots/underscores are captured, so
      # nothing else can reach the JSON.
      jre_ver="$(java -version 2>&1 | sed -n 's/^.* version "\([0-9][0-9._]*\)".*/\1/p' | head -n 1)"
      jre_desc=""
      [ -n "$jre_ver" ] && jre_desc=", version $jre_ver,"
      echo "java found on PATH but no javac -- this is a Java runtime (JRE), not a JDK" >&2
      no_jdk_fragment "a Java runtime, JRE$jre_desc was found on PATH, but no JDK: javac is missing, so the probes cannot be compiled and nothing was checked. Install a JDK -- $JDK_ADVICE -- or point the check at one already on this machine with --java-home."
    else
      echo "java/javac not found on PATH" >&2
      no_jdk_fragment "no Java found: neither javac nor a working java is on PATH, so nothing was checked. Install a JDK -- $JDK_ADVICE -- or point the check at one already on this machine with --java-home."
    fi
    exit 0
  fi
fi

# Minimum JDK the probe sources compile on: Probe.java calls
# ByteArrayOutputStream.toString(Charset), added in Java 10. Below the floor,
# javac would spray a raw "method not applicable" dump at the operator instead of
# an answer, so say so on the JSON channel and stop. SKIP, not FAIL: a too-old
# JDK is a machine-setup fact, and the fix may be as small as pointing the check
# at a newer JDK that is already installed.
#
# `javac -version` (NOT --version -- only JDK 9+ accepts the double-dash form)
# prints either "javac 21.0.8" or, on JDK 8, "javac 1.8.0_401", where a leading
# 1.x means major x. A banner that does not match either shape is left alone
# rather than guessed at: gating on a version that could not be read would block
# a JDK that is very likely fine.
MIN_JDK=10
jdk_ver="$("$JAVAC" -version 2>&1 | head -n 1)" || jdk_ver=""
jdk_ver="$(printf '%s' "$jdk_ver" | sed -n 's/^javac \([0-9][0-9._]*\).*/\1/p')"
case "$jdk_ver" in
  1.*) jdk_major="$(printf '%s' "$jdk_ver" | cut -d. -f2)" ;;
  *)   jdk_major="$(printf '%s' "$jdk_ver" | cut -d. -f1)" ;;
esac
case "$jdk_major" in ''|*[!0-9]*) jdk_major="" ;; esac
if [ -n "$jdk_major" ] && [ "$jdk_major" -lt "$MIN_JDK" ]; then
  # No filesystem path in this JSON: a Windows-style path carries literal
  # backslashes, which are invalid JSON escapes and make the launcher drop the
  # whole fragment. The version substituted in is digits/dots/underscores only,
  # by construction of the sed match above.
  echo "{\"runtime\":\"java\",\"trustStoreExercised\":\"\",\"target\":\"jdk-version\",\"verdict\":\"SKIP\",\"errorClass\":\"OK\",\"detail\":\"the JDK this check would use is too old: javac reports version $jdk_ver, but Java $MIN_JDK or newer is required to compile the probes, so nothing was checked. Install a newer JDK -- 17 or later recommended; the Camunda Spring Boot Starter requires 17 -- or point the check at a newer one already on this machine with --java-home\"}"
  exit 0
fi

mkdir -p "$OUT"
rc=0

# --- Tier 1: native trust probe (mandatory, no dependency) ---
if "$JAVAC" -encoding UTF-8 -d "$OUT" "$DIR/Probe.java" "$DIR/Shared.java" 2>&1; then
  # -Dstdout.encoding=UTF-8 / -Dstderr.encoding=UTF-8: without these, Windows'
  # default platform charset mangles non-ASCII bytes (an em-dash in a
  # remediation message became a replacement character).
  "$JAVA" -Dstdout.encoding=UTF-8 -Dstderr.encoding=UTF-8 -cp "$OUT" Probe "$@" || rc=1
else
  echo "javac compile of Probe.java failed" >&2
  rc=1
fi

# --- DepCheck.java (stdlib only) is compiled here, ahead of tier 2, because
# tier 2's SDK fetch runs through it: `DepCheck --fetch-sdk` hands Maven the
# proxy and the trust store, which means writing a settings.xml with the proxy
# password in it and building a keystore. Both happen in Java, not here, so a
# password containing quotes, & or < can never be misread as markup or shell
# syntax. Compiled on its own, after tier 1, so a DepCheck compile issue can
# never take down the MANDATORY trust probe. ---
depcheck_ok=0
if "$JAVAC" -encoding UTF-8 -d "$OUT" "$DIR/DepCheck.java" "$DIR/Shared.java" 2>&1; then
  depcheck_ok=1
else
  echo "javac compile of DepCheck.java failed" >&2
fi

# --- Tier 2: real SDK confirmation (optional -- needs Maven to fetch
# camunda-client-java; opt-in fetch, same reasoning as the Python probe's
# pip auto-install: an automated preflight run on a broken network shouldn't
# silently spend time fetching a dependency in exactly the scenario it
# exists to catch). Jars are COPIED into sdk/lib/ once and reused, and the
# classpath is a single "lib/*" wildcard the JVM expands itself.
#
# Why copy-dependencies + a wildcard, NOT dependency:build-classpath + a
# classpath string: the resolved classpath is ~6000
# chars, and Windows `set /p CP=<file` in run.cmd silently TRUNCATES it to
# ~1021 chars, dropping jars deep in the list (slf4j-api among them) and
# crashing the real client with NoClassDefFoundError: org/slf4j/LoggerFactory.
# A "lib/*" wildcard is expanded by the JVM, has no length limit, and needs
# no separator/mixed-path handling -- one clean directory path. ---
SDK_DIR="$DIR/sdk"
SDK_LIB="$SDK_DIR/lib"
SDK_SPEC="io.camunda:camunda-client-java:8.9.15"

# Fetching the pinned SDK is the DEFAULT, and opting out is explicit. A tier
# that silently SKIPs answers nothing about whether the real client reaches the
# cluster, which is the question this tier exists to settle -- and a SKIP sitting
# among PASS lines reads as "fine" to a participant scanning the output.
# Opt out with --no-install or CAMUNDA_SDK_AUTO_INSTALL=0 when writing into the
# machine's package cache is unwanted. --install is still accepted so existing
# muscle memory and scripts keep working; it is now a no-op.
auto_install=1
case "$(printf '%s' "${CAMUNDA_SDK_AUTO_INSTALL:-}" | tr '[:upper:]' '[:lower:]')" in
  0|false|no|off) auto_install=0 ;;
esac
for a in "$@"; do
  [ "$a" = "--no-install" ] && auto_install=0
done

libHasJars() { ls "$SDK_LIB"/*.jar >/dev/null 2>&1; }

# mvn_failed distinguishes "Maven ran but resolution FAILED" (a real finding --
# almost always a broken/misconfigured corporate mirror or a proxy blocking
# Central) from "Maven wasn't run at all" (absent / not opted in). Collapsing
# both into the same SKIP made a broken mirror emit "install Maven and set the
# flag" -- advice the operator had already followed -- and hid a hard training
# blocker behind a benign-looking SKIP. Do NOT `|| true` the
# mvn call: we need its exit status. mvn_failed=2 means the same, but
# `DepCheck --fetch-sdk` has already emitted the fragment saying so -- with the
# actual first error, and the proxy retry's outcome -- so nothing is added here.
#
# The fetch itself runs through DepCheck --fetch-sdk whenever DepCheck
# compiled: it tries the operator's own Maven settings first, and when that
# fails and a proxy is configured, retries once with Maven Central plus that
# proxy -- Maven reads neither --proxy nor HTTPS_PROXY. It also hands Maven the
# --trust-ca / --java-truststore trust store. The plain mvn call is the
# fallback for a DepCheck that did not compile.
mvn_failed=0
if ! libHasJars && [ "$auto_install" = "1" ] && command -v mvn >/dev/null 2>&1; then
  mkdir -p "$SDK_LIB"
  cat > "$SDK_DIR/pom.xml" <<POMEOF
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>local</groupId><artifactId>probe</artifactId><version>1.0</version>
  <dependencies>
    <dependency>
      <groupId>io.camunda</groupId><artifactId>camunda-client-java</artifactId><version>8.9.15</version>
    </dependency>
  </dependencies>
</project>
POMEOF
  echo "[java sdk-probe] resolving $SDK_SPEC via Maven (first run only, cached after)..." >&2
  if [ "$depcheck_ok" = "1" ]; then
    "$JAVA" -Dstdout.encoding=UTF-8 -Dstderr.encoding=UTF-8 -cp "$OUT" DepCheck --fetch-sdk "$SDK_DIR"
    case "$?" in
      0) ;;
      2) mvn_failed=2 ;;
      *) mvn_failed=1 ;;
    esac
  elif ! ( cd "$SDK_DIR" && mvn -q -B dependency:copy-dependencies -DoutputDirectory=lib ) >&2; then
    mvn_failed=1
  fi
fi

if libHasJars; then
  # One clean directory path per classpath entry (out dir + lib wildcard). On
  # Windows (java.exe, e.g. under Git Bash) both must be native paths joined
  # with ';'; elsewhere POSIX paths joined with ':'. cygpath present == the
  # java we invoke is Windows java.exe.
  if command -v cygpath >/dev/null 2>&1; then
    SEP=";"
    OUT_CP="$(cygpath -w "$OUT")"
    LIB_CP="$(cygpath -w "$SDK_LIB")\\*"
  else
    SEP=":"
    OUT_CP="$OUT"
    LIB_CP="$SDK_LIB/*"
  fi
  if "$JAVAC" -encoding UTF-8 -cp "$LIB_CP" -d "$OUT" "$DIR/SdkProbe.java" "$DIR/Shared.java" 2>&1; then
    "$JAVA" -Dstdout.encoding=UTF-8 -Dstderr.encoding=UTF-8 -cp "$OUT_CP$SEP$LIB_CP" SdkProbe "$@" || rc=1
  else
    echo "javac compile of SdkProbe.java failed against resolved classpath" >&2
    rc=1
  fi
elif [ "$mvn_failed" = "2" ]; then
  : # already reported by DepCheck --fetch-sdk -- see mvn_failed above
elif [ "$mvn_failed" = "1" ]; then
  # Maven WAS run and FAILED to resolve -- accurate remediation points at the
  # mirror/network, NOT "install Maven". WARN, not FAIL: this optional SDK tier
  # can't tell mirror-down from 401 from artifact-missing from Central-blocked
  # (the dedicated Maven dependency-resolution check does, via Central-vs-mirror
  # isolation) -- so it flags the finding and defers the authoritative
  # verdict, rather than asserting a cause it didn't isolate.
  echo '{"runtime":"java","trustStoreExercised":"","target":"maven-dependency-resolution","verdict":"WARN","errorClass":"MAVEN_RESOLVE_FAIL","detail":"Maven is installed and ran but could NOT resolve io.camunda:camunda-client-java:8.9.15 -- this is NOT a missing-Maven problem. Likely a corporate Maven mirror such as Nexus or Artifactory that cannot serve the Camunda artifacts -- missing, stale, or 401 -- or a proxy blocking Maven Central. This blocks building the training exercises regardless of cluster connectivity. See the mvn output on stderr above; run the dedicated Maven dependency-resolution check to isolate Central vs mirror."}'
else
  # Static, safe JSON (no untrusted content) -- SKIP, not FAIL: Maven was not
  # run (absent, or auto-install not opted in), so there is nothing to report
  # yet. The mandatory native probe above already covers the trust check.
  echo '{"runtime":"java","trustStoreExercised":"","target":"sdk","verdict":"SKIP","errorClass":"OK","detail":"camunda-client-java not resolved, so the real Java SDK was not exercised. The automatic fetch needs Maven on PATH -- install Maven and re-run, or drop the SDK jars into sdk/lib/ yourself. If you passed --no-sdk-install, or set CAMUNDA_SDK_AUTO_INSTALL=0, re-run without it to fetch the SDK automatically."}'
fi

# --- Tier 3: Maven dependency-resolution probe. Stdlib only (no
# Camunda SDK), compiled above, before tier 2. It self-gates: emits a SKIP
# fragment unless opted in (--maven-depcheck / CAMUNDA_MAVEN_DEPCHECK / any
# --maven-* setting), and only then shells out to Maven. Catches the
# corporate-mirror case the trust/SDK probes are blind to. A failed compile was
# already reported above. ---
if [ "$depcheck_ok" = "1" ]; then
  "$JAVA" -Dstdout.encoding=UTF-8 -Dstderr.encoding=UTF-8 -cp "$OUT" DepCheck "$@" || rc=1
fi

exit "$rc"
