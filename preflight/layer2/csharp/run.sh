#!/bin/sh
# Layer 2 C#/.NET probe entrypoint (invoked by the launcher; also runnable
# standalone by hand).
#
# Runs BOTH tiers and concatenates their fragments on stdout (the launcher
# reads every newline-delimited fragment): the native trust probe
# (mandatory, zero NuGet dependencies -- System.Net.Sockets/Security only)
# and the real Camunda.Orchestration.Sdk
# confirmation (tier 2 -- SKIPs cleanly if the package isn't restored and
# auto-install isn't opted in). Runs the second even if the first FAILs.
#
# Like Java (which needs an explicit javac compile step before it can run),
# C# needs an explicit `dotnet build` before `dotnet <dll>` -- unlike Python/
# Node's run-directly model. Each tier is rebuilt every invocation (no attempt
# at incremental-build caching beyond what `dotnet build` already does
# itself), the same "just rebuild every run" precedent Java's run.sh
# established (`javac` on every invocation, no caching).
#
# IMPORTANT: `dotnet build`'s own restore/compile progress messages are
# redirected to stderr (1>&2) below -- this probe's stdout is a
# machine-parsed, newline-delimited JSON channel (the contract requires one
# JSON object on stdout, nothing else), and `dotnet build` prints its own
# "Determining projects to restore..."/"X -> Y.dll" lines to stdout by
# default, which would otherwise corrupt that channel on every run (worse
# than Java's javac, which is silent on success). Only the final `dotnet
# <tier>.dll` invocation's stdout is left unredirected.
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"

# Which dotnet to use. CAMUNDA_DOTNET_BIN (set by the launcher from --dotnet-bin)
# pins a specific installation; a pin that doesn't work is a hard error rather
# than a fall back to PATH, because checking a different installation than the
# one that was asked for -- and reporting it as if it were the same -- is the
# confusion the pin exists to remove.
DOTNET="${CAMUNDA_DOTNET_BIN:-}"
if [ -n "$DOTNET" ]; then
  if ! "$DOTNET" --version >/dev/null 2>&1; then
    echo "the .NET SDK selected explicitly ($DOTNET) is missing or does not run; not falling back to PATH, because that would check a different installation than the one requested" >&2
    exit 1
  fi
else
  if ! command -v dotnet >/dev/null 2>&1; then
    echo "dotnet not found on PATH -- the .NET SDK is required (8.0+)" >&2
    exit 1
  fi
  DOTNET=dotnet
fi

# The SDK must be new enough to BUILD the tier-2 project, which is fixed at
# net8.0 to keep its lockfile valid: an older SDK cannot target a newer
# framework at all. Checked up front so this surfaces as a plain SKIP naming the
# version found, instead of an MSBuild error about an unknown target framework.
# Tier 1 is unaffected -- it derives its target from whatever SDK is present.
sdk_version="$("$DOTNET" --version 2>/dev/null)"
sdk_major="${sdk_version%%.*}"
case "$sdk_major" in
  ''|*[!0-9]*) sdk_major=0 ;;
esac

rc=0

# --- Tier 1: native trust probe (mandatory, zero NuGet dependencies) ---
if "$DOTNET" build "$DIR/Probe/Probe.csproj" -c Release -o "$DIR/Probe/out" --nologo -v quiet 1>&2; then
  "$DOTNET" "$DIR/Probe/out/Probe.dll" "$@" || rc=1
else
  # Emit a fragment, not just stderr. This tier is mandatory, so a build failure
  # here means the trust check never ran -- and reporting that only on stderr is
  # how it came to be invisible: the launcher would see the OTHER tier's clean
  # SKIP, find nothing failing, and print "All checks passed" for a stack whose
  # actual check never executed. No path goes in the JSON (backslashes are
  # invalid escapes); the build output is on stderr for the detail.
  echo "dotnet build of Probe.csproj failed" >&2
  echo '{"runtime":"csharp","trustStoreExercised":"","target":"trust","verdict":"FAIL","errorClass":"PROBE_CRASHED","detail":"the C# trust check could not be built, so it never ran -- see the dotnet build output on stderr. On a restricted network this is usually NuGet being unreachable while the SDK tries to fetch a targeting pack for a .NET version it does not ship with."}'
  rc=1
fi

# --- Tier 2: real SDK confirmation (optional -- needs the
# Camunda.Orchestration.Sdk NuGet package restored; opt-in fetch, same
# reasoning as every other language's auto-install: an automated preflight run
# on a broken network shouldn't silently spend time fetching a dependency in
# exactly the scenario it exists to catch). Restored packages are cached under
# SdkProbe/obj + the shared NuGet cache (~/.nuget/packages), reused on repeat
# runs, mirroring Java's "resolve once, cache after" Maven precedent. ---
auto_install=0
if [ "${CAMUNDA_SDK_AUTO_INSTALL:-}" = "1" ] || [ "${CAMUNDA_SDK_AUTO_INSTALL:-}" = "true" ]; then
  auto_install=1
fi
for a in "$@"; do
  [ "$a" = "--install" ] && auto_install=1
done

SDK_ASSETS="$DIR/SdkProbe/obj/project.assets.json"
restore_failed=0
if [ ! -f "$SDK_ASSETS" ] && [ "$auto_install" = "1" ] && [ "$sdk_major" -ge 8 ]; then
  echo "[csharp sdk-probe] restoring Camunda.Orchestration.Sdk via 'dotnet restore --locked-mode' against the committed packages.lock.json (first run only, cached after)..." >&2
  if ! "$DOTNET" restore "$DIR/SdkProbe/SdkProbe.csproj" --locked-mode 1>&2; then
    restore_failed=1
  fi
fi

if [ "$sdk_major" -lt 8 ]; then
  echo '{"runtime":"csharp","trustStoreExercised":"","target":"sdk","verdict":"SKIP","errorClass":"OK","detail":"the installed .NET SDK (major version '"$sdk_major"') is too old to build this check, which targets net8.0 -- an SDK can only build its own framework version or an older one. The mandatory native trust check is unaffected and its result above still stands. Install .NET 8 or newer, or point --dotnet-bin at a newer SDK already on this machine."}'
# restore_failed is tested BEFORE the assets file, deliberately: a restore that
# fails partway still writes obj/project.assets.json, so treating that file as
# proof of success sends a known-broken state on to the build step and turns a
# clean, explainable SKIP into an opaque failure.
elif [ "$restore_failed" = "1" ]; then
  # Maven-style distinction: "restore was attempted and FAILED" (often a
  # corporate NuGet mirror/proxy blocking nuget.org, or a
  # lock-file hash mismatch) is a real, distinct finding from "never
  # attempted" -- but mirrors the SIMPLER Python/TypeScript precedent of
  # collapsing both into a single SKIP verdict (differing only in detail
  # text), since unlike Java's dedicated Maven depcheck sub-probe, there is
  # no separate NuGet-mirror-isolation probe here to defer to.
  echo '{"runtime":"csharp","trustStoreExercised":"","target":"sdk","verdict":"SKIP","errorClass":"OK","detail":"Camunda.Orchestration.Sdk auto-install failed (dotnet restore --locked-mode) -- see stderr above; this is often a corporate NuGet mirror/proxy blocking nuget.org, or a lock-file hash mismatch. Manual install: dotnet restore layer2/csharp/SdkProbe/SdkProbe.csproj --locked-mode"}'
elif [ -f "$SDK_ASSETS" ]; then
  if "$DOTNET" build "$DIR/SdkProbe/SdkProbe.csproj" -c Release -o "$DIR/SdkProbe/out" --nologo -v quiet 1>&2; then
    "$DOTNET" "$DIR/SdkProbe/out/SdkProbe.dll" "$@" || rc=1
  else
    # A fragment rather than stderr alone: this tier's build can fail even after
    # a restore that looked fine (a targeting pack the SDK has to fetch
    # separately, for instance), and without a fragment the whole stack could
    # come out of the launcher with nothing to explain itself.
    echo "dotnet build of SdkProbe.csproj failed" >&2
    echo '{"runtime":"csharp","trustStoreExercised":"","target":"sdk","verdict":"SKIP","errorClass":"OK","detail":"the SDK check could not be built even though its packages resolved -- see the dotnet build output on stderr. On a restricted network this is usually a targeting pack the SDK still needs from nuget.org. The mandatory native trust check above is unaffected and its result stands."}'
  fi
else
  echo '{"runtime":"csharp","trustStoreExercised":"","target":"sdk","verdict":"SKIP","errorClass":"OK","detail":"Camunda.Orchestration.Sdk not resolved -- run: dotnet restore layer2/csharp/SdkProbe/SdkProbe.csproj --locked-mode, or set CAMUNDA_SDK_AUTO_INSTALL=1 (or pass --install) to fetch it automatically next run"}'
fi

exit "$rc"
