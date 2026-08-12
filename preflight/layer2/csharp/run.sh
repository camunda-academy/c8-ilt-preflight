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

if ! command -v dotnet >/dev/null 2>&1; then
  echo "dotnet not found on PATH -- the .NET SDK is required (8.0+ recommended, matching the real Camunda C# SDK's target framework; this probe itself targets net9.0 -- see Probe.csproj's comment)" >&2
  exit 1
fi

rc=0

# --- Tier 1: native trust probe (mandatory, zero NuGet dependencies) ---
if dotnet build "$DIR/Probe/Probe.csproj" -c Release -o "$DIR/Probe/out" --nologo -v quiet 1>&2; then
  dotnet "$DIR/Probe/out/Probe.dll" "$@" || rc=1
else
  echo "dotnet build of Probe.csproj failed" >&2
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
if [ ! -f "$SDK_ASSETS" ] && [ "$auto_install" = "1" ]; then
  echo "[csharp sdk-probe] restoring Camunda.Orchestration.Sdk via 'dotnet restore --locked-mode' against the committed packages.lock.json (first run only, cached after)..." >&2
  if ! dotnet restore "$DIR/SdkProbe/SdkProbe.csproj" --locked-mode 1>&2; then
    restore_failed=1
  fi
fi

if [ -f "$SDK_ASSETS" ]; then
  if dotnet build "$DIR/SdkProbe/SdkProbe.csproj" -c Release -o "$DIR/SdkProbe/out" --nologo -v quiet 1>&2; then
    dotnet "$DIR/SdkProbe/out/SdkProbe.dll" "$@" || rc=1
  else
    echo "dotnet build of SdkProbe.csproj failed" >&2
    rc=1
  fi
elif [ "$restore_failed" = "1" ]; then
  # Maven-style distinction: "restore was attempted and FAILED" (often a
  # corporate NuGet mirror/proxy blocking nuget.org, or a
  # lock-file hash mismatch) is a real, distinct finding from "never
  # attempted" -- but mirrors the SIMPLER Python/TypeScript precedent of
  # collapsing both into a single SKIP verdict (differing only in detail
  # text), since unlike Java's dedicated Maven depcheck sub-probe, there is
  # no separate NuGet-mirror-isolation probe here to defer to.
  echo '{"runtime":"csharp","trustStoreExercised":"","target":"sdk","verdict":"SKIP","errorClass":"OK","detail":"Camunda.Orchestration.Sdk auto-install failed (dotnet restore --locked-mode) -- see stderr above; this is often a corporate NuGet mirror/proxy blocking nuget.org, or a lock-file hash mismatch. Manual install: dotnet restore preflight/layer2/csharp/SdkProbe/SdkProbe.csproj --locked-mode"}'
else
  echo '{"runtime":"csharp","trustStoreExercised":"","target":"sdk","verdict":"SKIP","errorClass":"OK","detail":"Camunda.Orchestration.Sdk not resolved -- run: dotnet restore preflight/layer2/csharp/SdkProbe/SdkProbe.csproj --locked-mode, or set CAMUNDA_SDK_AUTO_INSTALL=1 (or pass --install) to fetch it automatically next run"}'
fi

exit "$rc"
