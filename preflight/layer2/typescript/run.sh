#!/bin/sh
# Layer 2 TypeScript/Node.js probe entrypoint (invoked by the launcher; also
# runnable standalone by hand -- some corporate EDR/AV tooling blocks or flags
# unsigned/unfamiliar binaries, so being able to run this as a plain shell
# script plus the system node binary, with no compiled artifact of its own,
# is a deliberate fallback).
#
# Runs BOTH tiers and concatenates their fragments on stdout (the launcher
# reads every newline-delimited fragment on stdout, regardless of which probe
# emitted it): probe.js (mandatory, SDK-free native trust check -- zero
# dependencies, needs only the `node` binary itself) and probe_sdk.js (tier 2,
# the real @camunda8/orchestration-cluster-api confirmation -- SKIPs cleanly
# if the SDK isn't installed and auto-install isn't opted in). Runs the
# second even if the first reports a FAIL, and vice versa.
#
# Unlike Java (which needs a separate javac compile step and a Maven-fetched
# classpath dance before its tier 2 can even run), Node needs neither: both
# tiers are plain, already-runnable JS, and probe_sdk.js resolves/installs its
# own dependency via ordinary node_modules lookup rooted at this directory --
# see probe_sdk.js's own module doc comment for the install mechanics.
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"

if ! command -v node >/dev/null 2>&1; then
  echo "node not found on PATH -- Node.js is required (22+ recommended, matching the real Camunda TypeScript SDK's package.json engines field)" >&2
  exit 1
fi

rc=0

# --- Tier 1: native trust probe (mandatory, zero dependencies) ---
node "$DIR/probe.js" "$@" || rc=1

# --- Tier 2: real SDK confirmation (optional -- probe_sdk.js handles its own
# opt-in `npm ci` against the committed, hash-verified lockfile; see its
# module doc comment for the auto-install/SKIP mechanics). ---
node "$DIR/probe_sdk.js" "$@" || rc=1

exit "$rc"
