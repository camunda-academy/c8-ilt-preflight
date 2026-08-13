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

# Minimum Node for TIER 2 ONLY -- read off the sources, not guessed: the
# exact-pinned tier-2 SDK (@camunda8/orchestration-cluster-api 9.1.4 in
# package.json/package-lock.json) declares engines.node ">=22", npm's own
# install-time-enforced contract. Its lower sub-floors are Node 18 (the global
# `fetch` the SDK's HTTP client calls -- below it, tier 2 dies with a bare
# "fetch is not defined") and Node 20.18.1 (the pinned undici behind
# --ts-proxy-support).
#
# Tier 1 is deliberately NOT gated on this. It uses only `tls`/`net` -- no fetch,
# no undici, no AbortSignal.timeout, and no syntax newer than async/arrow
# functions -- so it runs on far older Node than the SDK needs. Gating it on 22
# as well would withhold a perfectly valid answer to "can this machine reach the
# cluster at all", and that answer is the one with the long lead time: upgrading
# Node is a local ten-minute job, whereas a firewall or proxy change is an IT
# request that can take weeks. Someone on Node 20 needs to learn about both
# problems in the same run, not discover the network one after upgrading.
NODE_MIN_MAJOR=22

# Echoes the version a candidate reports; fails when the candidate is missing,
# not executable, or does not answer as Node.js at all -- existing on disk is
# not the same as being the runtime, so a candidate only counts once it has
# identified itself (the same rule the launcher applies on its own side).
node_version() {
  _out=$("$1" --version 2>&1) || return 1
  _ver=$(printf '%s\n' "$_out" | sed -n 's/^v*\([0-9][0-9.]*\).*/\1/p' | head -n 1)
  [ -n "$_ver" ] || return 1
  printf '%s\n' "$_ver"
}

NODE=""
NODE_VERSION=""
if [ -n "${CAMUNDA_NODE_BIN:-}" ]; then
  # Pinned by the operator (--node-bin, or this env var set directly). Used for
  # EVERY invocation below, and never falling back to PATH: Node's CA set and
  # TLS stack vary between majors, so falling back would check a different
  # installation than the one that was asked for -- the exact failure mode
  # pinning exists to remove.
  if NODE_VERSION=$(node_version "$CAMUNDA_NODE_BIN"); then
    NODE="$CAMUNDA_NODE_BIN"
  else
    echo "CAMUNDA_NODE_BIN is set to: $CAMUNDA_NODE_BIN" >&2
    echo "That is not a usable node binary -- it is missing, not executable, or it does not answer to --version." >&2
    echo "Refusing to fall back to the node on PATH: a different Node installation has its own TLS stack and bundled" >&2
    echo "CA set, so the result would not describe the Node you pinned. Fix the path, or unset it to use PATH." >&2
    exit 1
  fi
else
  if ! command -v node >/dev/null 2>&1; then
    echo "node not found on PATH -- Node.js is required (22+ recommended, matching the real Camunda TypeScript SDK's package.json engines field)" >&2
    exit 1
  fi
  if ! NODE_VERSION=$(node_version node); then
    echo "node is on PATH but does not answer as a working Node.js runtime -- pass --node-bin, or set CAMUNDA_NODE_BIN, to point at a real one" >&2
    exit 1
  fi
  NODE=node
fi

NODE_MAJOR=${NODE_VERSION%%.*}
tier2_supported=1
if [ "$NODE_MAJOR" -lt "$NODE_MIN_MAJOR" ]; then
  tier2_supported=0
fi

# The npm-alongside-pinned-node handling exists purely for tier 2's optional
# install, so it is pointless work (and a misleading warning) when tier 2 isn't
# going to run at all.
if [ "$tier2_supported" = "1" ] && [ -n "${CAMUNDA_NODE_BIN:-}" ]; then
  # Tier 2's opt-in install shells out to `npm`, which is a SEPARATE executable
  # -- the pinned node binary cannot stand in for it. Keep the npm that BELONGS
  # to the pinned node (its sibling in the same directory) by putting that
  # directory first on PATH, so the install and the run that follows it can
  # never land on two different Node installations. If there is no sibling npm,
  # say so rather than quietly using whichever npm PATH happens to offer.
  NODE_DIR=$(dirname "$CAMUNDA_NODE_BIN")
  if command -v cygpath >/dev/null 2>&1; then
    # A Windows-form directory cannot go into a POSIX PATH -- its drive colon is
    # the list separator, which would split the entry in half.
    NODE_DIR=$(cygpath -u "$NODE_DIR")
  fi
  if [ -x "$NODE_DIR/npm" ] || [ -f "$NODE_DIR/npm.cmd" ]; then
    PATH="$NODE_DIR:$PATH"
    export PATH
  else
    echo "[typescript probe] no npm next to the pinned node in $NODE_DIR -- tier 2's optional install step would fall back to whichever npm is on PATH, which may belong to a different Node installation" >&2
    # The directory is named on stderr only, never inside the fragment: a
    # Windows path's backslashes are invalid JSON escapes and the launcher would
    # silently drop the whole line.
    echo '{"runtime":"typescript","trustStoreExercised":"","target":"npm","verdict":"WARN","errorClass":"CONFIG_ERROR","detail":"You pinned a node binary with --node-bin / CAMUNDA_NODE_BIN, but there is no npm next to it (see stderr for the directory). npm is a separate executable, so tier 2 optional install step would use whichever npm is on PATH -- possibly one belonging to a different Node installation, which would install for a runtime other than the one being checked here."}'
  fi
fi

rc=0

# --- Tier 1: native trust probe (mandatory, zero dependencies) ---
"$NODE" "$DIR/probe.js" "$@" || rc=1

# --- Tier 2: real SDK confirmation (optional -- probe_sdk.js handles its own
# opt-in `npm ci` against the committed, hash-verified lockfile; see its
# module doc comment for the auto-install/SKIP mechanics). ---
if [ "$tier2_supported" = "1" ]; then
  "$NODE" "$DIR/probe_sdk.js" "$@" || rc=1
else
  # SKIP, not FAIL: too old a Node is a machine-setup fact, not a network
  # finding, and the fix may be as small as pointing at a newer Node already
  # installed. Says explicitly that the trust check above still counts, so the
  # reader doesn't discard a result that is perfectly valid. Only version numbers
  # are interpolated (plain digits and dots) -- the node path is deliberately
  # never put in a fragment (its backslashes are invalid JSON escapes).
  echo "{\"runtime\":\"typescript\",\"trustStoreExercised\":\"\",\"target\":\"sdk\",\"verdict\":\"SKIP\",\"errorClass\":\"OK\",\"detail\":\"Node.js $NODE_VERSION is too old to run the SDK check, which needs Node.js $NODE_MIN_MAJOR or newer -- the version the pinned Camunda TypeScript SDK itself requires. The trust check above DID run on this Node and its result stands. To exercise the SDK too, install Node.js $NODE_MIN_MAJOR+, or point this check at one you already have with --node-bin / CAMUNDA_NODE_BIN.\"}"
fi

exit "$rc"
