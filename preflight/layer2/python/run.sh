#!/bin/sh
# Layer 2 Python probe entrypoint (invoked by the launcher; also runnable
# standalone by hand for manual or security review without needing the
# launcher).
#
# Runs BOTH probes and concatenates their fragments on stdout -- the launcher
# reads every newline-delimited fragment from stdout as its own probe
# result: probe.py (mandatory, SDK-free trust check) and probe_sdk.py
# (tier 2, the real SDK confirmation -- SKIPs cleanly if the SDK isn't
# installed and auto-install isn't enabled). Runs the second even if the
# first reports a FAIL, and vice versa -- each is an independent check.
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"

if command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v python >/dev/null 2>&1; then
  PY=python
else
  echo "python3/python not found on PATH" >&2
  exit 1
fi

rc=0
"$PY" "$DIR/probe.py" "$@" || rc=1
"$PY" "$DIR/probe_sdk.py" "$@" || rc=1
exit "$rc"
