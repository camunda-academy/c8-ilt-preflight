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

# Minimum Python this probe pair actually needs -- read off the sources, not
# guessed: probe.py catches ssl.SSLCertVerificationError and probe_sdk.py calls
# subprocess.run() with capture_output=/text=, and all three of those arrived in
# 3.7. On anything older the probes die with an AttributeError/TypeError
# traceback instead of producing a result, so the floor is reported as a SKIP
# fragment below rather than left to crash in the operator's face.
PY_MIN="3.7"
PY_MIN_MAJOR=3
PY_MIN_MINOR=7

# Echoes the version a candidate reports; fails when the candidate is missing,
# not executable, or does not answer as Python at all.
#
# Existing on disk is not the same as being the interpreter: Windows ships an
# App Execution Alias stub named python3 that is not Python (it exits non-zero
# pointing at the Microsoft Store) while the official installer only creates
# python -- so a bare "is python3 on PATH" test picks the stub on a stock
# Windows box and every probe below then fails. A candidate only counts once it
# has identified itself, the same rule the launcher applies on its own side.
python_version() {
  _out=$("$1" --version 2>&1) || return 1
  _ver=$(printf '%s\n' "$_out" | sed -n 's/^[Pp]ython[[:space:]][[:space:]]*\([0-9][0-9.]*\).*/\1/p' | head -n 1)
  [ -n "$_ver" ] || return 1
  printf '%s\n' "$_ver"
}

PY=""
PY_VERSION=""
if [ -n "${CAMUNDA_PYTHON_BIN:-}" ]; then
  # Pinned by the operator (--python-bin, or this env var set directly). Use it
  # for EVERY invocation below, and never fall back to PATH: a trust store
  # belongs to an installation, so falling back would check a different
  # interpreter -- with its own certifi CA bundle -- than the one that was asked
  # for, which is the exact failure mode pinning exists to remove.
  if PY_VERSION=$(python_version "$CAMUNDA_PYTHON_BIN"); then
    PY="$CAMUNDA_PYTHON_BIN"
  else
    echo "CAMUNDA_PYTHON_BIN is set to: $CAMUNDA_PYTHON_BIN" >&2
    echo "That is not a usable Python interpreter -- it is missing, not executable, or it does not answer to --version." >&2
    echo "Refusing to fall back to the python on PATH: that is a different installation with its own certificate" >&2
    echo "bundle, so the result would not describe the interpreter you pinned. Fix the path, or unset it to use PATH." >&2
    exit 1
  fi
else
  _rejected=""
  for _cand in python3 python; do
    command -v "$_cand" >/dev/null 2>&1 || continue
    if PY_VERSION=$(python_version "$_cand"); then
      PY="$_cand"
      break
    fi
    _rejected="${_rejected}${_rejected:+, }$_cand"
  done
  if [ -z "$PY" ]; then
    if [ -n "$_rejected" ]; then
      echo "python3/python not found on PATH -- $_rejected exists but does not answer as a working Python (on Windows a python3 of this kind is usually the Microsoft Store placeholder, not Python). Pass --python-bin, or set CAMUNDA_PYTHON_BIN, to point at a real interpreter." >&2
    else
      echo "python3/python not found on PATH" >&2
    fi
    exit 1
  fi
fi

PY_MAJOR=${PY_VERSION%%.*}
_rest=${PY_VERSION#*.}
PY_MINOR=${_rest%%.*}
if [ "$PY_MAJOR" -lt "$PY_MIN_MAJOR" ] || { [ "$PY_MAJOR" -eq "$PY_MIN_MAJOR" ] && [ "$PY_MINOR" -lt "$PY_MIN_MINOR" ]; }; then
  # SKIP, not FAIL: this is a machine-setup fact, not a network finding, and the
  # fix may be as small as pointing at a newer interpreter already installed.
  # Only the two version numbers are interpolated (plain digits and dots) -- the
  # interpreter PATH is deliberately never put in a fragment, since a Windows
  # path's backslashes are invalid JSON escapes and the launcher would drop the
  # whole line.
  echo "{\"runtime\":\"python\",\"trustStoreExercised\":\"\",\"target\":\"runtime-version\",\"verdict\":\"SKIP\",\"errorClass\":\"OK\",\"detail\":\"Python $PY_VERSION is too old for this check, which needs Python $PY_MIN or newer. Nothing about your network was tested here. Install a newer Python, or point this check at one you already have with --python-bin / CAMUNDA_PYTHON_BIN.\"}"
  exit 0
fi

rc=0
"$PY" "$DIR/probe.py" "$@" || rc=1
"$PY" "$DIR/probe_sdk.py" "$@" || rc=1
exit "$rc"
