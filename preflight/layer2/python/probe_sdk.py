#!/usr/bin/env python3
"""Layer 2 SDK-snippet confirmation — Python (tier 2).

Standalone: python3 preflight/layer2/python/probe_sdk.py
Requires the real Camunda Python SDK (camunda-orchestration-sdk) — this is
the "literal SDK connects + gets topology" real confirmation, catching
proxy-handling/config issues the SDK-free native probe (probe.py) can't.
probe.py's trust check is still the mandatory tier; this is the recommended,
richer confirmation once the SDK is present.

The SDK reads its config from the SAME env vars the Go binary and probe.py
use: CAMUNDA_REST_ADDRESS/CAMUNDA_REGION, CAMUNDA_CLIENT_ID/SECRET,
CAMUNDA_MTLS_CA_PATH. No extra wiring needed.

Auto-install (off by default — a corporate-proxy/no-internet environment is
exactly the case this whole tool exists to catch, and silently spending 60s+
on a pip install during every automated preflight run would be bad UX in
precisely that scenario):
  CAMUNDA_SDK_AUTO_INSTALL=1   or   --install   installs the pinned SDK
  version (camunda-orchestration-sdk >=9,<10) if it isn't already present,
  then proceeds. If installation
  isn't enabled/fails, this emits a SKIP fragment with the manual install
  command — the native probe's fragments (from probe.py) still cover the
  mandatory trust check either way.

Trust-store nuance verified against the SDK's own source (not assumed):
httpx (the SDK's HTTP client) defaults verify=True, which internally builds
ssl.create_default_context(cafile=certifi.where()) — i.e. certifi, same as
probe.py. BUT once CAMUNDA_MTLS_CA_PATH is set, the SDK's own
build_ssl_context() (camunda_orchestration_sdk/runtime/tls.py) switches the
base store to ssl.create_default_context() (the OS/system store) plus the
custom CA — a DIFFERENT base trust store than the no-custom-CA case. This
probe reports which one applies rather than assuming "always certifi."
"""
import contextlib
import subprocess
import sys

from _shared import (
    classify_transport_error,
    crash_fragment,
    eprint,
    fragment,
    is_verbose,
    normalize_rest_base,
    resolve_is_full,
    silence_stdlib_logging,
)

# Exact version pin: a range like ">=9,<10" would let auto-install silently
# pull a FUTURE compromised 9.x release; pin the exact version we verified.
# Bump deliberately per Camunda release.
SDK_VERSION = "9.0.1"
SDK_SPEC = "camunda-orchestration-sdk==%s" % SDK_VERSION
# Optional operator-supplied hash-locked requirements file next to this probe.
# When present, install with --require-hashes so pip refuses any artifact whose
# hash doesn't match — the real defense against dependency-confusion / mirror
# poisoning (an attacker publishing camunda-orchestration-sdk==9.0.1 to an
# internal index pip happens to prefer). Not shipped by default because a
# cross-platform hash lock (pydantic-core etc. have per-OS binary wheels) must
# be generated per environment (e.g. `pip-compile --generate-hashes`) rather
# than committed once and assumed portable.
LOCK_FILENAME = "requirements.lock"
INSTALL_TIMEOUT_SECONDS = 90


def auto_install_enabled():
    import os

    if "--install" in sys.argv[1:]:
        return True
    return os.environ.get("CAMUNDA_SDK_AUTO_INSTALL", "").strip().lower() in ("1", "true", "yes")


def try_import_sdk():
    # Redirect stdout to stderr during import: the SDK or one of its transitive
    # deps could print() at import time, and this
    # probe's stdout is a line-delimited JSON channel the launcher parses — a
    # stray banner there would corrupt fragment parsing. Anything printed still
    # reaches the operator, just on stderr.
    try:
        with contextlib.redirect_stdout(sys.stderr):
            import camunda_orchestration_sdk as sdk_mod
            from camunda_orchestration_sdk import errors as sdk_errors

        return sdk_mod, sdk_errors, None
    except ImportError as e:
        return None, None, str(e)


def _lock_path():
    import os

    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), LOCK_FILENAME)
    return p if os.path.isfile(p) else None


def install_sdk():
    """Attempt to pip-install the exact-pinned SDK. Returns an error string, or
    None on success. Retries once with --user for the common locked-down-machine
    case (no write access to the global site-packages).

    Security: if a hash-locked requirements file sits next to this probe,
    install from it with --require-hashes (pip refuses any artifact whose
    hash doesn't match — this defeats dependency-confusion). Otherwise install
    the exact-pinned version and WARN loudly that the install is version-pinned
    but NOT hash-verified and uses whatever package index pip is configured for
    (PIP_INDEX_URL / pip.conf / an internal mirror), so on an untrusted network
    the operator should pre-install the SDK from a trusted source instead of
    using auto-install. --no-cache-dir avoids reusing a poisoned local cache.
    """
    lock = _lock_path()
    if lock:
        install_args = ["--require-hashes", "-r", lock]
        eprint("[python sdk-probe] installing from hash-locked %s" % LOCK_FILENAME)
    else:
        install_args = [SDK_SPEC]
        eprint("[python sdk-probe] SECURITY: installing %s from pip's configured index — version-pinned but NOT" % SDK_SPEC)
        eprint("[python sdk-probe] hash-verified. On an untrusted network, pre-install the SDK from a trusted source")
        eprint("[python sdk-probe] instead, or drop a hash-locked %s next to this probe." % LOCK_FILENAME)

    last_detail = "pip install did not complete"
    for extra_args in ([], ["--user"]):
        cmd = [sys.executable, "-m", "pip", "install", "--quiet", "--no-cache-dir", *extra_args, *install_args]
        eprint("[python sdk-probe] installing (%s)..." % ("user" if extra_args else "default"))
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=INSTALL_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            last_detail = "pip install timed out after %ds" % INSTALL_TIMEOUT_SECONDS
            continue  # try the --user variant before giving up
        except Exception as e:
            return "could not invoke pip: %s" % e
        if result.returncode == 0:
            return None
        tail = (result.stderr or result.stdout or "").strip()
        last_detail = tail[-400:] if len(tail) > 400 else tail
    return "pip install failed (tried default and --user): %s" % last_detail


def trust_store_label():
    # Kept short and plain-language deliberately -- this ends up in the
    # customer-facing result (Notes/FAIL details), not just an engineering
    # log.
    import os

    custom_ca = os.environ.get("CAMUNDA_MTLS_CA_PATH", "").strip()
    if custom_ca:
        return "the default certificate bundle plus your custom certificate (%s)" % custom_ca
    return "the default certificate bundle"


def run_checks(sdk_mod, sdk_errors):
    import os

    store_label = trust_store_label()
    fragments = []

    # Normalize the REST base the same way the Go binary does. Critical:
    # the SDK does NOT tolerate the stray-":443" path segment in Camunda
    # Console's copy-paste CAMUNDA_REST_ADDRESS form —
    # it hits /:443/<clusterId>/v2/status and Cloudflare returns
    # "default backend - 404". Passing the canonical URL via `configuration`
    # makes the SDK probe test the same endpoint Layer 1 does, instead of a
    # false-red 404. When the raw form needed fixing we still WARN, because a
    # participant hand-configuring the SDK from that same Console string would
    # hit the identical opaque 404.
    rest_base, host, was_normalized = normalize_rest_base()
    # Emit the normalization notice only in verbose mode: it's useful to the
    # operator/trainer but confusing noise for a participant (the normalization
    # still happens silently either way, so the check is valid regardless).
    if was_normalized and is_verbose():
        fragments.append(fragment(
            "%s (config)" % host, "WARN", "CONFIG_ERROR",
            "your CAMUNDA_REST_ADDRESS is Camunda Console's copy-paste form (stray ':443' path segment). "
            "This preflight normalized it to %s so the check is valid -- BUT the Python SDK does NOT do this "
            "itself: pasting the raw Console string straight into your SDK config yields a "
            "'default backend - 404'. Use the canonical form %s in participant SDK config." % (rest_base, rest_base)))

    # Mode decision must mirror the Go binary exactly: network mode is
    # credential-free and does status ONLY —
    # never an authenticated get_topology(), and never even acquires a token.
    # The launcher passes CAMUNDA_PREFLIGHT_MODE so the probe follows the same
    # decision the Go binary made; run standalone (env var unset), fall back to
    # creds-presence auto-detect, mirroring the Go binary's own default.
    has_creds = bool(os.environ.get("CAMUNDA_CLIENT_ID", "").strip() and os.environ.get("CAMUNDA_CLIENT_SECRET", "").strip())
    is_full = resolve_is_full(os.environ.get("CAMUNDA_PREFLIGHT_MODE", ""), has_creds)

    # Build the client config. In network mode force CAMUNDA_AUTH_STRATEGY=NONE
    # so the SDK acquires NO token and sends NO Authorization header even when
    # credentials happen to be in the environment — otherwise the SDK would
    # auto-infer OAUTH and authenticate a "credential-free" run (with
    # AUTH_STRATEGY=NONE, get_status sends no auth header and still succeeds). In full mode
    # leave auth to auto-infer OAUTH from the credentials.
    config = {"CAMUNDA_REST_ADDRESS": rest_base}
    if not is_full:
        config["CAMUNDA_AUTH_STRATEGY"] = "NONE"

    # NullLogger is required here, not just CAMUNDA_SDK_LOG_LEVEL=silent —
    # the SDK's own debug logger prints an unmasked "OAuth token request:
    # ... client_id=<value>" line to stderr on every authenticated call, and
    # setting CAMUNDA_SDK_LOG_LEVEL=silent does NOT suppress it (a real gap
    # in the SDK, worth reporting upstream). Only passing
    # logger=NullLogger() explicitly stops it.
    # Redaction requires this: never let a client ID reach stderr in the
    # clear, even though it isn't the client SECRET.
    client = sdk_mod.CamundaClient(configuration=config, logger=sdk_mod.NullLogger())

    # get_status() is the credential-free, network-mode analog — runs in BOTH
    # modes (full mode is a superset), matching the Go binary's status stage.
    target = "%s (sdk status)" % host
    try:
        client.get_status()
        fragments.append(fragment(target, "PASS", "OK", "SDK get_status() succeeded", store_label))
    except sdk_errors.ServiceUnavailableError as e:
        # FAIL, not WARN: blocks training right now (severity), even though
        # it's never the customer's fault (attribution -- see the Go
        # binary's IsOurClusterProblem/ExitOurClusterProblem).
        fragments.append(fragment(target, "FAIL", "CLUSTER_UNHEALTHY_503",
                                   "cluster reachable but unhealthy (503) — likely our shared preflight cluster, "
                                   "not your network: %s" % e, store_label))
    except sdk_errors.UnexpectedStatus as e:
        fragments.append(fragment(target, "FAIL", "UNEXPECTED_HTTP_STATUS", "unexpected HTTP status: %s" % e, store_label))
    except Exception as e:
        error_class, detail = classify_transport_error(e)
        fragments.append(fragment(target, "FAIL", error_class, detail, store_label))

    # get_topology() is the authenticated, FULL-MODE-ONLY analog. In network
    # mode emit NO fragment at all — matching the Go binary, which simply omits
    # its topology stage in network mode rather than printing a SKIP line.
    topology_target = "%s (sdk topology)" % host
    if not is_full:
        pass  # network mode: credential-free, topology omitted (no line), like Go
    elif not has_creds:
        fragments.append(fragment(topology_target, "SKIP", "OK",
                                   "full mode requested but CAMUNDA_CLIENT_ID/CAMUNDA_CLIENT_SECRET are not set — "
                                   "cannot run the authenticated get_topology() check"))
    else:
        try:
            topo = client.get_topology()
            broker_count = len(topo.brokers) if getattr(topo, "brokers", None) is not None else "?"
            fragments.append(fragment(topology_target, "PASS", "OK",
                                       "SDK get_topology() succeeded, %s broker(s)" % broker_count,
                                       store_label))
        except sdk_errors.UnauthorizedError as e:
            fragments.append(fragment(topology_target, "FAIL", "TOPOLOGY_AUTH_FAIL",
                                       "authenticated topology request rejected (401): %s" % e, store_label))
        except sdk_errors.UnexpectedStatus as e:
            fragments.append(fragment(topology_target, "FAIL", "UNEXPECTED_HTTP_STATUS", "unexpected HTTP status: %s" % e, store_label))
        except Exception as e:
            error_class, detail = classify_transport_error(e)
            fragments.append(fragment(topology_target, "FAIL", error_class, detail, store_label))

    try:
        client.close()
    except Exception:
        pass

    return fragments


def main():
    if any(a in ("-h", "--help") for a in sys.argv[1:]):
        eprint(__doc__)
        return 0

    # Defense-in-depth: silence stdlib logging BEFORE importing or using the
    # SDK, so no dependency can log a secret via a path NullLogger doesn't
    # cover.
    silence_stdlib_logging()

    sdk_mod, sdk_errors, import_err = try_import_sdk()

    if sdk_mod is None:
        if not auto_install_enabled():
            print(__import__("json").dumps(fragment(
                "sdk", "SKIP", "OK",
                "camunda-orchestration-sdk not installed (native trust probe in probe.py already covers the "
                "mandatory check) — install manually: pip install \"%s\", or set CAMUNDA_SDK_AUTO_INSTALL=1 "
                "(or pass --install) to install it automatically next run: %s" % (SDK_SPEC, import_err))))
            return 0

        install_err = install_sdk()
        if install_err:
            print(__import__("json").dumps(fragment(
                "sdk", "SKIP", "OK",
                "auto-install of the Camunda Python SDK failed — %s. Install manually: pip install \"%s\"" % (install_err, SDK_SPEC))))
            return 0

        sdk_mod, sdk_errors, import_err = try_import_sdk()
        if sdk_mod is None:
            print(__import__("json").dumps(fragment(
                "sdk", "SKIP", "OK",
                "pip reported a successful install but the SDK still failed to import: %s" % import_err)))
            return 0
        eprint("[python sdk-probe] installed %s" % SDK_SPEC)

    exit_code = 0
    import json

    for frag in run_checks(sdk_mod, sdk_errors):
        print(json.dumps(frag))
        sys.stdout.flush()
        if frag["verdict"] not in ("PASS", "WARN", "SKIP"):
            exit_code = 1
    return exit_code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        import json

        print(json.dumps(crash_fragment(e)))
        sys.exit(1)
