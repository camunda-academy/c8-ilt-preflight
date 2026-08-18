"""Shared helpers for the Python Layer 2 probes (probe.py + probe_sdk.py).

Centralized so the two probes never carry two independently-drifting copies
of the same transport-error classification — the exact kind of divergence
this whole project exists to prevent by keeping one shared error-classification
vocabulary across every probe language. Both the raw-socket probe and the
SDK-based probe funnel their connection errors through
classify_transport_error() below.
"""
import os
import re
import sys
from urllib.parse import urlparse

RUNTIME = "python"

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)

# Matches inline URL credentials (scheme://user:pass@host) so they can be
# masked out of any text before it's emitted.
_URL_CREDS_RE = re.compile(r"(\w+://)[^/@\s:]+:[^/@\s]+@")


def scrub_url_creds(text):
    """Mask user:pass@ credentials in any URL embedded in text. Applied to
    every fragment detail before emission, so a proxy password carried in an
    httpx/socket exception string can never reach stdout in the clear."""
    if not text:
        return text
    return _URL_CREDS_RE.sub(r"\1****:****@", text)


def silence_stdlib_logging():
    """Defense-in-depth: suppress ALL Python stdlib logging in the probe
    process. The SDK's own NullLogger stops its own logger
    abstraction, but a transitive dependency (httpx/httpcore) — or a future SDK
    version — could log an unmasked client_id via the stdlib `logging` module,
    which NullLogger doesn't intercept. The probe reports through its own JSON
    (stdout) and eprint (stderr) channels and does not rely on stdlib logging,
    so nothing of value is lost by disabling it outright."""
    import logging

    logging.disable(logging.CRITICAL)


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def fragment(target, verdict, error_class, detail, store_label=""):
    # Scrub URL credentials from the detail as a universal backstop — every
    # emitted fragment funnels through here, so a proxy password embedded in an
    # exception string can't leak to stdout regardless of which code path
    # built the detail.
    return {
        "runtime": RUNTIME,
        "trustStoreExercised": store_label,
        "target": target,
        "verdict": verdict,
        "errorClass": error_class,
        "detail": scrub_url_creds(detail),
    }


def crash_fragment(detail):
    return fragment("", "probe-error", "PROBE_CRASHED", "probe crashed: %s" % detail)


def is_verbose():
    """Whether to surface extra diagnostic fragments hidden by default (e.g. the
    Console-URL normalization notice) — useful to the operator/trainer, but
    confusing noise for participants. Set by the launcher via
    CAMUNDA_PREFLIGHT_VERBOSE (from the Go binary's --verbose), or by passing
    --verbose when running the probe standalone."""
    if "--verbose" in sys.argv[1:]:
        return True
    return os.environ.get("CAMUNDA_PREFLIGHT_VERBOSE", "").strip().lower() in ("1", "true", "yes")


def resolve_is_full(mode, has_creds):
    """Mirror the Go binary's network-vs-full decision so probes never diverge
    from it: network mode must be credential-free — status only, no
    authenticated topology, no token. An explicit
    mode (passed by the launcher via CAMUNDA_PREFLIGHT_MODE) wins; when unset
    (probe run standalone by hand) fall back to creds-presence auto-detect,
    the same default the Go binary uses."""
    m = (mode or "").strip().lower()
    if m == "network":
        return False
    if m == "full":
        return True
    return has_creds


def get_proxy_url():
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        v = os.environ.get(name)
        if v:
            return v
    return None


def mask_proxy(proxy_url):
    if not proxy_url:
        return ""
    p = urlparse(proxy_url)
    if p.username:
        netloc = "****:****@%s" % p.hostname
        if p.port:
            netloc += ":%d" % p.port
        return p._replace(netloc=netloc).geturl()
    return proxy_url


def resolve_api_host():
    """Same config-source precedence as the Go binary:
    an explicit CAMUNDA_REST_ADDRESS host wins over CAMUNDA_REGION."""
    rest_address = os.environ.get("CAMUNDA_REST_ADDRESS", "").strip()
    region = os.environ.get("CAMUNDA_REGION", "").strip() or "bru-2"

    if rest_address:
        candidate = rest_address if "://" in rest_address else "https://" + rest_address
        hostname = urlparse(candidate).hostname
        if hostname:
            return hostname
    return "%s.api.camunda.io" % region


def cluster_edge_detail(status_code):
    """Detail text for CLUSTER_EDGE_404 -- the catch-all for a status the SDK
    reached the real cluster edge with but that isn't specifically handled
    (503 and 401 get their own classifications). Same wording as the Go
    binary's status.go and the Java/C# SDK probes, so the message reads
    identically regardless of which check produced it."""
    return (
        "reached the cluster edge (HTTP %d) but got no valid cluster route -- this typically means our shared "
        "preflight cluster is paused or in a transient edge blip, NOT a problem with your network. Re-run in "
        "~5 minutes; if it persists, contact the training team." % status_code
    )


def has_cluster_target():
    """Whether enough config exists to build a REST base with an actual
    cluster route -- CAMUNDA_REST_ADDRESS carries a UUID somewhere in its
    path, or CAMUNDA_CLUSTER_ID is one itself.

    Mirrors the Go binary's own hostset.Resolve validation. That check runs
    before the binary ever invokes a probe, so it normally catches a missing
    cluster id before any Layer 2 code executes at all -- but this file is
    also runnable standalone, which bypasses it. Without this, normalize_rest_base()
    below silently falls back to a bare https://<region>.api.camunda.io with no
    cluster path, and the SDK's resulting 404 reads as a transient cluster
    problem instead of a missing --cluster-id/--host.
    """
    raw = os.environ.get("CAMUNDA_REST_ADDRESS", "").strip()
    if raw:
        for seg in raw.split("/"):
            if _UUID_RE.match(seg):
                return True
    return bool(_UUID_RE.match(os.environ.get("CAMUNDA_CLUSTER_ID", "").strip()))


def normalize_rest_base():
    """Rebuild a canonical https://<host>/<clusterId> REST base, mirroring the
    Go binary's hostset.parseExplicitHost tolerance (UUID-anywhere-in-path +
    authority-port stripping).

    This exists because the Camunda Python SDK does NOT tolerate the exact
    string Camunda Console tells users to copy: Console's copy-paste form
    embeds a stray ':443' path segment
    (https://<host>/:443/<clusterId>/v2/). The Go binary strips it; the SDK
    appends '/v2' and passes the whole path to httpx, hitting
    /:443/<clusterId>/v2/status -> Cloudflare 'default backend - 404'.
    Passing this normalized value to the SDK via
    its `configuration` param makes the SDK probe test the same canonical
    endpoint every other check does, instead of a false-red 404.

    Returns (rest_base, host, was_normalized). was_normalized is True when the
    raw input carried stray path segments (the exact case a hand-configuring
    participant would trip over), so the caller can WARN about it.
    """
    raw = os.environ.get("CAMUNDA_REST_ADDRESS", "").strip()
    region = os.environ.get("CAMUNDA_REGION", "").strip() or "bru-2"
    cluster_id_env = os.environ.get("CAMUNDA_CLUSTER_ID", "").strip()

    if not raw:
        host = "%s.api.camunda.io" % region
        if cluster_id_env:
            return "https://%s/%s" % (host, cluster_id_env), host, False
        return "https://%s" % host, host, False

    candidate = raw if "://" in raw else "https://" + raw
    parsed = urlparse(candidate)
    host = parsed.hostname or ("%s.api.camunda.io" % region)

    cluster_id = None
    for seg in parsed.path.split("/"):
        if _UUID_RE.match(seg):
            cluster_id = seg
            break
    if not cluster_id:
        cluster_id = cluster_id_env

    if not cluster_id:
        # No UUID anywhere — return the input untouched rather than guessing;
        # the SDK will surface its own error and the native probe still runs.
        return candidate, host, False

    canonical = "https://%s/%s" % (host, cluster_id)
    # Non-canonical if the raw path carried anything beyond the clusterId and
    # an optional trailing "v2" (e.g. a stray ":443"/"443" Console segment),
    # or if the authority carried an explicit port.
    stray_segments = [s for s in parsed.path.split("/") if s and s != cluster_id and s != "v2"]
    was_normalized = bool(stray_segments) or (parsed.port is not None)
    return canonical, host, was_normalized


# Substring rules mirror the Go binary's classifyDialError (httpclient.go) —
# same three confirmed OS wordings for a blocked connection, same DNS/timeout/
# cert-trust distinctions. Kept as text matching (not exception-type
# matching) so this ALSO works for httpx-wrapped errors in probe_sdk.py,
# where the original OS-level exception may be buried in __cause__/__context__
# rather than raised directly.
_DNS_MARKERS = (
    "nodename nor servname", "name or service not known", "getaddrinfo failed",
    "temporary failure in name resolution", "[errno 11001]", "[errno -2]",
    "[errno -3]",
)
_REFUSED_MARKERS = ("connection refused", "actively refused", "forbidden by its access permissions")
_TIMEOUT_MARKERS = ("timed out", "timeout")
_CERT_MARKERS = ("certificate_verify_failed", "certificate verify failed", "unable to get local issuer certificate")


def classify_transport_error(exc):
    """Classify a connection/TLS exception into (errorClass, detail).

    Walks __cause__/__context__ so an httpx-wrapped exception (whose real
    OS-level error is chained, not the top-level type) still classifies the
    same way a raw socket/ssl exception would.
    """
    chain = []
    seen = set()
    cur = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        chain.append(cur)
        cur = cur.__cause__ or cur.__context__

    for e in chain:
        if isinstance(e, __import__("socket").gaierror):
            return "DNS_FAIL", "hostname did not resolve: %s" % e
        if isinstance(e, ConnectionRefusedError):
            return "CONNECT_REFUSED", "connection refused — port 443 likely blocked by firewall: %s" % e
        if isinstance(e, (__import__("socket").timeout, TimeoutError)):
            return "CONNECT_TIMEOUT", "connection timed out — port 443 likely blocked/dropped by firewall: %s" % e

    text = " | ".join(str(e) for e in chain).lower()
    if any(m in text for m in _CERT_MARKERS):
        return "TLS_HANDSHAKE_FAIL", "certificate not trusted: %s" % chain[0]
    if any(m in text for m in _DNS_MARKERS):
        return "DNS_FAIL", "hostname did not resolve: %s" % chain[0]
    if any(m in text for m in _REFUSED_MARKERS):
        return "CONNECT_REFUSED", "connection refused — port 443 likely blocked by firewall: %s" % chain[0]
    if any(m in text for m in _TIMEOUT_MARKERS):
        return "CONNECT_TIMEOUT", "connection timed out — port 443 likely blocked/dropped by firewall: %s" % chain[0]
    if "ssl" in text or "tls" in text or "handshake" in text:
        return "TLS_HANDSHAKE_FAIL", "TLS handshake failed: %s" % chain[0]
    return "CONNECT_REFUSED", "connection failed: %s" % chain[0]
