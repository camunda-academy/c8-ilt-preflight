#!/usr/bin/env python3
"""Layer 2 native trust probe — Python.

Standalone: python3 preflight/layer2/python/probe.py
(no Camunda SDK required — stdlib ssl/socket only, certifi optional)

Env vars:
  CAMUNDA_REST_ADDRESS   full cluster REST URL (wins over CAMUNDA_REGION)
  CAMUNDA_REGION         region slug, default bru-2
  CAMUNDA_MTLS_CA_PATH   extra CA PEM to trust in addition to the SDK's store
  HTTPS_PROXY / HTTP_PROXY (or lowercase)   explicit proxy, CONNECT-tunneled

Emits one JSON fragment per line on stdout, per target, following the same
cross-runtime probe contract every Layer 2 probe shares:
  {runtime, trustStoreExercised, target, verdict, errorClass, detail}

Critical design point: this probe exercises the SAME trust
store the Camunda Python SDK uses by default — certifi's bundle (verified
in the SDK's own dependency, httpx: httpx/_config.py builds its default
ssl.create_default_context(cafile=certifi.where())) — NOT the stdlib
default, which loads the OS/system store instead. Using the stdlib
default would re-create the JVM-style false-green inside Layer 2: on a
Windows machine where IT pushed a corporate proxy CA into the OS store,
the stdlib default would trust it while the SDK (certifi) still doesn't.
"""
import base64
import json
import socket
import ssl
import sys
import time
from urllib.parse import urlparse

from _shared import (
    RUNTIME,
    classify_transport_error,
    eprint,
    fragment,
    get_proxy_url,
    mask_proxy,
    resolve_api_host,
)

CONNECT_TIMEOUT = 10
OAUTH_HOST = "login.cloud.camunda.io"


class ProxyError(ConnectionError):
    """Raised when the CONNECT tunnel itself fails (bad status line)."""

    def __init__(self, status_line):
        self.status_line = status_line
        super().__init__(status_line)


def resolve_targets():
    return [(resolve_api_host(), 443), (OAUTH_HOST, 443)]


def build_ssl_context():
    # store_label is kept short and plain-language deliberately -- it ends up
    # in the customer-facing result (Notes/FAIL details), not just an
    # engineering log. The certifi-vs-SDK nuance is documented in the training documentation.md
    # for trainers, not repeated here every time a participant runs the tool.
    import os

    custom_ca = os.environ.get("CAMUNDA_MTLS_CA_PATH", "").strip()
    try:
        import certifi

        ctx = ssl.create_default_context(cafile=certifi.where())
        store_label = "the default certificate bundle"
    except ImportError:
        # Fall back to the stdlib default only if certifi is absent, and say
        # so explicitly via store_label so the weaker check stays visible.
        ctx = ssl.create_default_context()
        store_label = "the default certificate bundle (installing 'certifi' is recommended for the most accurate check)"

    if custom_ca:
        ctx.load_verify_locations(cafile=custom_ca)
        store_label = "the default certificate bundle plus your custom certificate (%s)" % custom_ca

    return ctx, store_label


def connect_via_proxy(proxy_url, host, port, timeout):
    p = urlparse(proxy_url)
    proxy_host = p.hostname
    proxy_port = p.port or (443 if p.scheme == "https" else 80)

    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    if p.scheme == "https":
        proxy_ctx = ssl.create_default_context()
        sock = proxy_ctx.wrap_socket(sock, server_hostname=proxy_host)

    request_lines = ["CONNECT %s:%d HTTP/1.1" % (host, port), "Host: %s:%d" % (host, port)]
    if p.username:
        cred = base64.b64encode(("%s:%s" % (p.username, p.password or "")).encode()).decode()
        request_lines.append("Proxy-Authorization: Basic %s" % cred)
    request = "\r\n".join(request_lines) + "\r\n\r\n"
    sock.sendall(request.encode())

    sock.settimeout(timeout)
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk

    status_line = response.split(b"\r\n", 1)[0].decode(errors="replace").strip()
    if " 200 " not in (" " + status_line):
        sock.close()
        raise ProxyError(status_line or "no response from proxy")

    return sock


def probe_target(host, port, ctx, store_label, proxy_url):
    start = time.time()
    target = "%s:%d" % (host, port)

    try:
        if proxy_url:
            raw_sock = connect_via_proxy(proxy_url, host, port, CONNECT_TIMEOUT)
        else:
            raw_sock = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
    except ProxyError as e:
        if "407" in e.status_line:
            return fragment(target, "FAIL", "PROXY_AUTH_407",
                             "authenticated corporate proxy in path — supply credentials in the proxy URL "
                             "(Basic auth only; export HTTPS_PROXY=http://user:pass@<proxy>:<port>) "
                             "or ask IT to exempt these hosts. Proxy response: %s" % e.status_line)
        return fragment(target, "FAIL", "CONNECT_REFUSED", "proxy CONNECT tunnel failed: %s" % e.status_line)
    except Exception as e:
        error_class, detail = classify_transport_error(e)
        return fragment(target, "FAIL", error_class, detail)

    try:
        with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            tls_sock.do_handshake()
        elapsed_ms = int((time.time() - start) * 1000)
        return fragment(target, "PASS", "OK",
                         "TLS handshake succeeded (%dms)" % elapsed_ms,
                         store_label)
    except ssl.SSLCertVerificationError as e:
        return fragment(target, "FAIL", "TLS_HANDSHAKE_FAIL",
                         "certificate not trusted by %s: %s — likely a TLS-intercepting proxy; "
                         "import its root CA via CAMUNDA_MTLS_CA_PATH (see the training documentation)" % (store_label, e),
                         store_label)
    except Exception as e:
        error_class, detail = classify_transport_error(e)
        return fragment(target, "FAIL", error_class, detail, store_label)
    finally:
        try:
            raw_sock.close()
        except Exception:
            pass


def main():
    if any(a in ("-h", "--help") for a in sys.argv[1:]):
        eprint(__doc__)
        return 0

    ctx, store_label = build_ssl_context()
    proxy_url = get_proxy_url()
    if proxy_url:
        eprint("[python probe] using proxy: %s" % mask_proxy(proxy_url))
    eprint("[python probe] trust store: %s" % store_label)

    exit_code = 0
    for host, port in resolve_targets():
        frag = probe_target(host, port, ctx, store_label, proxy_url)
        print(json.dumps(frag))
        sys.stdout.flush()
        if frag["verdict"] not in ("PASS", "WARN", "SKIP"):
            exit_code = 1
    return exit_code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        # Last-resort: never let an unhandled exception produce a bare
        # traceback on stdout that the launcher can't parse — emit a proper
        # probe-error fragment instead, matching the shared cross-runtime
        # probe contract.
        from _shared import crash_fragment

        print(json.dumps(crash_fragment(e)))
        sys.exit(1)
