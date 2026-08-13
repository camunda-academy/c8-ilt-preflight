"""Regression tests for the shared Python-probe helpers.

Run: python -m unittest discover -s preflight/layer2/python
(stdlib unittest only — no pytest, no extra deps, matching the probes'
zero-third-party-for-the-native-path philosophy).
"""
import os
import unittest

import _shared


class NormalizeRestBaseTest(unittest.TestCase):
    def setUp(self):
        # Snapshot + clear the env vars the normalizer reads, restore in tearDown.
        self._saved = {k: os.environ.get(k) for k in
                       ("CAMUNDA_REST_ADDRESS", "CAMUNDA_REGION", "CAMUNDA_CLUSTER_ID")}
        for k in self._saved:
            os.environ.pop(k, None)

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    # A fake but valid-format UUID — the normalizer only checks the shape, not
    # the value; never hardcode the real shared-cluster id into the repo.
    CID = "11111111-2222-3333-4444-555555555555"

    def test_console_copy_paste_stray_443_is_normalized_and_flagged(self):
        # The real Camunda Console copy-paste form that the SDK 404s on.
        os.environ["CAMUNDA_REST_ADDRESS"] = "https://bru-2.zeebe.camunda.io/:443/%s/v2/" % self.CID
        base, host, was_normalized = _shared.normalize_rest_base()
        self.assertEqual(base, "https://bru-2.zeebe.camunda.io/%s" % self.CID)
        self.assertEqual(host, "bru-2.zeebe.camunda.io")
        self.assertTrue(was_normalized, "stray ':443' path segment must be flagged as normalized")

    def test_canonical_form_is_untouched_and_not_flagged(self):
        os.environ["CAMUNDA_REST_ADDRESS"] = "https://bru-2.api.camunda.io/%s" % self.CID
        base, host, was_normalized = _shared.normalize_rest_base()
        self.assertEqual(base, "https://bru-2.api.camunda.io/%s" % self.CID)
        self.assertEqual(host, "bru-2.api.camunda.io")
        self.assertFalse(was_normalized)

    def test_trailing_v2_slash_is_canonical_not_flagged(self):
        # /v2/ is a legitimate suffix the SDK appends anyway — not "stray".
        os.environ["CAMUNDA_REST_ADDRESS"] = "https://bru-2.api.camunda.io/%s/v2/" % self.CID
        base, _, was_normalized = _shared.normalize_rest_base()
        self.assertEqual(base, "https://bru-2.api.camunda.io/%s" % self.CID)
        self.assertFalse(was_normalized)

    def test_authority_port_is_flagged(self):
        os.environ["CAMUNDA_REST_ADDRESS"] = "https://bru-2.api.camunda.io:443/%s" % self.CID
        base, host, was_normalized = _shared.normalize_rest_base()
        self.assertEqual(base, "https://bru-2.api.camunda.io/%s" % self.CID)
        self.assertEqual(host, "bru-2.api.camunda.io")
        self.assertTrue(was_normalized)

    def test_region_plus_cluster_id_env_fallback(self):
        os.environ["CAMUNDA_REGION"] = "syd-1"
        os.environ["CAMUNDA_CLUSTER_ID"] = self.CID
        base, host, was_normalized = _shared.normalize_rest_base()
        self.assertEqual(base, "https://syd-1.api.camunda.io/%s" % self.CID)
        self.assertEqual(host, "syd-1.api.camunda.io")
        self.assertFalse(was_normalized)

    def test_no_uuid_returns_input_untouched(self):
        # No clusterId anywhere — don't guess, hand it back so the SDK/native
        # probe surface their own errors rather than a fabricated URL.
        os.environ["CAMUNDA_REST_ADDRESS"] = "https://bru-2.api.camunda.io/not-a-uuid"
        base, host, was_normalized = _shared.normalize_rest_base()
        self.assertEqual(host, "bru-2.api.camunda.io")
        self.assertFalse(was_normalized)


class ResolveIsFullTest(unittest.TestCase):
    def test_explicit_network_is_never_full_even_with_creds(self):
        # Regression guard: creds in env must NOT trigger an authenticated
        # topology call when the run is explicitly network mode.
        self.assertFalse(_shared.resolve_is_full("network", True))
        self.assertFalse(_shared.resolve_is_full("network", False))

    def test_explicit_full_is_always_full(self):
        self.assertTrue(_shared.resolve_is_full("full", True))
        self.assertTrue(_shared.resolve_is_full("full", False))

    def test_unset_falls_back_to_creds_presence(self):
        self.assertTrue(_shared.resolve_is_full("", True))
        self.assertFalse(_shared.resolve_is_full("", False))
        self.assertFalse(_shared.resolve_is_full(None, False))

    def test_case_and_whitespace_insensitive(self):
        self.assertFalse(_shared.resolve_is_full("  NETWORK  ", True))
        self.assertTrue(_shared.resolve_is_full("Full", False))


class ScrubUrlCredsTest(unittest.TestCase):
    # Regression test: a proxy password embedded in an exception string must
    # be masked before it can reach stdout.
    def test_masks_proxy_password(self):
        s = _shared.scrub_url_creds("ConnectError to http://alice:s3cret@proxy.corp:8080 failed")
        self.assertNotIn("s3cret", s)
        self.assertNotIn("alice", s)
        self.assertIn("****:****@proxy.corp:8080", s)

    def test_fragment_scrubs_detail(self):
        frag = _shared.fragment("t", "FAIL", "CONNECT_REFUSED",
                                "proxy https://bob:s3cret2@p:3128 refused")
        self.assertNotIn("s3cret2", frag["detail"])
        self.assertIn("****:****@p:3128", frag["detail"])

    def test_leaves_plain_urls_intact(self):
        s = _shared.scrub_url_creds("reached https://bru-2.api.camunda.io/v2/status")
        self.assertEqual(s, "reached https://bru-2.api.camunda.io/v2/status")


class SilenceStdlibLoggingTest(unittest.TestCase):
    # Regression test: after silencing, a dependency logging via the stdlib
    # `logging` module (the path NullLogger does NOT cover) must produce no
    # output — so it can't leak a client_id.
    def test_suppresses_dependency_logging(self):
        import io
        import logging

        try:
            _shared.silence_stdlib_logging()
            buf = io.StringIO()
            handler = logging.StreamHandler(buf)
            lg = logging.getLogger("httpcore.some.dep")
            lg.addHandler(handler)
            lg.setLevel(logging.DEBUG)
            lg.error("OAuth token request client_id=LEAKY-VALUE")
            lg.debug("client_id=LEAKY-VALUE")
            self.assertEqual(buf.getvalue(), "", "stdlib logging should be fully suppressed")
        finally:
            logging.disable(logging.NOTSET)  # restore for other tests


class ClassifyTransportErrorTest(unittest.TestCase):
    def test_connection_refused(self):
        code, _ = _shared.classify_transport_error(ConnectionRefusedError("refused"))
        self.assertEqual(code, "CONNECT_REFUSED")

    def test_dns_via_gaierror(self):
        import socket
        code, _ = _shared.classify_transport_error(socket.gaierror("name resolution"))
        self.assertEqual(code, "DNS_FAIL")

    def test_cert_marker_in_wrapped_message(self):
        # Simulate an httpx-wrapped error whose real cause mentions cert trust.
        inner = Exception("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")
        outer = Exception("connection error")
        outer.__cause__ = inner
        code, _ = _shared.classify_transport_error(outer)
        self.assertEqual(code, "TLS_HANDSHAKE_FAIL")


if __name__ == "__main__":
    unittest.main()
