package main

import "testing"

// Only stages that run through the shared HTTP client (which honors
// --diagnostic-insecure-skip-verify) must have their PASS suppressed when TLS
// verification is disabled. The transport stages dns/tcp/tls/alpn do NOT use
// that client (tls does its own independent verification), so they must stay
// honest and not be flagged.
func TestUsesInsecureHTTPClient(t *testing.T) {
	usesClient := []string{"status", "oauth-reachability", "oauth-token", "topology",
		"webcomponent-console", "webcomponent-operate"}
	for _, name := range usesClient {
		if !usesInsecureHTTPClient(name) {
			t.Errorf("%q uses the HTTP client and must be capped under --diagnostic-insecure-skip-verify", name)
		}
	}

	transport := []string{"dns", "tcp", "tls", "alpn"}
	for _, name := range transport {
		if usesInsecureHTTPClient(name) {
			t.Errorf("%q is a transport stage (own verification) and must NOT be treated as insecure-client", name)
		}
	}
}
