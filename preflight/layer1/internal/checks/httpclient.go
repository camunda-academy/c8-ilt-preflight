package checks

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// ClientOptions configures the shared HTTP client used for all real
// application-level calls (status, topology, oauth, web-component checks).
// This is deliberately a NORMAL, fully-verifying TLS client — the diagnostic
// dual-capture technique in tlsinspect.go is separate and only used for the
// TLS-inspection stage's reporting, never for these functional calls
// (never disable TLS verification, including here).
type ClientOptions struct {
	// CustomCAPath, if set (CAMUNDA_MTLS_CA_PATH), is appended to the system
	// root pool so a custom/corporate CA can be tested the same way the
	// SDKs support it.
	CustomCAPath   string
	ConnectTimeout time.Duration
	OverallTimeout time.Duration

	// ExplicitProxyURL, if set (--proxy), overrides HTTP_PROXY/HTTPS_PROXY
	// env-var auto-detection entirely, so an operator can force a specific
	// proxy regardless of what the environment reports.
	ExplicitProxyURL string

	// DiagnosticInsecureSkipVerify disables TLS verification for the real
	// application calls (status/topology/oauth). This must never be the
	// documented fix — callers using this MUST clearly label
	// every affected stage as diagnostic-only and must not report a clean
	// PASS while it's active (see checks.DiagnosticCap in main.go).
	DiagnosticInsecureSkipVerify bool
}

// NewHTTPClient builds the shared client. Proxy is picked up automatically
// from HTTP_PROXY/HTTPS_PROXY/NO_PROXY env vars via http.ProxyFromEnvironment.
func NewHTTPClient(opts ClientOptions) (*http.Client, error) {
	if opts.ConnectTimeout == 0 {
		opts.ConnectTimeout = 10 * time.Second
	}
	if opts.OverallTimeout == 0 {
		opts.OverallTimeout = 30 * time.Second
	}

	rootPool, err := BuildRootPool(opts.CustomCAPath)
	if err != nil {
		return nil, err
	}

	proxyFunc := http.ProxyFromEnvironment
	if opts.ExplicitProxyURL != "" {
		fixed, err := url.Parse(opts.ExplicitProxyURL)
		if err != nil {
			return nil, fmt.Errorf("could not parse --proxy %q: %w", opts.ExplicitProxyURL, err)
		}
		proxyFunc = http.ProxyURL(fixed)
	}

	dialer := &net.Dialer{Timeout: opts.ConnectTimeout}
	transport := &http.Transport{
		Proxy:               proxyFunc,
		DialContext:         dialer.DialContext,
		TLSHandshakeTimeout: opts.ConnectTimeout,
		TLSClientConfig: &tls.Config{
			RootCAs:            rootPool, // nil => Go uses the system pool
			InsecureSkipVerify: opts.DiagnosticInsecureSkipVerify,
		},
	}

	return &http.Client{
		Transport: transport,
		Timeout:   opts.OverallTimeout,
		// Do not follow redirects automatically for reachability probes —
		// a redirect response itself already proves "reachable" (any clean
		// HTTP response proves transport is open).
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

// BuildRootPool returns the trust pool to use for BOTH the real application
// HTTP client and the diagnostic TLS-inspection stage, so they agree on
// what counts as trusted (parity — if a custom CA is supplied, both see it).
// A nil, nil return means "use Go's default system pool".
func BuildRootPool(customCAPath string) (*x509.CertPool, error) {
	if customCAPath == "" {
		return nil, nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	pem, err := os.ReadFile(customCAPath)
	if err != nil {
		return nil, fmt.Errorf("could not read CAMUNDA_MTLS_CA_PATH %q: %w", customCAPath, err)
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no valid PEM certificates found in CAMUNDA_MTLS_CA_PATH %q", customCAPath)
	}
	return pool, nil
}

// DetectedProxy reports the effective proxy for a given target URL — either
// the explicit --proxy override, or whatever HTTP_PROXY/HTTPS_PROXY/NO_PROXY
// resolve to — with any embedded userinfo credentials masked before being
// surfaced in output (never leak proxy credentials in the report). Empty
// string means no proxy is in effect for this target.
func DetectedProxy(targetURL, explicitProxyURL string) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}

	var proxyURL *url.URL
	if explicitProxyURL != "" {
		proxyURL, err = url.Parse(explicitProxyURL)
		if err != nil {
			return ""
		}
	} else {
		proxyURL, err = http.ProxyFromEnvironment(&http.Request{URL: u})
		if err != nil || proxyURL == nil {
			return ""
		}
	}

	masked := *proxyURL
	if masked.User != nil {
		masked.User = url.UserPassword("****", "****")
	}
	return masked.String()
}

// proxyConfiguredForRun records whether a proxy (explicit --proxy or
// HTTP(S)_PROXY env) is active for this run. It's fixed for the whole
// process lifetime (one invocation = one proxy configuration), so a
// package-level value set once at startup (see SetProxyConfigured) is safe
// and avoids threading a bool through every classifyDialError call site.
var proxyConfiguredForRun bool

// SetProxyConfigured must be called once, early in main(), with whether a
// proxy is active for this run — used only to tailor the CONNECT_REFUSED/
// CONNECT_TIMEOUT remediation hint below.
func SetProxyConfigured(v bool) {
	proxyConfiguredForRun = v
}

const noProxyHint = " If this network has a corporate proxy, re-run with --proxy http://<proxy>:<port> (or set HTTPS_PROXY) — if that succeeds, this is a config change on your side (point your SDK/tooling at the proxy), not necessarily a network-team ticket."

// classifyDialError turns a transport-level error into the shared
// ErrorClass/Verdict vocabulary. These are the "real, one-shot failures"
// that must never be retried.
func classifyDialError(err error) (code string, detail string) {
	msg := err.Error()
	lower := strings.ToLower(msg)

	proxyHint := ""
	if !proxyConfiguredForRun {
		proxyHint = noProxyHint
	}

	switch {
	case strings.Contains(msg, "407") || strings.Contains(lower, "proxy authentication required"):
		return "PROXY_AUTH_407", "authenticated corporate proxy in path — the tool (and most training SDKs) can't traverse a proxy requiring NTLM/Negotiate credentials. If the proxy accepts Basic auth, supply credentials in the URL: --proxy http://user:pass@<proxy>:<port> (Basic only — NTLM/Negotiate is not supported). Otherwise ask IT to exempt these hosts."
	case isDNSError(err):
		return "DNS_FAIL", "hostname did not resolve — DNS split-horizon or no external DNS: " + msg + proxyHint
	case strings.Contains(lower, "connection refused") || strings.Contains(lower, "actively refused") || strings.Contains(lower, "forbidden by its access permissions"):
		// Three distinct OS wordings for the same "blocked" outcome, all
		// confirmed live: "connection refused" (Unix/Linux/macOS errno);
		// Windows connectex/WSAECONNREFUSED "...actively refused it."
		// (remote-side reject/RST); and Windows WSAEACCES "...forbidden by
		// its access permissions" (local OS-level block — this is what
		// Windows Firewall's own Block rule produces, confirmed via
		// New-NetFirewallRule -Action Block, distinct from a remote RST).
		// All three must be matched or Windows runs (the majority of
		// trainees) silently fall through to the generic default branch
		// with no detail text and no remediation hint at all.
		return "CONNECT_REFUSED", "connection refused — port 443 likely blocked by firewall (or DNS-sinkholed to an unreachable address; check target.resolvedIPs): " + msg + proxyHint
	case strings.Contains(lower, "timeout") || strings.Contains(lower, "i/o timeout") || strings.Contains(lower, "deadline exceeded"):
		return "CONNECT_TIMEOUT", "connection timed out — port 443 likely blocked/dropped by firewall: " + msg + proxyHint
	case isCertTrustError(err):
		// This is the SAME failure the tls stage's dual-capture diagnostic
		// already flagged as a non-public issuer (e.g. an intercepting
		// proxy) — the real, fully-verifying client correctly refuses it
		// too. Without this branch, the generic isTLSError message below
		// would claim "not a certificate-trust issue" while the error text right
		// next to it says "certificate signed by unknown authority" — a
		// direct, self-contradicting claim in exactly the scenario this
		// tool exists to catch. Give the accurate message instead.
		return "TLS_HANDSHAKE_FAIL", "TLS handshake failed — certificate not trusted (the same issue as the tls stage's non-public-issuer finding above, not a separate problem): " + msg
	case isTLSError(err):
		return "TLS_HANDSHAKE_FAIL", "TLS handshake failed (not a certificate-trust issue — see TLS stage for that): " + msg
	default:
		// Unrecognized OS/platform error text — still give the same
		// remediation hint rather than a bare, unexplained error dump.
		return "CONNECT_REFUSED", "connection failed: " + msg + proxyHint
	}
}

func isDNSError(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr)
}

func isTLSError(err error) bool {
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "tls") || strings.Contains(lower, "certificate") || strings.Contains(lower, "handshake")
}

// isCertTrustError narrows isTLSError to specifically an untrusted-chain
// failure (Go's crypto/x509 error text), as opposed to other TLS handshake
// failures (protocol mismatch, connection reset mid-handshake) that aren't
// about certificate trust at all.
func isCertTrustError(err error) bool {
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "x509:") ||
		strings.Contains(lower, "certificate signed by unknown authority") ||
		strings.Contains(lower, "certificate is not trusted") ||
		strings.Contains(lower, "unable to find valid certification path") ||
		strings.Contains(lower, "unknown authority") ||
		strings.Contains(lower, "self-signed certificate") ||
		strings.Contains(lower, "certificate has expired")
}
