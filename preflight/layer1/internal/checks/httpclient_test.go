package checks

import (
	"errors"
	"strings"
	"testing"
)

// TestClassifyDialError_CrossPlatformRefused is a regression test for a real
// bug: Windows's connectex/WSAECONNREFUSED error text ("...actively refused
// it.") doesn't contain the Unix/Linux/macOS "connection refused" substring,
// so it silently fell through to the generic default branch with no detail
// text and no remediation hint at all — on the majority OS trainees
// actually run. Both wordings must classify identically.
func TestClassifyDialError_CrossPlatformRefused(t *testing.T) {
	unix := errors.New("dial tcp 127.0.0.1:443: connect: connection refused")
	windows := errors.New(`dial tcp 127.0.0.1:443: connectex: No connection could be made because the target machine actively refused it.`)

	codeUnix, detailUnix := classifyDialError(unix)
	codeWin, detailWin := classifyDialError(windows)

	if codeUnix != "CONNECT_REFUSED" {
		t.Errorf("unix code = %q, want CONNECT_REFUSED", codeUnix)
	}
	if codeWin != "CONNECT_REFUSED" {
		t.Errorf("windows code = %q, want CONNECT_REFUSED", codeWin)
	}
	if !strings.Contains(detailWin, "port 443 likely blocked") {
		t.Errorf("windows detail lost the remediation text, got: %q", detailWin)
	}
	if !strings.Contains(detailUnix, "port 443 likely blocked") {
		t.Errorf("unix detail lost the remediation text, got: %q", detailUnix)
	}
}

// TestClassifyDialError_WindowsFirewallAccessDenied is a regression test for
// a third distinct OS wording: a `New-NetFirewallRule -Action Block` test
// shows Windows Firewall's own local block produces WSAEACCES ("...forbidden
// by its access permissions"), which is different from both "connection
// refused" and "...actively refused it."
// (that's a remote-side reject; this is a local OS-level block). Without
// this match it silently fell through to the generic default branch, same
// failure mode as the other two wordings.
func TestClassifyDialError_WindowsFirewallAccessDenied(t *testing.T) {
	err := errors.New(`dial tcp 198.51.100.10:443: connectex: An attempt was made to access a socket in a way forbidden by its access permissions.`)
	code, detail := classifyDialError(err)
	if code != "CONNECT_REFUSED" {
		t.Errorf("code = %q, want CONNECT_REFUSED", code)
	}
	if !strings.Contains(detail, "port 443 likely blocked") {
		t.Errorf("detail lost the remediation text, fell through to default branch, got: %q", detail)
	}
}

// TestClassifyDialError_407HintIncludesUserPassSyntax confirms the 407
// remediation tells the runner exactly how to supply Basic proxy
// credentials, not just "supply proxy credentials" with no syntax.
func TestClassifyDialError_407HintIncludesUserPassSyntax(t *testing.T) {
	err := errors.New(`proxy localhost:8080 refused CONNECT tunnel: HTTP 407 Proxy Authentication Required`)
	code, detail := classifyDialError(err)
	if code != "PROXY_AUTH_407" {
		t.Errorf("code = %q, want PROXY_AUTH_407", code)
	}
	if !strings.Contains(detail, "--proxy http://user:pass@") {
		t.Errorf("407 detail missing the user:pass syntax, got: %q", detail)
	}
	if !strings.Contains(detail, "NTLM") {
		t.Error("407 detail should still note NTLM/Negotiate is unsupported")
	}
}

// TestClassifyDialError_CertTrustErrorNotSelfContradictory is a regression
// test for a self-contradictory message that surfaces when running against a
// manual TLS-intercepting proxy: the real, fully-verifying HTTP client hits
// the SAME untrusted-CA failure the tls stage's diagnostic already flagged,
// but the generic TLS-handshake message claimed "not a certificate-trust
// issue" right next to an error that says "certificate signed by unknown
// authority" — a direct self-contradiction in exactly the scenario this
// tool exists to catch. Cert-trust errors must get an accurate message.
func TestClassifyDialError_CertTrustErrorNotSelfContradictory(t *testing.T) {
	err := errors.New(`Get "https://bru-2.api.camunda.io/x/v2/status": tls: failed to verify certificate: x509: certificate signed by unknown authority`)
	code, detail := classifyDialError(err)
	if code != "TLS_HANDSHAKE_FAIL" {
		t.Errorf("code = %q, want TLS_HANDSHAKE_FAIL", code)
	}
	if strings.Contains(detail, "not a certificate-trust issue") {
		t.Errorf("detail self-contradicts — claims 'not a certificate-trust issue' for an x509 trust error: %q", detail)
	}
	if !strings.Contains(detail, "not trusted") {
		t.Errorf("detail should accurately describe this as a trust failure, got: %q", detail)
	}
}

// TestClassifyDialError_NonCertTLSErrorStillGetsGenericMessage confirms a
// TLS failure that ISN'T about certificate trust (e.g. a protocol mismatch)
// still gets the generic message — the fix above must not misclassify
// every TLS-flavored error as a trust issue.
func TestClassifyDialError_NonCertTLSErrorStillGetsGenericMessage(t *testing.T) {
	err := errors.New(`tls: handshake failure`)
	_, detail := classifyDialError(err)
	if !strings.Contains(detail, "not a certificate-trust issue") {
		t.Errorf("non-cert TLS error should keep the generic message, got: %q", detail)
	}
}

func TestClassifyDialError_ProxyHintOnlyWhenNoProxyConfigured(t *testing.T) {
	defer SetProxyConfigured(false) // restore default for other tests

	refused := errors.New("dial tcp 127.0.0.1:443: connect: connection refused")

	SetProxyConfigured(false)
	_, detailNoProxy := classifyDialError(refused)
	if !strings.Contains(detailNoProxy, "--proxy") {
		t.Error("expected the --proxy suggestion when no proxy is configured")
	}

	SetProxyConfigured(true)
	_, detailWithProxy := classifyDialError(refused)
	if strings.Contains(detailWithProxy, "--proxy") {
		t.Error("did not expect the --proxy suggestion when a proxy is already configured")
	}
}

func TestClassifyDialError_UnrecognizedErrorStillGetsHint(t *testing.T) {
	defer SetProxyConfigured(false)
	SetProxyConfigured(false)

	weird := errors.New("some future OS wording we've never seen before")
	code, detail := classifyDialError(weird)
	if code != "CONNECT_REFUSED" {
		t.Errorf("code = %q, want CONNECT_REFUSED (default branch)", code)
	}
	if !strings.Contains(detail, "--proxy") {
		t.Error("expected the default branch to still carry the proxy hint, not a bare error dump")
	}
}
