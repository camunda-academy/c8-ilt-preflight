package checks

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"time"

	"c8preflight/internal/model"
)

// TCPConnect establishes a connection to host:port and reports the result.
// When proxy is non-nil it connects via the proxy's CONNECT tunnel (so the
// TLS handshake that follows inspects what the client would see *through the
// proxy*); when nil it dials directly. This is a real connectivity
// measurement, not a diagnostic bypass.
func TCPConnect(ctx context.Context, host string, port int, proxy *url.URL) (net.Conn, model.Stage) {
	start := time.Now()

	conn, err := DialWithOptionalProxy(ctx, host, port, proxy)
	elapsed := time.Since(start).Milliseconds()

	via := ""
	if proxy != nil {
		via = fmt.Sprintf(" (via proxy %s)", proxy.Hostname())
	}

	if err != nil {
		code, detail := classifyDialError(err)
		return nil, model.Stage{
			Name:            "tcp",
			Host:            host,
			Port:            port,
			Verdict:         model.VerdictFail,
			RemediationCode: model.ErrorClass(code),
			Detail:          detail,
			ElapsedMs:       elapsed,
		}
	}

	return conn, model.Stage{
		Name:            "tcp",
		Host:            host,
		Port:            port,
		Verdict:         model.VerdictPass,
		RemediationCode: model.ErrOK,
		Detail:          "TCP connection established" + via,
		ElapsedMs:       elapsed,
	}
}

// TLSInspectResult bundles the TLS + ALPN stage verdicts with the captured
// certificate info for the report's tls[] array.
type TLSInspectResult struct {
	TLSStage  model.Stage
	ALPNStage model.Stage
	Info      model.TLSInfo
}

// TLSInspect performs the handshake using a DELIBERATE two-step technique:
//  1. Capture the server's certificate chain with InsecureSkipVerify=true,
//     so we learn what was actually presented even when a normal client
//     would reject it (the intercepting-proxy case).
//  2. Independently verify that captured chain against the real trust
//     store (system roots, or system+customCA if provided) to determine
//     whether a normal client WOULD trust it.
//
// This is NOT "disabling TLS verification as a fix" (TLS verification must
// never be disabled for the actual functional checks/status/topology calls,
// which use a fully-verifying client in httpclient.go). This is purely a
// diagnostic capture so the tool can report the served issuer/subject and the
// interception finding even in the untrusted case, which a normal
// fail-closed handshake would never let us see. The verdict below still
// requires genuine trust to PASS.
func TLSInspect(ctx context.Context, conn net.Conn, host string, port int, customCARoots *x509.CertPool) TLSInspectResult {
	start := time.Now()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // diagnostic capture only — see doc comment above
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         tls.VersionTLS12,
	})
	defer tlsConn.Close()

	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	err := tlsConn.HandshakeContext(hctx)
	elapsed := time.Since(start).Milliseconds()

	if err != nil {
		code, detail := classifyDialError(err)
		if code == "CONNECT_REFUSED" {
			// A handshake-layer failure that isn't a recognized DNS/timeout/
			// proxy pattern is a genuine TLS problem, not a generic refusal.
			code, detail = string(model.ErrTLSHandshakeFail), "TLS handshake failed: "+err.Error()
		}
		fail := model.Stage{
			Name: "tls", Host: host, Port: port,
			Verdict: model.VerdictFail, RemediationCode: model.ErrorClass(code),
			Detail: detail, ElapsedMs: elapsed,
		}
		return TLSInspectResult{TLSStage: fail, ALPNStage: model.Stage{
			Name: "alpn", Host: host, Port: port, Verdict: model.VerdictSkip,
			RemediationCode: model.ErrOK, Detail: "skipped — TLS handshake did not complete",
		}}
	}

	state := tlsConn.ConnectionState()
	info := model.TLSInfo{Host: host, NegotiatedALPN: state.NegotiatedProtocol}

	isPublicCA := false
	var verifyDetail string
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		info.Issuer = leaf.Issuer.String()
		info.Subject = leaf.Subject.String()
		info.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)

		intermediates := x509.NewCertPool()
		for _, c := range state.PeerCertificates[1:] {
			intermediates.AddCert(c)
		}
		_, verifyErr := leaf.Verify(x509.VerifyOptions{
			DNSName:       host,
			Intermediates: intermediates,
			Roots:         customCARoots, // nil => Go uses the system root pool
		})
		if verifyErr == nil {
			isPublicCA = true
		} else {
			verifyDetail = verifyErr.Error()
		}
	}
	info.IsPublicCA = isPublicCA

	var tlsStage model.Stage
	if isPublicCA {
		tlsStage = model.Stage{
			Name: "tls", Host: host, Port: port,
			Verdict: model.VerdictPass, RemediationCode: model.ErrOK,
			Detail:    fmt.Sprintf("issuer: %s (trusted)", info.Issuer),
			ElapsedMs: elapsed,
		}
	} else {
		tlsStage = model.Stage{
			Name: "tls", Host: host, Port: port,
			Verdict: model.VerdictWarn, RemediationCode: model.ErrTLSNonPublicIssuer,
			Detail: fmt.Sprintf(
				"issuer: %s — NOT trusted by the system root store (likely a TLS-intercepting proxy). "+
					"Fix: import the proxy's root CA into this runtime's trust store, not by disabling certificate verification. Verify error: %s",
				info.Issuer, verifyDetail),
			ElapsedMs: elapsed,
		}
	}

	alpnVerdict := model.VerdictPass
	alpnCode := model.ErrOK
	alpnDetail := fmt.Sprintf("negotiated %s", nonEmpty(state.NegotiatedProtocol, "(none)"))
	if state.NegotiatedProtocol != "h2" {
		alpnVerdict = model.VerdictWarn
		alpnCode = model.ErrALPNDowngradeWarn
		alpnDetail = fmt.Sprintf(
			"negotiated %s instead of h2 — only matters if your training group uses the legacy gRPC Zeebe client; "+
				"the v2 REST API works fine over HTTP/1.1", nonEmpty(state.NegotiatedProtocol, "(none)"))
	}
	alpnStage := model.Stage{
		Name: "alpn", Host: host, Port: port,
		Verdict: alpnVerdict, RemediationCode: alpnCode,
		Detail: alpnDetail, ElapsedMs: 0,
	}

	return TLSInspectResult{TLSStage: tlsStage, ALPNStage: alpnStage, Info: info}
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
