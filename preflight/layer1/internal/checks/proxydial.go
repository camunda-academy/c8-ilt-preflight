package checks

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// ResolveProxyForHost returns the proxy URL that should be used to reach
// targetURL, or nil if none. It mirrors exactly what the net/http client in
// httpclient.go does, so the transport stages (tcp/tls/alpn) and the
// HTTP-client stages (status/oauth/topology) agree on whether a proxy is in
// play — an explicit --proxy always wins; otherwise HTTP(S)_PROXY/NO_PROXY
// env vars are honored (NO_PROXY included, via http.ProxyFromEnvironment).
func ResolveProxyForHost(targetURL, explicitProxyURL string) (*url.URL, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}
	req := &http.Request{URL: u}
	if explicitProxyURL != "" {
		p, perr := url.Parse(explicitProxyURL)
		if perr != nil {
			return nil, perr
		}
		return http.ProxyURL(p)(req)
	}
	return http.ProxyFromEnvironment(req)
}

// DialWithOptionalProxy establishes a raw TCP connection to host:port. When
// proxy is nil it dials directly; when proxy is set it dials the proxy and
// opens an HTTP CONNECT tunnel to host:port, so the subsequent TLS handshake
// inspects exactly what the client would see *through the proxy* — this is
// what makes the tls/alpn stages catch an intercepting proxy that the http
// client stages also traverse (the fix for the "transport bypasses proxy"
// limitation). NTLM/Negotiate proxy auth is not supported (Go has none);
// Basic proxy auth from the proxy URL's userinfo is sent if present.
func DialWithOptionalProxy(ctx context.Context, host string, port int, proxy *url.URL) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	target := net.JoinHostPort(host, strconv.Itoa(port))

	if proxy == nil {
		return dialer.DialContext(ctx, "tcp", target)
	}

	proxyAddr := proxy.Host
	if proxy.Port() == "" {
		defPort := "80"
		if proxy.Scheme == "https" {
			defPort = "443"
		}
		proxyAddr = net.JoinHostPort(proxy.Hostname(), defPort)
	}

	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("could not reach proxy %s: %w", proxyAddr, err)
	}

	// If the proxy itself is HTTPS, TLS-wrap the connection to the proxy
	// before issuing CONNECT.
	if proxy.Scheme == "https" {
		tlsProxy := tls.Client(conn, &tls.Config{ServerName: proxy.Hostname(), MinVersion: tls.VersionTLS12})
		if hsErr := tlsProxy.HandshakeContext(ctx); hsErr != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake to proxy %s failed: %w", proxyAddr, hsErr)
		}
		conn = tlsProxy
	}

	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(15 * time.Second))
	}

	connectReq := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if proxy.User != nil {
		username := proxy.User.Username()
		password, _ := proxy.User.Password()
		cred := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		connectReq += "Proxy-Authorization: Basic " + cred + "\r\n"
	}
	connectReq += "\r\n"

	if _, werr := conn.Write([]byte(connectReq)); werr != nil {
		conn.Close()
		return nil, fmt.Errorf("could not send CONNECT to proxy %s: %w", proxyAddr, werr)
	}

	// Parse the proxy's CONNECT response.
	br := bufio.NewReader(conn)
	resp, rerr := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if rerr != nil {
		conn.Close()
		return nil, fmt.Errorf("invalid CONNECT response from proxy %s: %w", proxyAddr, rerr)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		// Include the status code in the message so classifyDialError maps a
		// 407 to PROXY_AUTH_407.
		return nil, fmt.Errorf("proxy %s refused CONNECT tunnel: HTTP %d %s", proxyAddr, resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	// The bufio.Reader used to parse the CONNECT response may have read ahead
	// past the response headers. We return the RAW conn to the caller for the
	// TLS handshake, so any such buffered bytes would be silently lost —
	// corrupting the handshake and surfacing as a misleading TLS_HANDSHAKE_FAIL
	// from the very stage meant to diagnose proxies.
	// In the normal HTTPS case the client speaks first (ClientHello), so the
	// proxy sends nothing after the 200 and this is zero. If a proxy does
	// coalesce early bytes, fail loudly and specifically rather than let the
	// TLS layer choke on a truncated stream.
	if n := br.Buffered(); n > 0 {
		conn.Close()
		return nil, fmt.Errorf("proxy %s sent %d unexpected byte(s) after the CONNECT 200 response (server-speaks-first or a misbehaving proxy) — cannot cleanly hand the tunnel to TLS", proxyAddr, n)
	}

	// Clear the deadline; the caller (TLS handshake) sets its own.
	conn.SetDeadline(time.Time{})
	return conn, nil
}
