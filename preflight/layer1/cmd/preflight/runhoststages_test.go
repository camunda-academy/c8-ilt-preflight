package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"c8preflight/internal/checks"
	"c8preflight/internal/config"
	"c8preflight/internal/hostset"
	"c8preflight/internal/model"
	"c8preflight/internal/report"
)

// stubFailingDNS makes the dns stage fail the way it does on a machine whose
// resolver cannot resolve public names.
func stubFailingDNS(t *testing.T) {
	t.Helper()
	orig := resolveDNS
	resolveDNS = func(_ context.Context, host string) model.Stage {
		return model.Stage{
			Name: "dns", Host: host, Verdict: model.VerdictFail, RemediationCode: model.ErrDNSFail,
			Detail: "hostname did not resolve — DNS split-horizon or no external DNS: lookup " + host + ": no such host",
		}
	}
	t.Cleanup(func() { resolveDNS = orig })
}

// connectProxy is a minimal HTTP CONNECT proxy that tunnels every request to
// one upstream address, whatever host name the client asked for — standing in
// for a proxy that resolves names the client itself cannot.
type connectProxy struct {
	mu        sync.Mutex
	targets   []string
	authSeen  bool
	listener  net.Listener
	upstream  string
	waitGroup sync.WaitGroup
}

func startConnectProxy(t *testing.T, upstream string) *connectProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &connectProxy{listener: ln, upstream: upstream}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			p.waitGroup.Add(1)
			go p.serve(c)
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		p.waitGroup.Wait()
	})
	return p
}

func (p *connectProxy) serve(c net.Conn) {
	defer p.waitGroup.Done()
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method != http.MethodConnect {
		io.WriteString(c, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
		return
	}
	p.mu.Lock()
	p.targets = append(p.targets, req.Host)
	if req.Header.Get("Proxy-Authorization") != "" {
		p.authSeen = true
	}
	p.mu.Unlock()

	up, err := net.Dial("tcp", p.upstream)
	if err != nil {
		io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer up.Close()
	io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
	done := make(chan struct{})
	go func() {
		io.Copy(up, br)
		up.Close()
		close(done)
	}()
	io.Copy(c, up)
	c.Close()
	<-done
}

func (p *connectProxy) seen() ([]string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.targets...), p.authSeen
}

func stageNamesAndVerdicts(stages []model.Stage) string {
	parts := make([]string, len(stages))
	for i, s := range stages {
		parts[i] = s.Name + "=" + string(s.Verdict)
	}
	return strings.Join(parts, " ")
}

// When the local resolver fails but a proxy applies, the proxy resolves the
// name itself: dns must be a WARN, the remaining stages must run through the
// proxy, and the overall verdict must come from those real results.
func TestRunHostStages_DNSFailWithProxyContinuesThroughProxy(t *testing.T) {
	stubFailingDNS(t)

	const clusterID = "test-cluster"
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/"+clusterID+"/v2/status" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	proxy := startConnectProxy(t, srv.Listener.Addr().String())
	const proxyPassword = "pr0xy-s3cret"
	proxyURL := &url.URL{Scheme: "http", User: url.UserPassword("trainee", proxyPassword), Host: proxy.listener.Addr().String()}

	transport := srv.Client().Transport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(proxyURL)
	client := &http.Client{Transport: transport}
	t.Cleanup(transport.CloseIdleConnections)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(srv.Certificate())

	// The test certificate is valid for *.example.com; with dns stubbed to
	// fail, the name is only ever resolved (here: mapped) by the proxy.
	const host = "api.example.com"
	cfg := &config.Config{ProxyURL: proxyURL.String(), Target: hostset.Target{ClusterID: clusterID}}

	var result model.Result
	var stages []model.Stage
	runHostStages(context.Background(), client, rootPool, cfg, host, &result, func(s model.Stage) { stages = append(stages, s) })

	want := "dns=WARN tcp=PASS tls=PASS alpn=PASS status=PASS"
	if got := stageNamesAndVerdicts(stages); got != want {
		t.Fatalf("stages = %q, want %q\n%+v", got, want, stages)
	}
	dns := stages[0]
	if dns.RemediationCode != model.ErrDNSViaProxyWarn {
		t.Errorf("dns code = %s, want %s", dns.RemediationCode, model.ErrDNSViaProxyWarn)
	}
	if !strings.Contains(dns.Detail, "through the proxy") || !strings.Contains(dns.Detail, "no such host") {
		t.Errorf("dns detail should explain the proxy fallback and keep the lookup error, got %q", dns.Detail)
	}
	for _, s := range stages {
		if strings.Contains(s.Detail, proxyPassword) || strings.Contains(s.Detail, "trainee") {
			t.Errorf("stage %s leaks proxy credentials: %q", s.Name, s.Detail)
		}
	}
	if len(result.TLS) != 1 || result.TLS[0].Host != host {
		t.Errorf("expected one TLS info entry for %s, got %+v", host, result.TLS)
	}

	targets, authSeen := proxy.seen()
	if len(targets) == 0 {
		t.Fatal("proxy saw no CONNECT requests")
	}
	for _, target := range targets {
		if target != host+":443" {
			t.Errorf("proxy CONNECT target = %q, want %q (by name, not a locally resolved IP)", target, host+":443")
		}
	}
	if !authSeen {
		t.Error("expected Basic proxy credentials on the CONNECT request")
	}

	overall := report.BuildOverall(stages, nil)
	if overall.Verdict != model.VerdictWarn || overall.FailingStage != "" {
		t.Errorf("overall = %+v, want WARN with no failing stage", overall)
	}
	if code := report.ExitCodeFor(model.Result{Stages: stages, Overall: overall}); code != model.ExitOK {
		t.Errorf("exit code = %d, want %d", code, model.ExitOK)
	}

	line := report.StageLine(dns)
	if !strings.HasPrefix(line, "[WARN]") || strings.Contains(line, "DNS resolution failed") {
		t.Errorf("dns stage line should read as a proxy-fallback WARN, got %q", line)
	}
	notes := report.Notes(model.Result{Stages: stages, Overall: overall})
	if !strings.Contains(notes, string(model.ErrDNSViaProxyWarn)) || strings.Contains(notes, "Try a different network") {
		t.Errorf("notes should carry the proxy-fallback advice, not the DNS_FAIL advice, got %q", notes)
	}
}

// helperEnv marks a child test process started by runWithProxyEnv.
const helperEnv = "PREFLIGHT_TEST_HOSTSTAGES_HELPER"

// runWithProxyEnv re-runs the named test in a child process whose proxy
// environment contains only extraEnv. A child is needed because
// net/http reads the proxy environment once per process, so neither the
// developer's own proxy settings nor another test's can be swapped in place.
func runWithProxyEnv(t *testing.T, extraEnv ...string) {
	t.Helper()
	var env []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		switch strings.ToUpper(name) {
		case "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "REQUEST_METHOD":
			continue
		}
		env = append(env, kv)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v")
	cmd.Env = append(append(env, helperEnv+"=1"), extraEnv...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child test failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "--- PASS: "+t.Name()) {
		t.Fatalf("child test did not run:\n%s", out)
	}
}

func assertDNSFailAndSkips(t *testing.T, host string) {
	t.Helper()
	cfg := &config.Config{Target: hostset.Target{ClusterID: "test-cluster"}}
	var result model.Result
	var stages []model.Stage
	runHostStages(context.Background(), http.DefaultClient, nil, cfg, host, &result, func(s model.Stage) { stages = append(stages, s) })

	want := "dns=FAIL tcp=SKIP tls=SKIP alpn=SKIP status=SKIP"
	if got := stageNamesAndVerdicts(stages); got != want {
		t.Fatalf("stages = %q, want %q", got, want)
	}
	if stages[0].RemediationCode != model.ErrDNSFail {
		t.Errorf("dns code = %s, want %s", stages[0].RemediationCode, model.ErrDNSFail)
	}
	if overall := report.BuildOverall(stages, nil); overall.Verdict != model.VerdictFail || overall.FailingStage != "dns" {
		t.Errorf("overall = %+v, want FAIL at dns", overall)
	}
}

// Without any proxy, a DNS failure still blocks the host: FAIL and skip the rest.
func TestRunHostStages_DNSFailWithoutProxyStops(t *testing.T) {
	if os.Getenv(helperEnv) == "" {
		runWithProxyEnv(t)
		return
	}
	stubFailingDNS(t)
	assertDNSFailAndSkips(t, "api.example.com")
}

// A host exempted by NO_PROXY is reached directly, so a DNS failure for it
// still blocks it, even though a proxy is configured for everything else.
func TestRunHostStages_DNSFailNoProxyExemptStops(t *testing.T) {
	if os.Getenv(helperEnv) == "" {
		runWithProxyEnv(t, "HTTPS_PROXY=http://127.0.0.1:9", "NO_PROXY=api.example.com")
		return
	}
	if p, _ := checks.ResolveProxyForHost("https://zeebe.example.com", ""); p == nil {
		t.Fatal("test setup: expected the environment proxy to apply to a non-exempt host")
	}
	stubFailingDNS(t)
	assertDNSFailAndSkips(t, "api.example.com")
}
