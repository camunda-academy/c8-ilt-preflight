package launcher

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"c8preflight/internal/model"
)

// count returns how many env lines start with name= (case-insensitive).
func count(env []string, name string) []string {
	var vals []string
	for _, e := range env {
		if strings.HasPrefix(strings.ToUpper(e), strings.ToUpper(name)+"=") {
			vals = append(vals, e)
		}
	}
	return vals
}

// TestProbeEnv_ExplicitFlagsOverrideInherited guards against flag-set config
// (--proxy, --trust-ca, --host) failing to propagate to Layer 2 probes: a run
// using those flags must not route Layer 1 one way while the probes read a
// partial/inherited environment and test a different target/path (a
// false-green). probeEnv must translate each into its env var and drop any
// inherited copy so the explicit flag wins.
func TestProbeEnv_ExplicitFlagsOverrideInherited(t *testing.T) {
	// Inherited (differently-cased) values that must all be dropped.
	t.Setenv("HTTPS_PROXY", "http://inherited:9999")
	t.Setenv("http_proxy", "http://inherited:9999")
	t.Setenv("CAMUNDA_MTLS_CA_PATH", "/inherited/ca.pem")
	t.Setenv("CAMUNDA_REST_ADDRESS", "https://inherited.api.camunda.io/xxx")

	env := probeEnv(ProbeConfig{
		Mode:          "network",
		RESTAddress:   "https://bru-2.api.camunda.io/CID",
		ExplicitProxy: "http://localhost:8080",
		CACertPath:    "/tmp/mitm.pem",
	})

	if got := count(env, "CAMUNDA_PREFLIGHT_MODE"); len(got) != 1 || got[0] != "CAMUNDA_PREFLIGHT_MODE=network" {
		t.Errorf("mode = %v, want [CAMUNDA_PREFLIGHT_MODE=network]", got)
	}
	for name, want := range map[string]string{
		"HTTPS_PROXY": "HTTPS_PROXY=http://localhost:8080",
		"HTTP_PROXY":  "HTTP_PROXY=http://localhost:8080",
		// --trust-ca must reach the Java probe too: it reads CAMUNDA_CA_CERTIFICATE_PATH,
		// not CAMUNDA_MTLS_CA_PATH -- forwarding only one name makes the Java
		// probe warn about its own wrong-var-name mismatch check even though
		// the operator used our single --trust-ca flag.
		"CAMUNDA_MTLS_CA_PATH":        "CAMUNDA_MTLS_CA_PATH=/tmp/mitm.pem",
		"CAMUNDA_CA_CERTIFICATE_PATH": "CAMUNDA_CA_CERTIFICATE_PATH=/tmp/mitm.pem",
		"CAMUNDA_REST_ADDRESS":        "CAMUNDA_REST_ADDRESS=https://bru-2.api.camunda.io/CID",
	} {
		got := count(env, name)
		if len(got) != 1 || got[0] != want {
			t.Errorf("%s = %v, want exactly [%s] (inherited must be dropped)", name, got, want)
		}
	}
}

// TestProbeEnv_StripsCredsInNetworkMode guards network mode's credential-free
// guarantee: a probe must never inherit the client secret/id from the parent
// environment.
func TestProbeEnv_StripsCredsInNetworkMode(t *testing.T) {
	t.Setenv("CAMUNDA_CLIENT_SECRET", "should-not-reach-probe")
	t.Setenv("CAMUNDA_CLIENT_ID", "should-not-reach-probe")
	t.Setenv("CAMUNDA_CLIENT_AUTH_CLIENTSECRET", "alias-secret")

	env := probeEnv(ProbeConfig{Mode: "network"})
	for _, e := range env {
		up := strings.ToUpper(e)
		if strings.HasPrefix(up, "CAMUNDA_CLIENT_SECRET=") ||
			strings.HasPrefix(up, "CAMUNDA_CLIENT_ID=") ||
			strings.HasPrefix(up, "CAMUNDA_CLIENT_AUTH_CLIENTSECRET=") {
			t.Errorf("network-mode probe env still carries a credential var: %q", e)
		}
	}
}

// TestProbeEnv_KeepsCredsInFullMode confirms full-mode probes still get the
// credentials they legitimately need (the authenticated topology check).
func TestProbeEnv_KeepsCredsInFullMode(t *testing.T) {
	t.Setenv("CAMUNDA_CLIENT_SECRET", "needed-in-full-mode")
	env := probeEnv(ProbeConfig{Mode: "full"})
	found := false
	for _, e := range env {
		if e == "CAMUNDA_CLIENT_SECRET=needed-in-full-mode" {
			found = true
		}
	}
	if !found {
		t.Error("full-mode probe env should carry the client secret")
	}
}

// TestProbeEntrypoint_EmptyDirReturnsEmpty is the regression test for finding
// #6: an empty layer2Dir must NOT become a CWD-relative path that os.Stat/exec
// would resolve against the current directory.
func TestProbeEntrypoint_EmptyDirReturnsEmpty(t *testing.T) {
	if got := probeEntrypoint("", "java"); got != "" {
		t.Errorf("probeEntrypoint(\"\", ...) = %q, want \"\" (never a CWD-relative path)", got)
	}
	if got := probeEntrypoint("   ", "java"); got != "" {
		t.Errorf("probeEntrypoint(blank, ...) = %q, want \"\"", got)
	}
}

// TestProbeEnv_VerboseForwarded confirms --verbose reaches probes as
// CAMUNDA_PREFLIGHT_VERBOSE=1 (so they surface the normalization notice), and
// is absent otherwise (default: hidden from participants).
func TestProbeEnv_VerboseForwarded(t *testing.T) {
	on := probeEnv(ProbeConfig{Mode: "network", Verbose: true})
	if got := count(on, "CAMUNDA_PREFLIGHT_VERBOSE"); len(got) != 1 || got[0] != "CAMUNDA_PREFLIGHT_VERBOSE=1" {
		t.Errorf("verbose on: got %v, want [CAMUNDA_PREFLIGHT_VERBOSE=1]", got)
	}
	off := probeEnv(ProbeConfig{Mode: "network", Verbose: false})
	if got := count(off, "CAMUNDA_PREFLIGHT_VERBOSE"); len(got) != 0 {
		t.Errorf("verbose off: got %v, want none", got)
	}
}

// TestProbeEnv_JavaTrustStoreForwarded confirms --java-truststore/password
// reach the probe as CAMUNDA_JAVA_TRUSTSTORE(_PASSWORD), and any inherited
// copy is dropped when the flag wasn't given (same precedence as --trust-ca).
func TestProbeEnv_JavaTrustStoreForwarded(t *testing.T) {
	t.Setenv("CAMUNDA_JAVA_TRUSTSTORE", "/inherited/truststore.jks")
	t.Setenv("CAMUNDA_JAVA_TRUSTSTORE_PASSWORD", "inherited-pw")

	env := probeEnv(ProbeConfig{
		Mode:                   "network",
		JavaTrustStorePath:     "/tmp/custom-truststore.jks",
		JavaTrustStorePassword: "changeit",
	})
	for name, want := range map[string]string{
		"CAMUNDA_JAVA_TRUSTSTORE":          "CAMUNDA_JAVA_TRUSTSTORE=/tmp/custom-truststore.jks",
		"CAMUNDA_JAVA_TRUSTSTORE_PASSWORD": "CAMUNDA_JAVA_TRUSTSTORE_PASSWORD=changeit",
	} {
		got := count(env, name)
		if len(got) != 1 || got[0] != want {
			t.Errorf("%s = %v, want exactly [%s] (inherited must be dropped)", name, got, want)
		}
	}
}

// TestProbeEnv_JavaTrustStoreWinsOverCACertPath guards against a real conflict:
// --trust-ca is forwarded to Java too (as CAMUNDA_CA_CERTIFICATE_PATH), which
// always wins over -Djavax.net.ssl.trustStore in Java's own code, silently
// defeating --java-truststore even though the operator explicitly asked for
// both (--trust-ca for Go/Python/TS, --java-truststore for Java). When
// JavaTrustStorePath is set, CAMUNDA_CA_CERTIFICATE_PATH must be absent
// entirely -- both the forwarded --trust-ca value AND any copy inherited from
// the operator's shell (e.g. a stray env var left over from an earlier run,
// with no --trust-ca flag in sight) -- while CAMUNDA_MTLS_CA_PATH
// (Go/Python/TS's name) still carries --trust-ca normally.
func TestProbeEnv_JavaTrustStoreWinsOverCACertPath(t *testing.T) {
	t.Setenv("CAMUNDA_CA_CERTIFICATE_PATH", "/inherited/stray-ca.pem")

	env := probeEnv(ProbeConfig{
		Mode:               "network",
		CACertPath:         "/tmp/mitmproxy-ca.pem",
		JavaTrustStorePath: "/tmp/custom-truststore.jks",
	})
	if got := count(env, "CAMUNDA_CA_CERTIFICATE_PATH"); len(got) != 0 {
		t.Errorf("CAMUNDA_CA_CERTIFICATE_PATH = %v, want none (must not win over --java-truststore, forwarded or inherited)", got)
	}
	if got := count(env, "CAMUNDA_MTLS_CA_PATH"); len(got) != 1 || got[0] != "CAMUNDA_MTLS_CA_PATH=/tmp/mitmproxy-ca.pem" {
		t.Errorf("CAMUNDA_MTLS_CA_PATH = %v, want [CAMUNDA_MTLS_CA_PATH=/tmp/mitmproxy-ca.pem] (--trust-ca must still reach Go/Python/TS)", got)
	}
	if got := count(env, "CAMUNDA_JAVA_TRUSTSTORE"); len(got) != 1 || got[0] != "CAMUNDA_JAVA_TRUSTSTORE=/tmp/custom-truststore.jks" {
		t.Errorf("CAMUNDA_JAVA_TRUSTSTORE = %v, want [CAMUNDA_JAVA_TRUSTSTORE=/tmp/custom-truststore.jks]", got)
	}
}

// TestProbeEnv_MavenDepcheckForwarded confirms the --maven-* config reaches the
// Java depcheck sub-probe via env, and the boolean opt-ins only appear when set.
func TestProbeEnv_MavenDepcheckForwarded(t *testing.T) {
	on := probeEnv(ProbeConfig{
		Mode:             "network",
		MavenDepcheck:    true,
		MavenMirror:      "https://nexus.corp/repo",
		MavenSettings:    "/tmp/settings.xml",
		MavenCentralOnly: true,
	})
	for name, want := range map[string]string{
		"CAMUNDA_MAVEN_DEPCHECK":     "CAMUNDA_MAVEN_DEPCHECK=1",
		"CAMUNDA_MAVEN_MIRROR":       "CAMUNDA_MAVEN_MIRROR=https://nexus.corp/repo",
		"CAMUNDA_MAVEN_SETTINGS":     "CAMUNDA_MAVEN_SETTINGS=/tmp/settings.xml",
		"CAMUNDA_MAVEN_CENTRAL_ONLY": "CAMUNDA_MAVEN_CENTRAL_ONLY=1",
	} {
		got := count(on, name)
		if len(got) != 1 || got[0] != want {
			t.Errorf("%s = %v, want [%s]", name, got, want)
		}
	}
	// Off by default: no depcheck env vars leak when nothing is set.
	off := probeEnv(ProbeConfig{Mode: "network"})
	for _, name := range []string{"CAMUNDA_MAVEN_DEPCHECK", "CAMUNDA_MAVEN_CENTRAL_ONLY"} {
		if got := count(off, name); len(got) != 0 {
			t.Errorf("%s should be absent by default, got %v", name, got)
		}
	}
}

// TestProbeEnv_EmptyKnobsLeaveInheritedIntact confirms that a knob left empty
// (no flag given) preserves the inherited env var — so env-var-configured
// proxies/CA/host still reach the probe.
func TestProbeEnv_EmptyKnobsLeaveInheritedIntact(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://corp-proxy:8080")
	t.Setenv("CAMUNDA_MTLS_CA_PATH", "/corp/ca.pem")
	env := probeEnv(ProbeConfig{Mode: "full"}) // no proxy/ca/host overrides
	for _, want := range []string{"HTTPS_PROXY=http://corp-proxy:8080", "CAMUNDA_MTLS_CA_PATH=/corp/ca.pem"} {
		found := false
		for _, e := range env {
			if e == want {
				found = true
			}
		}
		if !found {
			t.Errorf("inherited %q should be preserved when the knob is empty", want)
		}
	}
}

// TestParseFragments_MultipleLines confirms the launcher contract's multi-
// fragment case: a probe MAY emit several newline-delimited fragments on
// stdout (e.g. java's trust probe + depcheck sub-probe). Both must survive
// into the merged result.
func TestParseFragments_MultipleLines(t *testing.T) {
	stdout := `{"runtime":"java","trustStoreExercised":"cacerts","target":"bru-2.api.camunda.io:443","verdict":"PASS","errorClass":"OK","detail":"trusted"}
{"runtime":"java","trustStoreExercised":"maven-central","target":"repo.maven.apache.org","verdict":"FAIL","errorClass":"MAVEN_MIRROR_UNREACHABLE","detail":"mirror down"}`

	frags := parseFragments(stdout)
	if len(frags) != 2 {
		t.Fatalf("got %d fragments, want 2: %+v", len(frags), frags)
	}
	if frags[0].Verdict != model.VerdictPass || frags[0].Target != "bru-2.api.camunda.io:443" {
		t.Errorf("fragment 0 = %+v, want the trust-probe fragment", frags[0])
	}
	if frags[1].ErrorClass != model.ErrMavenMirrorUnreach {
		t.Errorf("fragment 1 = %+v, want MAVEN_MIRROR_UNREACHABLE", frags[1])
	}
}

func TestParseFragments_SingleLine(t *testing.T) {
	stdout := `{"runtime":"python","trustStoreExercised":"certifi","target":"login.cloud.camunda.io:443","verdict":"PASS","errorClass":"OK","detail":"trusted"}`
	frags := parseFragments(stdout)
	if len(frags) != 1 {
		t.Fatalf("got %d fragments, want 1", len(frags))
	}
	if frags[0].Runtime != "python" {
		t.Errorf("Runtime = %q, want python", frags[0].Runtime)
	}
}

// TestParseFragmentLine covers the per-line helper invokeProbes' streaming
// path calls directly -- factored out of parseFragments so a fragment can be
// classified line-by-line as a probe subprocess produces output, instead of
// only after collecting the whole stdout buffer at process exit.
func TestParseFragmentLine(t *testing.T) {
	valid := `{"runtime":"python","trustStoreExercised":"certifi","target":"a:443","verdict":"PASS","errorClass":"OK","detail":"ok"}`
	if frag, ok := parseFragmentLine(valid); !ok || frag.Runtime != "python" {
		t.Errorf("valid line: got frag=%+v ok=%v, want a parsed python fragment", frag, ok)
	}
	if _, ok := parseFragmentLine("   "); ok {
		t.Error("blank line should not parse as a fragment")
	}
	if _, ok := parseFragmentLine("not json"); ok {
		t.Error("garbage line should not parse as a fragment")
	}
	if _, ok := parseFragmentLine(`{"trustStoreExercised":"certifi"}`); ok {
		t.Error("JSON missing runtime should not parse as a fragment")
	}
}

// TestInvokeProbes_StreamsFragmentsViaCallback guards against Layer 2 results
// only printing after the ENTIRE probe subprocess exits (multi-minute for the
// Maven depcheck), unlike Layer 1's per-stage streaming. Confirms onFragment
// is called once per fragment line the probe emits, and the aggregated return
// value matches what was streamed.
func TestInvokeProbes_StreamsFragmentsViaCallback(t *testing.T) {
	entry := writeTestProbe(t,
		`{"runtime":"java","trustStoreExercised":"cacerts","target":"a:443","verdict":"PASS","errorClass":"OK","detail":"one"}`,
		`{"runtime":"java","trustStoreExercised":"","target":"maven-dependency-resolution","verdict":"SKIP","errorClass":"OK","detail":"two"}`,
	)

	var streamed []model.ProbeFragment
	frags := invokeProbes(context.Background(), "java", entry, ProbeConfig{Mode: "network"}, func(f model.ProbeFragment) {
		streamed = append(streamed, f)
	})

	if len(frags) != 2 {
		t.Fatalf("got %d returned fragments, want 2: %+v", len(frags), frags)
	}
	if len(streamed) != 2 {
		t.Fatalf("got %d streamed (callback) fragments, want 2: %+v", len(streamed), streamed)
	}
	if streamed[0].Detail != "one" || streamed[1].Detail != "two" {
		t.Errorf("streamed fragments out of order or wrong content: %+v", streamed)
	}
}

// writeTestProbe writes a minimal standalone probe entrypoint (matching the
// real run.sh/run.cmd convention: one JSON fragment per line on stdout) that
// invokeProbes can exec directly, and returns its path.
func writeTestProbe(t *testing.T, lines ...string) string {
	t.Helper()
	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		path := filepath.Join(dir, "run.cmd")
		script := "@echo off\r\n"
		for _, l := range lines {
			script += "echo " + l + "\r\n"
		}
		if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	path := filepath.Join(dir, "run.sh")
	script := "#!/bin/sh\n"
	for _, l := range lines {
		script += "echo '" + l + "'\n"
	}
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestParseFragments_SkipsBlankAndInvalidLines confirms a probe can print
// incidental progress text on stdout (or blank lines) without corrupting
// the fragments that follow, as long as each fragment is on its own line.
func TestParseFragments_SkipsBlankAndInvalidLines(t *testing.T) {
	stdout := "starting probe...\n\n" +
		`{"runtime":"python","trustStoreExercised":"certifi","target":"a:443","verdict":"PASS","errorClass":"OK","detail":"ok"}` +
		"\nnot json at all\n"

	frags := parseFragments(stdout)
	if len(frags) != 1 {
		t.Fatalf("got %d fragments, want 1 (progress text and garbage should be skipped): %+v", len(frags), frags)
	}
}

// TestParseFragments_NoValidFragment_ReturnsEmpty confirms the caller
// (invokeProbes) sees an empty slice — not a fabricated fragment — when
// nothing parseable was found, so it can apply the exit-code-classification
// fallback exactly once.
func TestParseFragments_NoValidFragment_ReturnsEmpty(t *testing.T) {
	frags := parseFragments("garbage\nmore garbage\n")
	if len(frags) != 0 {
		t.Fatalf("got %d fragments, want 0", len(frags))
	}
}

func TestParseFragments_RequiresNonEmptyRuntime(t *testing.T) {
	// A syntactically valid JSON object with no "runtime" field must not be
	// accepted as a fragment — Runtime is how the launcher/report layer
	// identifies which probe produced it.
	stdout := `{"trustStoreExercised":"certifi","target":"a:443","verdict":"PASS","errorClass":"OK","detail":"ok"}`
	frags := parseFragments(stdout)
	if len(frags) != 0 {
		t.Fatalf("got %d fragments, want 0 (missing runtime field)", len(frags))
	}
}
