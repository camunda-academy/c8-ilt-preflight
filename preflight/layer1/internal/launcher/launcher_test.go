package launcher

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"

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

// TestProbeEntrypoint_EmptyDirReturnsEmpty guards against a real security bug:
// an empty layer2Dir must NOT become a CWD-relative path that os.Stat/exec
// would resolve against the current directory, which would let a planted
// script in an untrusted working directory get executed.
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

// TestInvokeProbes_PartialRunIsNotSilentlyGreen guards against the worst
// failure mode this tool can have: reporting success for a stack that was only
// half-checked. A run script runs several tiers and exits non-zero if any of
// them failed, but a tier whose compile/build step dies emits NO fragment at
// all — only stderr. Since a probe exits non-zero only when it emitted a
// FAIL/probe-error fragment, a non-zero exit with nothing failing among the
// parsed fragments means exactly that, and must not be swallowed.
//
// Reproduces a real field report: the C# stack's mandatory trust tier failed to
// build, its optional SDK tier cleanly SKIPped, and the run printed
// "All checks passed."
func TestInvokeProbes_PartialRunIsNotSilentlyGreen(t *testing.T) {
	entry := writeTestProbeExit(t, 1, "dotnet build of Probe.csproj failed",
		`{"runtime":"csharp","trustStoreExercised":"","target":"sdk","verdict":"SKIP","errorClass":"OK","detail":"not resolved"}`,
	)

	var streamed []model.ProbeFragment
	frags := invokeProbes(context.Background(), "csharp", entry, ProbeConfig{Mode: "network"}, func(f model.ProbeFragment) {
		streamed = append(streamed, f)
	})

	if len(frags) != 2 {
		t.Fatalf("got %d fragments, want 2 (the SKIP plus a synthesized probe-error): %+v", len(frags), frags)
	}
	got := frags[1]
	if got.Verdict != model.VerdictProbeError || got.ErrorClass != model.ErrProbeCrashed {
		t.Errorf("synthesized fragment: got verdict=%q errorClass=%q, want probe-error/PROBE_CRASHED", got.Verdict, got.ErrorClass)
	}
	if got.Runtime != "csharp" {
		t.Errorf("synthesized fragment runtime: got %q, want %q", got.Runtime, "csharp")
	}
	if !strings.Contains(got.Detail, "dotnet build of Probe.csproj failed") {
		t.Errorf("synthesized fragment must carry the probe's stderr so the failure is diagnosable; got detail: %q", got.Detail)
	}
	// The whole point is that the operator SEES it, not just that it lands in
	// the returned slice.
	if len(streamed) != 2 {
		t.Fatalf("got %d streamed fragments, want 2: %+v", len(streamed), streamed)
	}
}

// TestInvokeProbes_CleanFailNotDoubleReported is the other half of the guard
// above: a probe that exits non-zero BECAUSE it correctly reported a FAIL has
// already accounted for its exit code, so no extra probe-error may be invented
// on top of it.
func TestInvokeProbes_CleanFailNotDoubleReported(t *testing.T) {
	entry := writeTestProbeExit(t, 1, "",
		`{"runtime":"python","trustStoreExercised":"certifi","target":"a:443","verdict":"FAIL","errorClass":"TLS_HANDSHAKE_FAIL","detail":"untrusted"}`,
	)

	frags := invokeProbes(context.Background(), "python", entry, ProbeConfig{Mode: "network"}, nil)

	if len(frags) != 1 {
		t.Fatalf("got %d fragments, want exactly 1 (the FAIL, with nothing synthesized): %+v", len(frags), frags)
	}
	if frags[0].Verdict != model.VerdictFail {
		t.Errorf("got verdict %q, want FAIL", frags[0].Verdict)
	}
}

// TestDetectRuntime_PinnedMissingNeverFallsBackToPath locks in the whole point
// of pinning: if the operator names an installation and it can't be used, the
// run must say so, NOT quietly check whatever PATH offers instead. A fallback
// here would report a different JDK/interpreter's trust store as though it were
// the requested one.
func TestDetectRuntime_PinnedMissingNeverFallsBackToPath(t *testing.T) {
	st := DetectRuntime("java", RuntimeOverrides{JavaHome: filepath.Join(t.TempDir(), "no-such-jdk")})

	if st.Present {
		t.Error("a pinned JDK that does not exist must not be reported present")
	}
	if !st.Pinned {
		t.Error("status must record that this came from an explicit pin, so the message can say so")
	}
	if st.UnusableReason == "" {
		t.Error("must explain why the pin was unusable")
	}
	if st.BinaryFound != "" {
		t.Errorf("must not resolve some other binary as a fallback; got %q", st.BinaryFound)
	}
}

// TestDetectRuntime_RejectsBinaryThatIsNotTheRuntime covers the Windows
// python3.exe App Execution Alias: a file that exists on PATH, is executable,
// and is not Python — it exits non-zero telling you to install from the Store.
// Presence on disk therefore cannot be the test; the candidate has to identify
// itself successfully or it doesn't count.
func TestDetectRuntime_RejectsBinaryThatIsNotTheRuntime(t *testing.T) {
	fake := writeFakeBinary(t, "python3", 49, "Python was not found; run without arguments to install from the Microsoft Store")

	st := DetectRuntime("python", RuntimeOverrides{PythonBin: fake})

	if st.Present {
		t.Error("a binary that fails to identify itself must not count as the runtime present")
	}
	if st.UnusableReason == "" {
		t.Error("must explain that the binary exists but is not a working runtime")
	}
}

// TestDetectRuntime_PinnedRuntimeIsUsed is the positive case: a pinned binary
// that answers normally is used, recorded, and marked as explicitly selected.
func TestDetectRuntime_PinnedRuntimeIsUsed(t *testing.T) {
	fake := writeFakeBinary(t, "python", 0, "Python 3.11.9")

	st := DetectRuntime("python", RuntimeOverrides{PythonBin: fake})

	if !st.Present || !st.Pinned {
		t.Fatalf("pinned working runtime should be present and marked pinned; got %+v", st)
	}
	if st.Version != "Python 3.11.9" {
		t.Errorf("version = %q, want the binary's self-reported first line", st.Version)
	}
}

func TestUnderDir(t *testing.T) {
	base := t.TempDir()
	if !underDir(filepath.Join(base, "bin", "java"), base) {
		t.Error("a path inside the directory should be reported as under it")
	}
	if underDir(filepath.Join(base, "..", "elsewhere", "java"), base) {
		t.Error("a sibling path must not be reported as under the directory")
	}
}

// writeFakeBinary creates an executable that prints one line and exits with the
// given code — a stand-in for a runtime (or, with a non-zero code, for a
// lookalike that isn't one).
func writeFakeBinary(t *testing.T, name string, exitCode int, line string) string {
	t.Helper()
	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		path := filepath.Join(dir, name+".cmd")
		script := "@echo off\r\necho " + line + "\r\nexit /b " + fmt.Sprint(exitCode) + "\r\n"
		if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	path := filepath.Join(dir, name)
	script := "#!/bin/sh\necho '" + line + "'\nexit " + fmt.Sprint(exitCode) + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestInvokeProbes_CrashStderrTruncation guards the two properties a real
// field case exposed: a mandatory diagnostic field (a crashed probe's stderr,
// the ONLY evidence when a stack died before producing any result) was being
// cut at 300 bytes -- too short for build-tool errors, which routinely run
// long and put the useful part (which artifact, which file) past the first
// few hundred characters -- using a byte-slice truncation that could also
// split a multi-byte UTF-8 rune in half, which json.Marshal then silently
// mangles to a replacement character.
//
// The stderr content is constructed so a naive s[:4000] cuts exactly through
// the first byte of a 2-byte rune -- a truncation bug and an off-by-one in
// the boundary math would both show up as invalid UTF-8 here, not just a
// coincidentally-fine cut.
func TestInvokeProbes_CrashStderrTruncation(t *testing.T) {
	marker := "MARKER-PAST-OLD-300-CAP"
	padding := strings.Repeat("x", 3999-len(marker)) // marker+padding = 3999 bytes
	stderrText := marker + padding + "ä" + strings.Repeat("y", 500)

	dir := t.TempDir()
	stderrFile := filepath.Join(dir, "stderr.txt")
	if err := os.WriteFile(stderrFile, []byte(stderrText), 0o644); err != nil {
		t.Fatal(err)
	}

	var entry string
	if runtime.GOOS == "windows" {
		entry = filepath.Join(dir, "run.cmd")
		script := "@echo off\r\ntype \"" + stderrFile + "\" 1>&2\r\nexit /b 1\r\n"
		if err := os.WriteFile(entry, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	} else {
		entry = filepath.Join(dir, "run.sh")
		script := "#!/bin/sh\ncat \"" + stderrFile + "\" 1>&2\nexit 1\n"
		if err := os.WriteFile(entry, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// No stdout at all -- exercises the zero-fragment fallback path, the
	// other of the two stderr-embedding call sites this test covers.
	frags := invokeProbes(context.Background(), "csharp", entry, ProbeConfig{Mode: "network"}, nil)
	if len(frags) != 1 {
		t.Fatalf("got %d fragments, want 1 (the synthesized crash fragment): %+v", len(frags), frags)
	}
	got := frags[0].Detail

	if !utf8.ValidString(got) {
		t.Errorf("Detail is not valid UTF-8 -- truncation split a multi-byte rune: %q", got)
	}
	if strings.ContainsRune(got, utf8.RuneError) {
		t.Errorf("Detail contains a Unicode replacement character -- a byte sequence was corrupted: %q", got)
	}
	if !strings.Contains(got, marker) {
		t.Errorf("Detail lost content a 300-byte cap would have cut -- the raised limit isn't taking effect. Detail: %q", got)
	}
	if !strings.Contains(got, "(truncated)") {
		t.Error("Detail should still show the truncation marker -- the test's stderr is longer than the (generous) cap")
	}
}

// writeTestProbe writes a minimal standalone probe entrypoint (matching the
// real run.sh/run.cmd convention: one JSON fragment per line on stdout) that
// invokeProbes can exec directly, and returns its path.
func writeTestProbe(t *testing.T, lines ...string) string {
	t.Helper()
	return writeTestProbeExit(t, 0, "", lines...)
}

// writeTestProbeExit is writeTestProbe plus control over the entrypoint's exit
// code and one line of stderr, so the launcher's exit-code classification can
// be tested against the real run.sh/run.cmd shape.
func writeTestProbeExit(t *testing.T, exitCode int, stderrLine string, lines ...string) string {
	t.Helper()
	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		path := filepath.Join(dir, "run.cmd")
		script := "@echo off\r\n"
		for _, l := range lines {
			script += "echo " + l + "\r\n"
		}
		if stderrLine != "" {
			script += "echo " + stderrLine + " 1>&2\r\n"
		}
		script += fmt.Sprintf("exit /b %d\r\n", exitCode)
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
	if stderrLine != "" {
		script += "echo '" + stderrLine + "' >&2\n"
	}
	script += fmt.Sprintf("exit %d\n", exitCode)
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

// TestPinCandidates_AcceptsDirectoryOrBinary covers the usability trap that a
// pin is naturally a directory for some runtimes (a JDK home, a virtualenv) and
// a file for others (a node binary). Both must be accepted for every stack, and
// a directory has to expand to the layouts these installations really use --
// including Scripts/ for a Windows virtualenv, which is where a venv pin lands.
func TestPinCandidates_AcceptsDirectoryOrBinary(t *testing.T) {
	dir := t.TempDir()
	got := RuntimeOverrides{PythonBin: dir}.pinCandidates("python")
	if len(got) == 0 {
		t.Fatal("a directory pin must expand to candidate binaries, got none")
	}
	var sawBin, sawScripts bool
	for _, c := range got {
		if strings.Contains(c, string(filepath.Separator)+"bin"+string(filepath.Separator)) {
			sawBin = true
		}
		if strings.Contains(c, string(filepath.Separator)+"Scripts"+string(filepath.Separator)) {
			sawScripts = true
		}
	}
	if !sawBin || !sawScripts {
		t.Errorf("directory pin must cover POSIX bin/ and Windows Scripts/ virtualenv layouts; got %v", got)
	}

	// A path that isn't a directory is taken as the binary itself, unchanged.
	file := filepath.Join(dir, "node")
	if err := os.WriteFile(file, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := (RuntimeOverrides{NodeBin: file}).pinCandidates("typescript"); len(got) != 1 || got[0] != filepath.Clean(file) {
		t.Errorf("a binary pin should pass through unchanged; got %v", got)
	}
}

// TestDetectRuntime_DirectoryPinResolvesBinary is the end of that path: pointing
// at a directory finds the executable inside it.
func TestDetectRuntime_DirectoryPinResolvesBinary(t *testing.T) {
	home := t.TempDir()
	binDir := filepath.Join(home, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	name := "java"
	script := "#!/bin/sh\necho 'openjdk version \"17.0.1\"'\n"
	if runtime.GOOS == "windows" {
		name, script = "java.cmd", "@echo off\r\necho openjdk version \"17.0.1\"\r\n"
	}
	if err := os.WriteFile(filepath.Join(binDir, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	st := DetectRuntime("java", RuntimeOverrides{JavaHome: home})

	if !st.Present || !st.Pinned {
		t.Fatalf("directory pin should resolve to the binary under bin/; got %+v", st)
	}
	if !strings.Contains(st.Version, "17.0.1") {
		t.Errorf("version = %q, want it to carry 17.0.1", st.Version)
	}
}

// TestPinFailureReason_DistinguishesDirectoryFromMissing guards the message
// itself: reporting "file does not exist" for a directory that plainly does
// exist is what sent a real user looking in the wrong place.
func TestPinFailureReason_DistinguishesDirectoryFromMissing(t *testing.T) {
	dir := t.TempDir()
	got := pinFailureReason("csharp", dir, []string{filepath.Join(dir, "dotnet.exe")})
	if !strings.Contains(got, "is a directory") || !strings.Contains(got, "dotnet.exe") {
		t.Errorf("a directory pin must be named as such and list what was sought; got %q", got)
	}

	missing := filepath.Join(dir, "not-there")
	if got := pinFailureReason("csharp", missing, []string{missing}); !strings.Contains(got, "does not exist") {
		t.Errorf("a missing path should say so; got %q", got)
	}
}

// TestInheritedGlobalJSONWarning covers the C#-only case where the .NET tooling
// picks up an SDK pin from the working directory upward -- which routinely
// presents as "dotnet is broken", so the file has to be named.
func TestInheritedGlobalJSONWarning(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "global.json"), []byte(`{"sdk":{"version":"6.0.100"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// os.Chdir rather than t.Chdir: the module targets go1.22, and t.Chdir needs
	// 1.24 -- not worth raising the floor customers build against for a test.
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(sub); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })

	frag, ok := inheritedGlobalJSONWarning("csharp")
	if !ok {
		t.Fatal("a global.json above the working directory must be reported for csharp")
	}
	if frag.Verdict != model.VerdictWarn || frag.ErrorClass != model.ErrConfigError {
		t.Errorf("got %s/%s, want WARN/CONFIG_ERROR", frag.Verdict, frag.ErrorClass)
	}
	if !strings.Contains(frag.Detail, "global.json") {
		t.Errorf("detail must name the file; got %q", frag.Detail)
	}
	// Only C# reads global.json; warning other stacks would be noise.
	if _, ok := inheritedGlobalJSONWarning("java"); ok {
		t.Error("global.json is a .NET concern and must not be reported for java")
	}
}

// TestRun_MasksHomeDirInRuntimeDetail is the wiring test for MaskHomeDir: the
// pure function is tested directly in the redact package, but this proves
// Run() actually calls it before RuntimeDetail.Binary reaches the caller --
// the field that lands in the result JSON unconditionally, not just under
// --verbose. Reproduces the real shape a live run produced (a per-user
// install directory) rather than an synthetic path unlikely to occur.
func TestRun_MasksHomeDirInRuntimeDetail(t *testing.T) {
	home := filepath.Join(t.TempDir(), "Users", "realname")
	binDir := filepath.Join(home, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	binName := "python"
	binScript := "#!/bin/sh\necho 'Python 3.11.0'\n"
	if runtime.GOOS == "windows" {
		binName, binScript = "python.cmd", "@echo off\r\necho Python 3.11.0\r\n"
	}
	if err := os.WriteFile(filepath.Join(binDir, binName), []byte(binScript), 0o755); err != nil {
		t.Fatal(err)
	}

	layer2Dir := t.TempDir()
	stackDir := filepath.Join(layer2Dir, "python")
	if err := os.MkdirAll(stackDir, 0o755); err != nil {
		t.Fatal(err)
	}
	entryName, entryScript := "run.sh", "#!/bin/sh\necho '{\"runtime\":\"python\",\"trustStoreExercised\":\"\",\"target\":\"a\",\"verdict\":\"PASS\",\"errorClass\":\"OK\",\"detail\":\"ok\"}'\n"
	if runtime.GOOS == "windows" {
		entryName, entryScript = "run.cmd", "@echo off\r\necho {\"runtime\":\"python\",\"trustStoreExercised\":\"\",\"target\":\"a\",\"verdict\":\"PASS\",\"errorClass\":\"OK\",\"detail\":\"ok\"}\r\n"
	}
	if err := os.WriteFile(filepath.Join(stackDir, entryName), []byte(entryScript), 0o755); err != nil {
		t.Fatal(err)
	}

	_, _, runtimes, _ := Run(context.Background(), layer2Dir, []string{"python"}, true,
		ProbeConfig{Mode: "network", Runtimes: RuntimeOverrides{PythonBin: filepath.Join(binDir, binName)}}, nil)

	if len(runtimes) != 1 {
		t.Fatalf("got %d runtime details, want 1: %+v", len(runtimes), runtimes)
	}
	if strings.Contains(runtimes[0].Binary, "realname") {
		t.Errorf("RuntimeDetail.Binary leaked the real username: %q", runtimes[0].Binary)
	}
	if !strings.Contains(runtimes[0].Binary, "<redacted-user>") {
		t.Errorf("RuntimeDetail.Binary should carry the masked placeholder; got %q", runtimes[0].Binary)
	}
}
