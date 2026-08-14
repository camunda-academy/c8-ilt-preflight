package config

import (
	"flag"
	"io"
	"os"
	"strings"
	"testing"
)

// A syntactically valid but fake UUID — real cluster ids are never committed.
const testClusterID = "11111111-2222-4333-8444-555555555555"

// TestParse_HelpDoesNotLeakEnvCreds is a regression test guarding against a
// real leak: flag defaults populated from env vars would leak, since Go
// prints defaults in --help, so `preflight --help` would dump
// CAMUNDA_CLIENT_SECRET/ID whenever they were set. Defaults must be static;
// env is applied post-parse.
func TestParse_HelpDoesNotLeakEnvCreds(t *testing.T) {
	t.Setenv("CAMUNDA_CLIENT_ID", "LEAKY-CLIENT-ID-XYZ")
	t.Setenv("CAMUNDA_CLIENT_SECRET", "LEAKY-CLIENT-SECRET-XYZ")
	t.Setenv("CAMUNDA_REST_ADDRESS", "https://bru-2.api.camunda.io/LEAKY-CLUSTER-ID")

	// Flag usage is written to os.Stderr by default; capture it via a pipe,
	// draining it CONCURRENTLY in a goroutine. An OS pipe's buffer is finite,
	// so a write larger than the buffer blocks until something drains the
	// read end. Reading concurrently makes this correct regardless of how
	// large --help's output ever grows.
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	usageCh := make(chan string, 1)
	go func() {
		out, _ := io.ReadAll(r)
		usageCh <- string(out)
	}()
	_, err := Parse([]string{"-h"})
	w.Close()
	os.Stderr = old
	usage := <-usageCh

	if err != flag.ErrHelp {
		t.Fatalf("expected flag.ErrHelp from -h, got %v", err)
	}
	for _, secret := range []string{"LEAKY-CLIENT-ID-XYZ", "LEAKY-CLIENT-SECRET-XYZ", "LEAKY-CLUSTER-ID"} {
		if strings.Contains(usage, secret) {
			t.Errorf("--help output leaked %q — flag defaults must be static, not env-populated", secret)
		}
	}
}

// TestParse_RejectsFullModeWithInsecureFlag is the regression test asserting
// that full mode + --diagnostic-insecure-skip-verify would POST the client
// secret over an unverified TLS connection. Parse must refuse it.
func TestParse_RejectsFullModeWithInsecureFlag(t *testing.T) {
	_, err := Parse([]string{
		"--cluster-id", "11111111-2222-3333-4444-555555555555",
		"--client-id", "id", "--client-secret", "secret",
		"--mode", "full", "--diagnostic-insecure-skip-verify",
	})
	if err == nil {
		t.Fatal("expected an error for full mode + --diagnostic-insecure-skip-verify, got nil")
	}
	if !strings.Contains(err.Error(), "unverified TLS") {
		t.Errorf("error should explain the unverified-TLS credential risk, got: %v", err)
	}
}

// TestParse_RejectsUnknownStackUpFront is the regression test for the
// non-existent-vs-not-installed distinction: a typo'd runtime ("jav") must be
// rejected as a config error before any Go transport checks run, not reported
// downstream as a "runtime not installed" FAIL (which wrongly implies the fix
// is installing something rather than correcting the flag).
func TestParse_RejectsUnknownStackUpFront(t *testing.T) {
	_, err := Parse([]string{
		"--cluster-id", "11111111-2222-3333-4444-555555555555",
		"--mode", "network", "--stacks", "jav",
	})
	if err == nil {
		t.Fatal("expected a config error for an unknown --stacks value, got nil")
	}
	if !strings.Contains(err.Error(), "unknown --stacks value") {
		t.Errorf("error should name the unknown value, got: %v", err)
	}
	if !strings.Contains(err.Error(), `"java"`) {
		t.Errorf("error should suggest the close known runtime, got: %v", err)
	}
}

// TestParse_AcceptsKnownStacks confirms the validation doesn't reject a
// legitimate multi-stack selection.
func TestParse_AcceptsKnownStacks(t *testing.T) {
	cfg, err := Parse([]string{
		"--cluster-id", "11111111-2222-3333-4444-555555555555",
		"--mode", "network", "--stacks", "java,python",
	})
	if err != nil {
		t.Fatalf("valid --stacks should parse, got: %v", err)
	}
	if len(cfg.Stacks) != 2 || cfg.Stacks[0] != "java" || cfg.Stacks[1] != "python" {
		t.Errorf("stacks = %v, want [java python]", cfg.Stacks)
	}
}

// TestParse_TrustCAFlag confirms the current flag name resolves correctly.
func TestParse_TrustCAFlag(t *testing.T) {
	cfg, err := Parse([]string{"--cluster-id", testClusterID, "--trust-ca", "/tmp/corp-ca.pem"})
	if err != nil {
		t.Fatalf("--trust-ca should parse, got: %v", err)
	}
	if cfg.CustomCAPath != "/tmp/corp-ca.pem" {
		t.Errorf("CustomCAPath = %q, want /tmp/corp-ca.pem", cfg.CustomCAPath)
	}
}

// TestParse_LegacyCAFlagStillWorks is the regression test for the --ca ->
// --trust-ca rename: --ca must keep working, unchanged, as a deprecated
// alias so existing scripts/muscle memory don't break outright.
func TestParse_LegacyCAFlagStillWorks(t *testing.T) {
	cfg, err := Parse([]string{"--cluster-id", testClusterID, "--ca", "/tmp/corp-ca.pem"})
	if err != nil {
		t.Fatalf("--ca (legacy alias) should still parse, got: %v", err)
	}
	if cfg.CustomCAPath != "/tmp/corp-ca.pem" {
		t.Errorf("CustomCAPath = %q, want /tmp/corp-ca.pem", cfg.CustomCAPath)
	}
}

// TestParse_TrustCAWinsOverLegacyCA confirms the current name takes priority
// if both are somehow given.
func TestParse_TrustCAWinsOverLegacyCA(t *testing.T) {
	cfg, err := Parse([]string{
		"--cluster-id", testClusterID,
		"--trust-ca", "/tmp/new.pem", "--ca", "/tmp/old.pem",
	})
	if err != nil {
		t.Fatalf("got error: %v", err)
	}
	if cfg.CustomCAPath != "/tmp/new.pem" {
		t.Errorf("CustomCAPath = %q, want /tmp/new.pem (--trust-ca must win over --ca)", cfg.CustomCAPath)
	}
}

// TestParse_MavenDepcheckRequiresJava guards against a no-op: the depcheck runs
// only inside the Java probe, so opting in without the java stack does nothing.
func TestParse_MavenDepcheckRequiresJava(t *testing.T) {
	_, err := Parse([]string{"--cluster-id", testClusterID, "--maven-depcheck", "--stacks", "python"})
	if err == nil {
		t.Fatal("expected an error for --maven-depcheck without the java stack, got nil")
	}
	if !strings.Contains(err.Error(), "java stack") {
		t.Errorf("error should explain it needs the java stack, got: %v", err)
	}
}

// TestParse_MavenDepcheckWithJava confirms the opt-in parses with java selected.
func TestParse_MavenDepcheckWithJava(t *testing.T) {
	cfg, err := Parse([]string{"--cluster-id", testClusterID, "--maven-depcheck", "--stacks", "java"})
	if err != nil {
		t.Fatalf("--maven-depcheck --stacks java should parse, got: %v", err)
	}
	if !cfg.MavenDepcheck {
		t.Error("MavenDepcheck should be true")
	}
}

// TestParse_MavenMirrorImpliesDepcheck confirms providing --maven-mirror turns
// the check on without a separate --maven-depcheck.
func TestParse_MavenMirrorImpliesDepcheck(t *testing.T) {
	cfg, err := Parse([]string{
		"--cluster-id", testClusterID, "--stacks", "java",
		"--maven-mirror", "https://nexus.corp/repo",
	})
	if err != nil {
		t.Fatalf("got error: %v", err)
	}
	if !cfg.MavenDepcheck {
		t.Error("--maven-mirror should imply MavenDepcheck=true")
	}
	if cfg.MavenMirror != "https://nexus.corp/repo" {
		t.Errorf("MavenMirror = %q, want https://nexus.corp/repo", cfg.MavenMirror)
	}
}

// TestParse_SkipTransportRequiresRuntime guards against a false-green: with no
// --stacks/--auto, --skip-transport would run nothing yet report success.
func TestParse_SkipTransportRequiresRuntime(t *testing.T) {
	_, err := Parse([]string{
		"--cluster-id", "11111111-2222-3333-4444-555555555555",
		"--mode", "network", "--skip-transport",
	})
	if err == nil {
		t.Fatal("expected an error for --skip-transport without a runtime, got nil")
	}
	if !strings.Contains(err.Error(), "--skip-transport") {
		t.Errorf("error should explain --skip-transport needs a runtime, got: %v", err)
	}
}

// TestParse_SkipTransportWithStacks confirms the flag parses when a runtime is
// selected.
func TestParse_SkipTransportWithStacks(t *testing.T) {
	cfg, err := Parse([]string{
		"--cluster-id", "11111111-2222-3333-4444-555555555555",
		"--mode", "network", "--skip-transport", "--stacks", "python",
	})
	if err != nil {
		t.Fatalf("--skip-transport with --stacks should parse, got: %v", err)
	}
	if !cfg.SkipTransport {
		t.Error("SkipTransport should be set")
	}
}

// TestParse_NetworkModeWithInsecureFlagIsAllowed confirms the flag is still
// usable for its legitimate purpose — transport/TLS debugging in network mode.
func TestParse_NetworkModeWithInsecureFlagIsAllowed(t *testing.T) {
	cfg, err := Parse([]string{
		"--cluster-id", "11111111-2222-3333-4444-555555555555",
		"--mode", "network", "--diagnostic-insecure-skip-verify",
	})
	if err != nil {
		t.Fatalf("network mode + insecure flag should be allowed, got: %v", err)
	}
	if !cfg.DiagnosticInsecureSkipVerify {
		t.Error("DiagnosticInsecureSkipVerify should be set")
	}
}

// TestParse_EnvStillAppliedAfterParse confirms the leak fix didn't break the
// documented precedence: env values are still picked up when no flag is
// passed. Mode is NOT auto-detected from credential presence: network is the
// hard default even with creds present in the environment, until --mode full
// is passed.
func TestParse_EnvStillAppliedAfterParse(t *testing.T) {
	t.Setenv("CAMUNDA_CLIENT_ID", "env-id")
	t.Setenv("CAMUNDA_CLIENT_SECRET", "env-secret")
	t.Setenv("CAMUNDA_REST_ADDRESS", "https://bru-2.api.camunda.io/11111111-2222-3333-4444-555555555555")

	cfg, err := Parse(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ClientID != "env-id" || cfg.ClientSecret != "env-secret" {
		t.Errorf("env creds not applied post-parse: id=%q secret set=%v", cfg.ClientID, cfg.ClientSecret != "")
	}
	if cfg.Mode != "network" {
		t.Errorf("expected network mode (no auto-detect from env creds), got %q", cfg.Mode)
	}
	if cfg.ModeExplicit {
		t.Error("expected ModeExplicit false when --mode was not passed")
	}
}

// TestParse_FullModeRequiresExplicitFlag is the regression test for the
// removed auto-detect: credentials alone (env or flags) must NOT switch the
// run into full mode -- only an explicit --mode full does.
func TestParse_FullModeRequiresExplicitFlag(t *testing.T) {
	t.Setenv("CAMUNDA_CLIENT_ID", "env-id")
	t.Setenv("CAMUNDA_CLIENT_SECRET", "env-secret")
	t.Setenv("CAMUNDA_REST_ADDRESS", "https://bru-2.api.camunda.io/11111111-2222-3333-4444-555555555555")

	cfg, err := Parse([]string{"--mode", "full"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Mode != "full" {
		t.Errorf("expected full mode when explicitly requested, got %q", cfg.Mode)
	}
	if !cfg.ModeExplicit {
		t.Error("expected ModeExplicit true when --mode full was passed")
	}
}

// TestParse_FlagWinsOverEnv confirms an explicit flag still overrides env.
func TestParse_FlagWinsOverEnv(t *testing.T) {
	t.Setenv("CAMUNDA_REST_ADDRESS", "https://bru-2.api.camunda.io/env-cluster")
	cfg, err := Parse([]string{"--host", "https://syd-1.api.camunda.io/11111111-2222-3333-4444-555555555555"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Target.Region != "syd-1" {
		t.Errorf("explicit --host should win over env; got target region %q (host %q)", cfg.Target.Region, cfg.Host)
	}
}

// TestParse_RejectsSOCKSProxy is a regression test guarding against a real
// gap: a --proxy socks5://... URL would otherwise be silently accepted, then
// the CONNECT-tunnel dialer would try to speak HTTP CONNECT to it — against
// a real SOCKS server that produces a confusing protocol-mismatch error
// instead of a clear "unsupported" message. Only http(s) proxy schemes are
// actually supported (no SOCKS, no NTLM/Negotiate).
func TestParse_RejectsSOCKSProxy(t *testing.T) {
	_, err := Parse([]string{"--cluster-id", testClusterID, "--proxy", "socks5://localhost:1080"})
	if err == nil {
		t.Fatal("expected an error for an unsupported SOCKS proxy scheme, got nil")
	}
	if !strings.Contains(err.Error(), "does not support") {
		t.Errorf("error should clearly say the scheme is unsupported, got: %v", err)
	}
}

func TestParse_AcceptsHTTPAndHTTPSProxy(t *testing.T) {
	for _, scheme := range []string{"http://localhost:8080", "https://localhost:8443"} {
		cfg, err := Parse([]string{"--cluster-id", testClusterID, "--proxy", scheme})
		if err != nil {
			t.Errorf("--proxy %q should be accepted, got error: %v", scheme, err)
		}
		if cfg != nil && cfg.ProxyURL != scheme {
			t.Errorf("ProxyURL = %q, want %q", cfg.ProxyURL, scheme)
		}
	}
}

func TestParse_NoProxyFlagIsFine(t *testing.T) {
	_, err := Parse([]string{"--cluster-id", testClusterID})
	if err != nil {
		t.Errorf("no --proxy flag at all should not error, got: %v", err)
	}
}

// TestParse_RejectsMissingJavaTrustStore is a regression test for a real JVM
// footgun: javax.net.ssl.trustStore silently falls back to the default
// cacerts when the named file doesn't exist (documented JSSE behavior, not an
// error) -- so a typo'd --java-truststore path would otherwise produce a
// quiet false PASS instead of a config error. Catch it here, loudly.
func TestParse_RejectsMissingJavaTrustStore(t *testing.T) {
	_, err := Parse([]string{"--cluster-id", testClusterID, "--java-truststore", "/no/such/file.jks"})
	if err == nil {
		t.Fatal("expected an error for a --java-truststore path that doesn't exist, got nil")
	}
	if !strings.Contains(err.Error(), "fails SILENTLY") {
		t.Errorf("error should explain the JVM's silent-fallback footgun, got: %v", err)
	}
}

// TestParse_AcceptsRealJavaTrustStore confirms a real file passes.
func TestParse_AcceptsRealJavaTrustStore(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "truststore-*.jks")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	cfg, err := Parse([]string{"--cluster-id", testClusterID, "--java-truststore", f.Name(), "--java-truststore-password", "changeit"})
	if err != nil {
		t.Fatalf("a real --java-truststore file should be accepted, got: %v", err)
	}
	if cfg.JavaTrustStorePath != f.Name() {
		t.Errorf("JavaTrustStorePath = %q, want %q", cfg.JavaTrustStorePath, f.Name())
	}
	if cfg.JavaTrustStorePassword != "changeit" {
		t.Errorf("JavaTrustStorePassword = %q, want %q", cfg.JavaTrustStorePassword, "changeit")
	}
}

// TestParse_RejectsJavaTrustStorePasswordWithoutPath guards a config mistake:
// a password with nothing to unlock.
func TestParse_RejectsJavaTrustStorePasswordWithoutPath(t *testing.T) {
	_, err := Parse([]string{"--cluster-id", testClusterID, "--java-truststore-password", "changeit"})
	if err == nil {
		t.Fatal("expected an error for --java-truststore-password without --java-truststore, got nil")
	}
	if !strings.Contains(err.Error(), "nothing to unlock") {
		t.Errorf("error should explain the password has nothing to unlock, got: %v", err)
	}
}

// TestParse_NoSDKInstall covers the one opt-OUT flag in the set: unlike the
// opt-in flags, its env form has to be able to turn the fetch off on its own,
// while an explicit flag still outranks the environment.
func TestParse_NoSDKInstall(t *testing.T) {
	base := []string{"--cluster-id", "11111111-2222-3333-4444-555555555555", "--region", "bru-2"}

	cfg, err := Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NoSDKInstall {
		t.Error("fetching the SDK must be the default, so NoSDKInstall should be false when nothing asks otherwise")
	}

	cfg, err = Parse(append([]string{"--no-sdk-install"}, base...))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.NoSDKInstall {
		t.Error("--no-sdk-install did not opt out")
	}

	for _, off := range []string{"0", "false", "FALSE", "no", "off"} {
		t.Setenv("CAMUNDA_SDK_AUTO_INSTALL", off)
		cfg, err = Parse(base)
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.NoSDKInstall {
			t.Errorf("CAMUNDA_SDK_AUTO_INSTALL=%q should opt out", off)
		}
	}

	// A truthy env value leaves the default alone rather than inverting it.
	t.Setenv("CAMUNDA_SDK_AUTO_INSTALL", "1")
	cfg, err = Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NoSDKInstall {
		t.Error("CAMUNDA_SDK_AUTO_INSTALL=1 should keep the fetch enabled")
	}
}
