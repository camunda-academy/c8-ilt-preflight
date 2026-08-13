package redact

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// TestScrub_MasksKnownSecrets guards streamed stdout: it must be scrubbed of
// secret material, since the file-writer refuse-to-emit guard doesn't cover
// the terminal. A server-reflected client secret (e.g. echoed in an OAuth
// error_description) must not survive into printed output.
func TestScrub_MasksKnownSecrets(t *testing.T) {
	s := Secrets{ClientSecret: "SUPER-SECRET-VALUE", AccessToken: "TOKEN-ABC-123"}

	in := "OAuth returned no valid access_token. Server said: bad secret SUPER-SECRET-VALUE for TOKEN-ABC-123"
	out := s.Scrub(in)

	if strings.Contains(out, "SUPER-SECRET-VALUE") {
		t.Error("Scrub left the client secret in the output")
	}
	if strings.Contains(out, "TOKEN-ABC-123") {
		t.Error("Scrub left the access token in the output")
	}
	if !strings.Contains(out, "****") {
		t.Error("Scrub should replace secrets with a mask")
	}
	if !strings.Contains(out, "OAuth returned no valid access_token") {
		t.Error("Scrub should leave non-secret text intact")
	}
}

// TestProxyPassword_CoveredBySelfCheckAndScrub guards that a proxy password
// is caught by ScanForLeak (refuse-to-emit on file writes) and masked by
// Scrub (stdout).
func TestProxyPassword_CoveredBySelfCheckAndScrub(t *testing.T) {
	s := Secrets{ProxyPassword: "pr0xy-pw"}
	if s.ScanForLeak("effective proxy http://user:pr0xy-pw@p:8080") == "" {
		t.Error("ScanForLeak should flag the proxy password")
	}
	if got := s.Scrub("proxy pr0xy-pw here"); strings.Contains(got, "pr0xy-pw") {
		t.Errorf("Scrub left the proxy password: %q", got)
	}
}

func TestScrub_EmptySecretsIsNoOp(t *testing.T) {
	s := Secrets{}
	in := "nothing secret here"
	if got := s.Scrub(in); got != in {
		t.Errorf("Scrub with no known secrets changed the text: %q", got)
	}
}

// TestScrub_DoesNotMaskShortEmptyToken guards against masking every empty
// string (strings.ReplaceAll with "" would insert masks everywhere).
func TestScrub_DoesNotMangleWhenOnlyOneSecretSet(t *testing.T) {
	s := Secrets{ClientSecret: "abc123def456"}
	out := s.Scrub("value abc123def456 end")
	if strings.Contains(out, "abc123def456") || !strings.Contains(out, "value") || !strings.Contains(out, "end") {
		t.Errorf("unexpected scrub result: %q", out)
	}
}

// A typo'd client id makes the OAuth server reflect it back in
// error_description; that text lands in a Stage.Detail which reaches BOTH
// stdout and the shareable result JSON, so it must be masked, not raw.
func TestScrub_MasksClientIDReflectedByServer(t *testing.T) {
	s := Secrets{ClientID: "abcd1234WXYZ"}
	reflected := "OAuth returned no valid access_token. Server said: client 'abcd1234WXYZ' not found"
	got := s.Scrub(reflected)
	if strings.Contains(got, "abcd1234WXYZ") {
		t.Fatalf("raw client id survived Scrub: %q", got)
	}
	if !strings.Contains(got, "abcd...WXYZ") {
		t.Fatalf("expected first4...last4 mask (diagnostically useful), got %q", got)
	}
}

// A client id is NOT a hard secret: it must be masked, never trigger the
// refuse-to-write guard (that would throw away the whole result over
// non-secret material).
func TestScanForLeak_ClientIDDoesNotBlockWriting(t *testing.T) {
	s := Secrets{ClientID: "abcd1234WXYZ", ClientSecret: "REAL-SECRET-VALUE"}
	if reason := s.ScanForLeak("mentions client abcd1234WXYZ only"); reason != "" {
		t.Fatalf("client id must not trip refuse-to-write, got %q", reason)
	}
	// ...but a real secret still must.
	if reason := s.ScanForLeak("oops REAL-SECRET-VALUE"); reason == "" {
		t.Fatal("client secret MUST still trip refuse-to-write")
	}
}

// Truncate is applied to server-controlled text that is often non-ASCII on a
// localized corporate proxy. A naive byte slice can split a multi-byte rune.
func TestTruncate_DoesNotSplitMultiByteRune(t *testing.T) {
	// Each 'ü' is 2 bytes, so a cut at an odd byte offset lands mid-rune.
	s := strings.Repeat("ü", 50)
	got := Truncate(s, 15)
	if !utf8.ValidString(got) {
		t.Fatalf("Truncate produced invalid UTF-8: %q", got)
	}
	if len(got) == 0 {
		t.Fatal("Truncate returned nothing")
	}
}

// TestMaskHomeDir covers the common case: a resolved binary
// path routinely runs through a per-user profile directory -- a pyenv/nvm
// install, a Windows Store App Execution Alias, a personal venv -- and that
// path is always in the result JSON, not just --verbose. 
func TestMaskHomeDir(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{
			"windows store alias",
			`C:\Users\jsmith\AppData\Local\Microsoft\WindowsApps\python3.exe`,
			`C:\Users\<redacted-user>\AppData\Local\Microsoft\WindowsApps\python3.exe`,
		},
		{"windows jdk home", `C:\Users\jsmith\.jdks\jdk-21\bin\java.exe`, `C:\Users\<redacted-user>\.jdks\jdk-21\bin\java.exe`},
		{"macos", `/Users/jsmith/.pyenv/versions/3.11/bin/python`, `/Users/<redacted-user>/.pyenv/versions/3.11/bin/python`},
		{"linux", `/home/jsmith/.nvm/versions/node/v22/bin/node`, `/home/<redacted-user>/.nvm/versions/node/v22/bin/node`},
		{"wsl", `/mnt/c/Users/jsmith/venv/Scripts/python.exe`, `/mnt/c/Users/<redacted-user>/venv/Scripts/python.exe`},
		{"no home dir segment", `C:\Program Files\dotnet\dotnet.exe`, `C:\Program Files\dotnet\dotnet.exe`},
		{"empty", "", ""},
	}
	for _, c := range cases {
		if got := MaskHomeDir(c.in); got != c.want {
			t.Errorf("%s: MaskHomeDir(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

// TestMaskProxyValue guards the two properties that actually matter: presence
// of a proxy is never hidden (an empty input must stay empty, or "no proxy"
// becomes indistinguishable from "a proxy, hidden"), and a non-empty value
// never leaks any part of the real host/IP into the placeholder.
func TestMaskProxyValue(t *testing.T) {
	if got := MaskProxyValue(""); got != "" {
		t.Errorf(`MaskProxyValue("") = %q, want "" -- absence of a proxy must not be masked`, got)
	}
	for _, raw := range []string{
		"http://proxy.internal.corp:8080",
		"10.20.30.40:3128",
		"http=proxy:80;https=proxy:8080",
	} {
		got := MaskProxyValue(raw)
		if got == raw {
			t.Errorf("MaskProxyValue(%q) returned the value unchanged", raw)
		}
		if strings.Contains(got, "proxy.internal.corp") || strings.Contains(got, "10.20.30.40") {
			t.Errorf("MaskProxyValue(%q) = %q leaked part of the real value", raw, got)
		}
	}
}
