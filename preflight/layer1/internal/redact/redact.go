// Package redact enforces the tool's redaction guarantee: nothing sensitive
// enters human output, the JSON result, or the verbose log — in any run mode.
package redact

import (
	"encoding/json"
	"regexp"
	"strings"
	"unicode/utf8"
)

// MaskID masks a client ID to first4...last4. Short IDs (<=8 chars) are fully
// masked so the mask itself can't leak the whole value.
func MaskID(id string) string {
	if len(id) <= 8 {
		return "****"
	}
	return id[:4] + "..." + id[len(id)-4:]
}

// homeDirPattern matches the username segment of a per-user home directory:
// \Users\<name> (Windows), /Users/<name> (macOS), /home/<name> (Linux). WSL
// paths (/mnt/c/Users/<name>) are covered too, since that's the same "Users"
// literal appearing later in the string.
var homeDirPattern = regexp.MustCompile(`(?i)([/\\](?:Users|home)[/\\])([^/\\]+)`)

// MaskHomeDir replaces the username segment of any home-directory path found
// in s, leaving the rest of the path intact.
//
// A resolved binary path routinely runs through a per-user profile directory —
// a pyenv/nvm install, `pip install --user`, a personal venv, a Downloads
// folder the tool itself was unzipped into — so printing it verbatim puts a
// participant's real name into a file this tool explicitly tells them to send
// to a third party (their training contact). The surrounding directory
// structure is still useful for diagnosis; only the identifying segment needs
// to go.
func MaskHomeDir(s string) string {
	return homeDirPattern.ReplaceAllString(s, "${1}<redacted-user>")
}

// MaskProxyValue replaces a non-empty proxy description with a placeholder
// that confirms a proxy exists without naming it.
//
// A detected proxy's hostname or IP reveals internal network naming/topology
// to whoever the result file ends up with (the training team, by design).
// Deliberately a fixed placeholder rather than a partial redaction: the raw
// value can be a full URL, a bare "host:port", or Windows' semicolon-separated
// per-protocol ProxyServer form, and no single parsing strategy handles all
// three without risking a partial value slipping through. The empty string
// (no proxy detected/configured) passes through unchanged -- that fact isn't
// sensitive, and masking it would make "no proxy" indistinguishable from "a
// proxy, hidden."
//
// The placeholder carries no parentheses or leading "configured" of its own —
// every call site already supplies that framing (a "Proxy: %s" line, a
// "configured (%s)" clause) — so it reads correctly wherever it's substituted
// in, masked or not.
func MaskProxyValue(s string) string {
	if s == "" {
		return s
	}
	return "hostname/IP hidden — re-run with --unmasked-hostnames to reveal it"
}

// Secrets holds the sensitive values known for the current run. The
// self-check scans final output for these before anything is written or
// printed, and refuses to emit if it finds any.
type Secrets struct {
	ClientSecret string
	AccessToken  string
	// ClientID is NOT a hard secret (it's semi-public identifying material),
	// so it is deliberately handled differently from the fields above: Scrub
	// MASKS it to first4...last4 rather than ScanForLeak refusing to write.
	// This matters because an OAuth server's own error_description can reflect
	// the client_id back at us (e.g. "client 'abc123' not found" on a typo'd
	// id) — that text lands in a Stage.Detail, which reaches BOTH stdout and
	// the shareable result JSON. Refusing to write the whole result over a
	// non-secret would be worse than masking it, hence the split treatment.
	ClientID string
	// ProxyPassword is the password from a --proxy/HTTP(S)_PROXY userinfo, if
	// any. It's a real secret on many corporate networks and must not leak
	// into output, even though no current code path prints it —
	// defense-in-depth.
	ProxyPassword string
	// JavaTrustStorePassword is --java-truststore-password / CAMUNDA_JAVA_TRUSTSTORE_PASSWORD.
	// Never printed by any current code path, but if a Java probe's own error
	// text ever echoed a keystore-load exception verbatim, this stops it
	// carrying the password — same defense-in-depth reasoning as ProxyPassword.
	JavaTrustStorePassword string
}

// jsonEscaped returns how s appears once encoded into a JSON string value.
//
// This matters because the leak scan runs against ALREADY-MARSHALLED JSON.
// encoding/json escapes `"` and `\`, and HTML-escapes `&`, `<` and `>` into
// &-style sequences, so a plaintext comparison silently misses any secret
// containing them — which is exactly the shape of a user-chosen proxy or
// truststore password. Comparing against both forms closes that.
func jsonEscaped(s string) string {
	b, err := json.Marshal(s)
	if err != nil || len(b) < 2 {
		return s
	}
	return string(b[1 : len(b)-1]) // strip the surrounding quotes
}

// containsSecret reports whether text carries value either literally or in its
// JSON-encoded form.
func containsSecret(text, value string) bool {
	if value == "" {
		return false
	}
	if strings.Contains(text, value) {
		return true
	}
	if esc := jsonEscaped(value); esc != value && strings.Contains(text, esc) {
		return true
	}
	return false
}

// bearerTokenPattern matches an Authorization-style bearer value: the scheme
// followed by something long enough to actually be a token.
//
// A bare `strings.Contains(text, "Bearer ")` would be too blunt: this tool runs
// against hostile and misconfigured proxies by design, and their error pages
// routinely contain prose like `must use the "Bearer " scheme`. Any such text
// reaches a Stage detail, so a substring match would trip the guard and
// suppress the ENTIRE result file — on precisely the broken-network run where
// the participant most needs a file to send. Requiring token-shaped material
// keeps the guard useful without handing a remote party a switch to silence
// the output.
var bearerTokenPattern = regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._~+/=-]{16,}`)

// ScanForLeak returns a non-empty reason if s contains any known secret
// material or an obvious bearer-token pattern. This is a last-resort guard,
// not the primary defense — callers must not construct output containing
// secrets in the first place; this only catches accidental future leaks.
func (s Secrets) ScanForLeak(text string) string {
	if containsSecret(text, s.ClientSecret) {
		return "output contains the raw client secret"
	}
	if containsSecret(text, s.AccessToken) {
		return "output contains the raw access token"
	}
	if containsSecret(text, s.ProxyPassword) {
		return "output contains the raw proxy password"
	}
	if containsSecret(text, s.JavaTrustStorePassword) {
		return "output contains the raw Java truststore password"
	}
	if bearerTokenPattern.MatchString(text) {
		return "output contains what looks like a bearer token"
	}
	return ""
}

// Scrub replaces any known secret material in text with a masked placeholder.
// Use this on streamed human output (stdout), where the file writers' refuse-
// to-emit behavior (ScanForLeak) isn't possible mid-stream. It's a last-resort
// backstop — callers still must not construct output containing secrets in
// the first place. This matters because stage lines print via bare fmt.Print
// with no other redaction, so a server-controlled OAuth error_description
// reflected back to the terminal could otherwise carry the client secret
// past the file-only self-check.
func (s Secrets) Scrub(text string) string {
	// Both forms, for the same reason ScanForLeak checks both: Scrub also runs
	// over already-marshalled JSON, where a secret containing " \ & < or >
	// appears only in its escaped form and a plaintext replace would miss it.
	for _, secret := range []string{s.ClientSecret, s.AccessToken, s.ProxyPassword, s.JavaTrustStorePassword} {
		if secret == "" {
			continue
		}
		text = strings.ReplaceAll(text, secret, "****")
		if esc := jsonEscaped(secret); esc != secret {
			text = strings.ReplaceAll(text, esc, "****")
		}
	}
	// Masked, not fully hidden: first4...last4 keeps it diagnostically useful
	// for the operator ("is that the id I actually issued?") while still
	// avoiding a full disclosure. Applied last so it can't partially rewrite
	// a longer secret that happens to embed the id.
	if s.ClientID != "" {
		text = strings.ReplaceAll(text, s.ClientID, MaskID(s.ClientID))
	}
	return text
}

// Truncate shortens a response body for diagnostic display — never dump a
// full response body into a remediation message or log line.
func Truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	// Back off to a rune boundary. The input is server-controlled text (an
	// OAuth error_description, a proxy's error page) which is often non-ASCII
	// on a localized corporate proxy — a naive s[:max] byte slice can cut a
	// multi-byte rune in half, producing invalid UTF-8 that json.Marshal then
	// silently rewrites to U+FFFD. Cosmetic, but trivially avoidable.
	cut := max
	for cut > 0 && !utf8.ValidString(s[:cut]) {
		cut--
	}
	return s[:cut] + "... (truncated)"
}
