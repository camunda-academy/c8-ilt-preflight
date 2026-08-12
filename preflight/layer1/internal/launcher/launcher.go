// Package launcher implements the Layer 2 dispatch mechanism: selecting which
// per-runtime stacks to probe, detecting whether each runtime is present, and
// invoking the actual probes under preflight/layer2/<stack>/ following the
// documented convention below. If a stack has no probe available (e.g. a
// future runtime not yet supported), the launcher reports SKIP with a clear
// "not yet available" detail rather than failing.
package launcher

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"c8preflight/internal/model"
)

// KnownStacks is the set of stack names accepted by --stacks/--auto.
var KnownStacks = []string{"java", "python", "typescript", "csharp"}

// IsKnownStack reports whether name is one of the runtimes the toolkit ships
// a Layer 2 probe for. Callers (config.Parse) use this to reject a typo'd
// --stacks value up front rather than misreport it as "runtime not installed".
func IsKnownStack(name string) bool {
	for _, s := range KnownStacks {
		if s == name {
			return true
		}
	}
	return false
}

// SuggestStack returns the closest known stack name to an unknown input, or ""
// if none is close. Deliberately conservative — only a prefix match (e.g.
// "jav" -> "java", "pyth" -> "python") — so it never guesses wildly.
func SuggestStack(name string) string {
	if name == "" {
		return ""
	}
	for _, s := range KnownStacks {
		if strings.HasPrefix(s, name) || strings.HasPrefix(name, s) {
			return s
		}
	}
	return ""
}

// runtimeBinary maps a stack name to the command(s) that indicate the
// runtime is installed, checked via PATH lookup — in preference order.
var runtimeBinary = map[string][]string{
	"java":       {"java"},
	"python":     {"python3", "python"},
	"typescript": {"node"},
	"csharp":     {"dotnet"},
}

// probeEntrypoint is the per-OS standalone entrypoint convention every
// probe must provide under preflight/layer2/<stack>/. Every probe must also
// be runnable standalone by hand (so it stays inspectable/runnable even if
// something blocks the launcher's own process-spawning) — this is the same
// file the launcher invokes.
//
// Returns "" when layer2Dir is empty (probe directory not found — see
// findLayer2Dir, which refuses CWD-relative resolution for security). An empty
// return must NEVER be turned into a relative path here, or os.Stat/exec would
// become CWD-relative again, letting a planted script in an untrusted working
// directory get executed.
func probeEntrypoint(layer2Dir, stack string) string {
	if strings.TrimSpace(layer2Dir) == "" {
		return ""
	}
	name := "run.sh"
	if runtime.GOOS == "windows" {
		name = "run.cmd"
	}
	return filepath.Join(layer2Dir, stack, name)
}

// RuntimeStatus is what the launcher determines for one selected stack
// before even trying to run a probe.
type RuntimeStatus struct {
	Stack         string
	Present       bool
	BinaryFound   string // which candidate binary was found on PATH, if any
	StandaloneCmd string // the exact command an operator could run by hand
}

// DetectRuntime checks whether a stack's runtime is present on PATH.
func DetectRuntime(stack string) RuntimeStatus {
	candidates, known := runtimeBinary[stack]
	if !known {
		return RuntimeStatus{Stack: stack, Present: false}
	}
	for _, bin := range candidates {
		if path, err := exec.LookPath(bin); err == nil {
			return RuntimeStatus{Stack: stack, Present: true, BinaryFound: path}
		}
	}
	return RuntimeStatus{Stack: stack, Present: false}
}

// SelectStacks resolves the final stack list: explicit --stacks is the
// default mechanism; --auto scans for any known runtime present on PATH
// (the unknown-language fallback). Explicit selection wins if both are
// somehow set, since it is the documented default and more specific.
func SelectStacks(explicit []string, auto bool) []string {
	if len(explicit) > 0 {
		return explicit
	}
	if !auto {
		return nil
	}
	var found []string
	for _, s := range KnownStacks {
		if DetectRuntime(s).Present {
			found = append(found, s)
		}
	}
	return found
}

// ProbeConfig is the resolved run configuration the Go binary passes down to
// every Layer 2 probe. Probes speak only the CAMUNDA_* / HTTP(S)_PROXY env-var
// convention, so anything the operator set via a FLAG (rather than the matching
// env var) has to be translated back into env vars here — otherwise Layer 1
// (which reads flags) and Layer 2 (which reads env) test different things.
// Without this, a run using --proxy would route Layer 1 through the proxy but
// let probes connect directly (a false-green); the same gap would apply to
// --host and --trust-ca. Forwarding the fully-resolved config ensures both
// layers exercise the identical target, path, and trust material.
type ProbeConfig struct {
	Mode string // "network"|"full" -> CAMUNDA_PREFLIGHT_MODE

	// RESTAddress is what the probe should treat as CAMUNDA_REST_ADDRESS. Pass
	// the operator's RAW explicit host when they gave one (so the probe can
	// still detect + WARN about the Console copy-paste ":443" form), else a
	// canonical https://<host>/<clusterId> derived from the resolved target.
	RESTAddress string

	// ExplicitProxy is the --proxy flag value (empty when the operator relied on
	// HTTP(S)_PROXY env vars, which are then inherited untouched).
	ExplicitProxy string

	// CACertPath is the resolved --trust-ca / CAMUNDA_MTLS_CA_PATH (empty if none).
	CACertPath string

	// Verbose forwards --verbose to probes (as CAMUNDA_PREFLIGHT_VERBOSE=1) so
	// they surface extra diagnostic fragments hidden by default — e.g. the
	// Console-URL normalization notice, which is useful to the operator but
	// confusing noise for participants.
	Verbose bool

	// JavaTrustStorePath/Password are the resolved --java-truststore /
	// CAMUNDA_JAVA_TRUSTSTORE(_PASSWORD) — forwarded to CAMUNDA_JAVA_TRUSTSTORE(_PASSWORD)
	// so the Java probes can apply -Djavax.net.ssl.trustStore before any SSL work.
	// Only Java reads these; forwarding them to every probe's env is harmless
	// (unrecognized env vars are ignored), matching how CACertPath is already
	// forwarded under two names regardless of which stack is running.
	JavaTrustStorePath     string
	JavaTrustStorePassword string

	// Maven dependency-resolution check, forwarded to the Java DepCheck
	// sub-probe via env. Only the java run script consumes these.
	MavenDepcheck    bool
	MavenMirror      string
	MavenSettings    string
	MavenCentralOnly bool

	// TSProxySupport forwards --ts-proxy-support to CAMUNDA_TS_PROXY_SUPPORT.
	// Only probe_sdk.js (TypeScript tier 2) reads this -- opt-in because it
	// swaps the real SDK's own (proxy-blind) fetch for a hand-written
	// proxy-tunneling override, changing what the check actually exercises
	// (see RUNBOOK's TypeScript section). Off by default so the tool's
	// default behavior mirrors the real, unmodified SDK exactly.
	TSProxySupport bool
}

// onFragment, when non-nil, is called once per fragment AS SOON AS it is
// known — the moment a synchronous SKIP/FAIL is decided, or the moment a
// probe subprocess emits a line of stdout — so the caller can print it
// immediately, matching Layer 1's per-stage streaming. Without this, Layer 2
// would buffer every stack's ENTIRE fragment set until every stack's
// subprocess had exited, so a multi-minute probe — e.g. the Maven depcheck's
// real network fetches — would print nothing at all until the whole run
// finished, indistinguishable from a hang, and one slow stack would delay
// printing a DIFFERENT, already-finished stack's results. Pass nil to just
// get the aggregated slice without streaming.
//
// Run dispatches each selected stack's probe (if available) and returns the
// runtimesDetected/Skipped lists plus merged probe fragments, per the
// cross-runtime probe contract (every probe emits one JSON fragment per line
// on stdout; see any layer2/<stack>/_shared.* module for the shape).
// layer2Dir is the path to the preflight/layer2 directory (probes live under
// <layer2Dir>/<stack>/). pc is the resolved run config forwarded to every
// probe (see ProbeConfig).
func Run(ctx context.Context, layer2Dir string, stacks []string, explicitSelection bool, pc ProbeConfig, onFragment func(model.ProbeFragment)) (detected []string, skipped []string, probes []model.ProbeFragment) {
	emit := func(f model.ProbeFragment) {
		probes = append(probes, f)
		if onFragment != nil {
			onFragment(f)
		}
	}
	for _, stack := range stacks {
		status := DetectRuntime(stack)
		entry := probeEntrypoint(layer2Dir, stack)

		if !status.Present {
			if explicitSelection {
				// Selected-but-absent = loud FAIL, not a silent skip — an operator
				// who explicitly named this stack needs to know it's missing.
				emit(model.ProbeFragment{
					Runtime:             stack,
					TrustStoreExercised: "",
					Target:              "",
					Verdict:             model.VerdictFail,
					ErrorClass:          model.ErrRuntimeAbsent,
					Detail:              fmt.Sprintf("selected runtime %q is not installed on this machine — install it, then re-run", stack),
				})
			}
			skipped = append(skipped, stack)
			continue
		}
		detected = append(detected, stack)

		if entry == "" {
			// The layer2 probe directory wasn't found next to the executable
			// (findLayer2Dir refuses CWD-relative resolution for security).
			// Report SKIP rather than silently doing nothing — and never fall
			// back to a relative path that os.Stat/exec would resolve against
			// the CWD, which would let a planted script in an untrusted
			// working directory get executed instead.
			emit(model.ProbeFragment{
				Runtime: stack, Verdict: model.VerdictSkip, ErrorClass: model.ErrOK,
				Detail: fmt.Sprintf("runtime present (%s), but the layer2 probe directory was not found next to the executable — ship layer2/ alongside the binary, or set CAMUNDA_LAYER2_DIR", status.BinaryFound),
			})
			continue
		}

		if _, err := os.Stat(entry); err != nil {
			// A runtime can be present on PATH with no probe shipped for it
			// yet (e.g. a stack added to KnownStacks ahead of its probe).
			// Kept short and plain-language deliberately -- this ends up in
			// the customer-facing result, not an internal roadmap note.
			emit(model.ProbeFragment{
				Runtime:             stack,
				TrustStoreExercised: "",
				Target:              "",
				Verdict:             model.VerdictSkip,
				ErrorClass:          model.ErrOK,
				Detail:              "runtime detected, but no probe is available for it yet.",
			})
			continue
		}

		// invokeProbes calls onFragment itself, per line, AS the subprocess
		// produces it -- not via emit(), which would call it a second time.
		probes = append(probes, invokeProbes(ctx, stack, entry, pc, onFragment)...)
	}
	return detected, skipped, probes
}

// probeEnv builds the environment for a probe process: the parent environment,
// with each flag-resolved value translated into the env var the probe reads.
// For every knob the operator can set explicitly (proxy, CA, REST address) we
// DROP any inherited copy first, then re-add the resolved value, so an explicit
// flag wins deterministically over an inherited env var — matching the Go
// binary's own precedence. CAMUNDA_PREFLIGHT_MODE is always set. A knob left
// empty means "no flag given" and the inherited env var (if any) is preserved.
func probeEnv(pc ProbeConfig) []string {
	// overrides maps an env-var name to the value we want to force; empty value
	// means "don't override, leave inherited untouched".
	overrides := map[string]string{
		"CAMUNDA_REST_ADDRESS": pc.RESTAddress,
		"CAMUNDA_MTLS_CA_PATH": pc.CACertPath,

		"CAMUNDA_JAVA_TRUSTSTORE":          pc.JavaTrustStorePath,
		"CAMUNDA_JAVA_TRUSTSTORE_PASSWORD": pc.JavaTrustStorePassword,

		"CAMUNDA_MAVEN_MIRROR":   pc.MavenMirror,
		"CAMUNDA_MAVEN_SETTINGS": pc.MavenSettings,
	}
	if pc.MavenDepcheck {
		overrides["CAMUNDA_MAVEN_DEPCHECK"] = "1"
	}
	if pc.MavenCentralOnly {
		overrides["CAMUNDA_MAVEN_CENTRAL_ONLY"] = "1"
	}
	if pc.TSProxySupport {
		overrides["CAMUNDA_TS_PROXY_SUPPORT"] = "1"
	}
	// The real Java SDK does NOT read CAMUNDA_MTLS_CA_PATH -- it reads
	// CAMUNDA_CA_CERTIFICATE_PATH (verified against camunda-client-java
	// source). Without this second name, an operator using this tool's own
	// unified --trust-ca flag would trip the java probe's own "wrong env var
	// name" mismatch warning -- a self-inflicted false alarm caused by only
	// forwarding one of the two names. Forward --trust-ca under BOTH names so
	// every probe's own per-language convention is satisfied from one flag --
	// EXCEPT when --java-truststore was explicitly given: forwarding
	// CAMUNDA_CA_CERTIFICATE_PATH too would silently win over Java's
	// -Djavax.net.ssl.trustStore (that code path always takes priority),
	// with only a same-run WARN as the signal -- an operator combining
	// --trust-ca with --java-truststore would otherwise get the truststore
	// silently ignored. dropJavaCACertPath also strips any INHERITED
	// CAMUNDA_CA_CERTIFICATE_PATH -- e.g. left over in the operator's shell
	// from an earlier test -- since that causes the identical silent
	// override with no --trust-ca in sight. This lets the two flags actually
	// compose: --trust-ca reaches Go/Python/TS, --java-truststore reaches Java,
	// neither steps on the other.
	dropJavaCACertPath := pc.JavaTrustStorePath != ""
	if !dropJavaCACertPath {
		overrides["CAMUNDA_CA_CERTIFICATE_PATH"] = pc.CACertPath
	}
	// A proxy override targets BOTH HTTP_PROXY and HTTPS_PROXY.
	if pc.ExplicitProxy != "" {
		overrides["HTTPS_PROXY"] = pc.ExplicitProxy
		overrides["HTTP_PROXY"] = pc.ExplicitProxy
	}

	// Credential env vars are stripped from the child unless this is a full-mode
	// run. Network mode is credential-free by design, so a network-mode probe
	// must never inherit the client secret —
	// otherwise Layer 1's redaction guarantee silently ends at the process
	// boundary and a buggy/hostile probe could log or transmit it. In full mode
	// probes legitimately need credentials (the authenticated topology check),
	// so they're passed through. Covers both the primary names and the SDK's
	// documented aliases.
	credEnvNames := []string{
		"CAMUNDA_CLIENT_SECRET", "CAMUNDA_CLIENT_ID",
		"CAMUNDA_CLIENT_AUTH_CLIENTSECRET", "CAMUNDA_CLIENT_AUTH_CLIENTID",
		"CAMUNDA_BASIC_AUTH_PASSWORD", "CAMUNDA_BASIC_AUTH_USERNAME",
	}
	stripCreds := strings.ToLower(pc.Mode) != "full"

	overriding := func(envLine string) bool {
		up := strings.ToUpper(envLine)
		if stripCreds {
			for _, name := range credEnvNames {
				if strings.HasPrefix(up, name+"=") {
					return true // drop credentials in non-full mode
				}
			}
		}
		if dropJavaCACertPath && strings.HasPrefix(up, "CAMUNDA_CA_CERTIFICATE_PATH=") {
			return true // strip any inherited copy too -- see the comment above
		}
		for name, val := range overrides {
			if val != "" && strings.HasPrefix(up, name+"=") {
				return true
			}
		}
		return false
	}

	parent := os.Environ()
	out := make([]string, 0, len(parent)+len(overrides)+1)
	for _, e := range parent {
		if overriding(e) {
			continue // dropped (credential in non-full mode) or re-added canonically below
		}
		out = append(out, e)
	}
	out = append(out, "CAMUNDA_PREFLIGHT_MODE="+pc.Mode)
	if pc.Verbose {
		out = append(out, "CAMUNDA_PREFLIGHT_VERBOSE=1")
	}
	for name, val := range overrides {
		if val != "" {
			out = append(out, name+"="+val)
		}
	}
	return out
}

// probeTimeoutDefault covers the trust probe (+ optional SDK-snippet probe),
// both of which are quick network/TLS checks. probeTimeoutWithMavenDepcheck is
// used instead when the operator opted into the Maven dependency-resolution
// check: DepCheck runs up to two go-offline legs, each with its own internal
// 240s timeout, so the OUTER process timeout must comfortably exceed 2x that
// or the launcher would kill the whole probe mid-fetch and misreport a real
// (if slow) result as a crash.
const (
	probeTimeoutDefault           = 30 * time.Second
	probeTimeoutWithMavenDepcheck = 10 * time.Minute
)

// invokeProbes runs one probe's standalone entrypoint and streams its stdout
// JSON fragments per the cross-runtime probe contract, calling onFragment (if
// non-nil) the moment each line is read -- not after the process exits. A
// probe MAY emit several newline-delimited fragments — e.g. the java stack
// emits one fragment for its trust probe, one for the optional SDK probe, one
// for the optional Maven depcheck; most probes emit exactly one. Any failure
// to produce at least one
// valid fragment is classified as a single probe-error (present runtime,
// broken probe) — distinct from SKIP (absent) and from a clean FAIL.
func invokeProbes(ctx context.Context, stack, entry string, pc ProbeConfig, onFragment func(model.ProbeFragment)) []model.ProbeFragment {
	timeout := probeTimeoutDefault
	if pc.MavenDepcheck {
		timeout = probeTimeoutWithMavenDepcheck
	}
	pctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(pctx, entry)
	// Forward the fully-resolved run config so Layer 1 and Layer 2 exercise the
	// identical target, network path, mode, and trust material.
	cmd.Env = probeEnv(pc)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return []model.ProbeFragment{{
			Runtime: stack, Verdict: model.VerdictProbeError, ErrorClass: model.ErrProbeCrashed,
			Detail: fmt.Sprintf("could not attach to probe stdout: %v", err),
		}}
	}
	if err := cmd.Start(); err != nil {
		return []model.ProbeFragment{{
			Runtime: stack, Verdict: model.VerdictProbeError, ErrorClass: model.ErrProbeCrashed,
			Detail: fmt.Sprintf("could not start probe: %v", err),
		}}
	}

	var frags []model.ProbeFragment
	scanner := bufio.NewScanner(stdout)
	// A probe's own stdout line (a JSON fragment) can be long-ish, but never
	// pathologically so — 1MiB is generous headroom over bufio's 64KiB default,
	// guarding against a misbehaving probe wedging the scanner on one huge line.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if frag, ok := parseFragmentLine(line); ok {
			frags = append(frags, frag)
			if onFragment != nil {
				onFragment(frag)
			}
		}
	}
	runErr := cmd.Wait()

	if len(frags) > 0 {
		return frags
	}

	// stdout produced no parseable fragment at all — fall back to classifying
	// from the exit code, since the probe's stdout isn't parseable.
	detail := "probe produced no parseable JSON fragment on stdout"
	if runErr != nil {
		detail = fmt.Sprintf("probe exited with error: %v (stderr: %s)", runErr, truncate(stderr.String(), 300))
	}
	fallback := model.ProbeFragment{
		Runtime:             stack,
		TrustStoreExercised: "",
		Target:              "",
		Verdict:             model.VerdictProbeError,
		ErrorClass:          model.ErrProbeCrashed,
		Detail:              detail,
	}
	if onFragment != nil {
		onFragment(fallback)
	}
	return []model.ProbeFragment{fallback}
}

// parseFragments reads every non-blank line of a probe's stdout and keeps
// whichever ones unmarshal into a valid ProbeFragment (non-empty Runtime).
// Lines that aren't valid JSON fragments are skipped, not fatal — this lets
// a probe print incidental progress text on stdout before its fragment(s)
// without corrupting the whole result, as long as each fragment is on its
// own line. Pure function (no process execution) so it's unit-testable
// without a real probe binary.
func parseFragments(stdout string) []model.ProbeFragment {
	var frags []model.ProbeFragment
	for _, line := range strings.Split(stdout, "\n") {
		if frag, ok := parseFragmentLine(line); ok {
			frags = append(frags, frag)
		}
	}
	return frags
}

// parseFragmentLine is parseFragments' per-line core, factored out so the
// streaming path in invokeProbes can classify one line at a time (as the
// subprocess produces it) instead of waiting for the whole stdout buffer.
func parseFragmentLine(line string) (model.ProbeFragment, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return model.ProbeFragment{}, false
	}
	var frag model.ProbeFragment
	if err := json.Unmarshal([]byte(line), &frag); err == nil && frag.Runtime != "" {
		return frag, true
	}
	return model.ProbeFragment{}, false
}

func truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "... (truncated)"
}
