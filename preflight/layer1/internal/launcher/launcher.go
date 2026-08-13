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
	"c8preflight/internal/redact"
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

// RuntimeOverrides pins which runtime INSTALLATION each stack is checked with,
// instead of accepting whatever PATH happens to offer first.
//
// This exists because "the language is installed" is not the question the tool
// actually needs answered — "the runtime the training exercises will use can
// reach the cluster" is. Those differ whenever a machine carries more than one
// JDK, interpreter or Node major, which on a corporate laptop is normal. The
// same override is applied to Go's own detection AND forwarded to the probe, so
// the two can never end up describing different installations.
type RuntimeOverrides struct {
	JavaHome  string // a JDK directory; its bin/java is used
	PythonBin string // an interpreter binary
	NodeBin   string // a node binary
	DotnetBin string // a dotnet binary
}

// pinnedValue returns the raw operator-selected path for a stack, or "".
func (o RuntimeOverrides) pinnedValue(stack string) string {
	switch stack {
	case "java":
		return o.JavaHome
	case "python":
		return o.PythonBin
	case "typescript":
		return o.NodeBin
	case "csharp":
		return o.DotnetBin
	}
	return ""
}

// pinCandidates expands an operator's runtime selection into the concrete
// binaries worth trying, in preference order.
//
// A directory and an executable are both accepted for every stack, because the
// distinction is an implementation detail nobody should have to remember: a JDK
// is naturally identified by its home directory while a node binary is
// naturally a file, and demanding the "right" kind per stack only produces
// "file does not exist" for a path that plainly exists. Passing a directory also
// covers how these installations are actually laid out — notably a virtualenv,
// where the interpreter is under bin/ on Unix and Scripts/ on Windows.
func (o RuntimeOverrides) pinCandidates(stack string) []string {
	raw := strings.TrimSpace(o.pinnedValue(stack))
	if raw == "" {
		return nil
	}
	raw = filepath.Clean(raw)
	if st, err := os.Stat(raw); err != nil || !st.IsDir() {
		// Not a directory (or not there at all): treat it as the binary itself
		// and let the caller report what went wrong.
		return []string{raw}
	}
	var names []string
	switch stack {
	case "java":
		names = []string{"java"}
	case "python":
		names = []string{"python3", "python"}
	case "typescript":
		names = []string{"node"}
	case "csharp":
		names = []string{"dotnet"}
	}
	// Layouts, in order: alongside the directory itself (a .NET install root, an
	// unpacked node dist), under bin/ (a JDK home, a POSIX virtualenv), and under
	// Scripts/ (a Windows virtualenv).
	//
	// Names are left extensionless on purpose: exec.LookPath applies the host's
	// executable extensions itself, which on Windows means a .cmd/.bat wrapper is
	// found as readily as a .exe. Corporate-managed toolchains are often exactly
	// such a wrapper, and hardcoding .exe would quietly refuse them.
	subdirs := []string{"", "bin", "Scripts"}
	var out []string
	for _, sub := range subdirs {
		for _, name := range names {
			out = append(out, filepath.Join(raw, sub, name))
		}
	}
	return out
}

// RuntimeStatus is what the launcher determines for one selected stack
// before even trying to run a probe.
type RuntimeStatus struct {
	Stack          string
	Present        bool
	BinaryFound    string // which binary was resolved, if any
	Version        string // as self-reported by that binary, first line
	Pinned         bool   // resolved from a RuntimeOverrides selection, not PATH
	UnusableReason string // why a resolved binary could not be used as this runtime
	StandaloneCmd  string // the exact command an operator could run by hand
}

// DetectRuntime resolves which runtime installation a stack will be checked
// with, and asks it for its version.
//
// An operator-pinned selection is honored first and, crucially, is NEVER
// quietly replaced by a PATH lookup when it turns out to be unusable: falling
// back would check a different installation than the one that was asked for and
// report it as though it were the same, which is the exact confusion pinning
// exists to remove. A broken pin is reported as absent-with-a-reason instead.
func DetectRuntime(stack string, ov RuntimeOverrides) RuntimeStatus {
	candidates, known := runtimeBinary[stack]
	if !known {
		return RuntimeStatus{Stack: stack, Present: false}
	}
	if candidates := ov.pinCandidates(stack); len(candidates) > 0 {
		for _, candidate := range candidates {
			path, err := exec.LookPath(candidate)
			if err != nil {
				continue
			}
			if version, ok := runtimeVersion(path, stack); ok {
				return RuntimeStatus{
					Stack: stack, Present: true, BinaryFound: path, Pinned: true, Version: version,
				}
			}
		}
		return RuntimeStatus{
			Stack: stack, Present: false, Pinned: true,
			UnusableReason: pinFailureReason(stack, ov.pinnedValue(stack), candidates),
		}
	}
	// Existing on disk is not the same as being the runtime. Windows ships an
	// App Execution Alias stub named python3.exe that is not Python at all — it
	// exits non-zero telling you to visit the Store — and the official Python
	// installer only creates python.exe, so on a stock Windows box with Python
	// properly installed a bare "is python3 on PATH" lookup finds the stub and
	// reports the runtime as present while every probe using it would fail.
	// So a candidate only counts once it has identified itself.
	var rejected []string
	for _, bin := range candidates {
		path, err := exec.LookPath(bin)
		if err != nil {
			continue
		}
		version, ok := runtimeVersion(path, stack)
		if !ok {
			// Keep what it said instead of only that it failed: the reply is
			// usually the whole diagnosis (a Store placeholder announcing itself,
			// or dotnet refusing because a global.json pins an absent SDK).
			said := version
			if said == "" {
				said = "no output"
			}
			rejected = append(rejected, fmt.Sprintf("%s (%s)", redact.MaskHomeDir(path), said))
			continue
		}
		return RuntimeStatus{Stack: stack, Present: true, BinaryFound: path, Version: version}
	}
	st := RuntimeStatus{Stack: stack, Present: false}
	if len(rejected) > 0 {
		st.UnusableReason = fmt.Sprintf("found a %s runtime on PATH that does not work: %s", stack, strings.Join(rejected, "; ")) + rejectionHint(stack)
	}
	return st
}

// rejectionHint adds the most common per-stack explanation for a runtime that is
// on PATH yet doesn't work, since the runtime's own message is often terse.
func rejectionHint(stack string) string {
	switch stack {
	case "python":
		return ". On Windows a python3.exe like this is usually the Microsoft Store placeholder rather than Python itself"
	case "csharp":
		return ". A dotnet that refuses to report a version is usually being held to an SDK version that isn't installed by a global.json in scope"
	default:
		return ""
	}
}

// pinFailureReason explains why an operator's runtime selection couldn't be
// used, in terms of what was actually looked for.
//
// The naive message here is Go's own "file does not exist", which is actively
// misleading when the path given was a directory that exists perfectly well and
// simply doesn't hold the binary. Naming the candidates tried turns a dead end
// into something the reader can act on.
func pinFailureReason(stack, raw string, candidates []string) string {
	cleaned := filepath.Clean(strings.TrimSpace(raw))
	// Masked before use in any message below: an operator's pin is very often a
	// per-user path (their own home directory, a personal venv), and this text
	// ends up in a FAIL fragment inside the shareable result JSON.
	maskedCleaned := redact.MaskHomeDir(cleaned)
	st, err := os.Stat(cleaned)
	switch {
	case err != nil:
		return fmt.Sprintf("no %s runtime at %s -- that path does not exist", stack, maskedCleaned)
	case st.IsDir():
		maskedCandidates := make([]string, len(candidates))
		for i, c := range candidates {
			maskedCandidates[i] = redact.MaskHomeDir(c)
		}
		return fmt.Sprintf("%s is a directory, and none of the places a %s runtime normally sits inside one held a working "+
			"executable (looked for: %s). Point at the executable itself if it lives somewhere unusual.",
			maskedCleaned, stack, strings.Join(maskedCandidates, ", "))
	default:
		return fmt.Sprintf("%s exists but does not answer as a working %s runtime -- it may be a placeholder or wrapper "+
			"rather than the real thing", maskedCleaned, stack)
	}
}

// pinMismatchWarning flags the case where the environment plainly points at one
// runtime installation but a DIFFERENT one is what actually got used — a
// JAVA_HOME naming one JDK while an earlier PATH entry supplies another, or an
// activated virtualenv bypassed by a system interpreter.
//
// Worth a WARN rather than silence because both installations have their own
// trust store, so the result describes a runtime the operator didn't think they
// were testing. Not an error: this layout is often deliberate, and the fix
// (pinning explicitly) is offered rather than forced.
func pinMismatchWarning(st RuntimeStatus) (model.ProbeFragment, bool) {
	if st.Pinned || st.BinaryFound == "" {
		return model.ProbeFragment{}, false
	}
	var envName, pinFlag string
	switch st.Stack {
	case "java":
		envName, pinFlag = "JAVA_HOME", "--java-home"
	case "python":
		envName, pinFlag = "VIRTUAL_ENV", "--python-bin"
	default:
		return model.ProbeFragment{}, false
	}
	root := strings.TrimSpace(os.Getenv(envName))
	if root == "" || underDir(st.BinaryFound, root) {
		return model.ProbeFragment{}, false
	}
	return model.ProbeFragment{
		Runtime: st.Stack,
		// The " (config)" suffix is the cross-language convention marking a
		// finding about configuration rather than a check against a real host.
		// It keeps this out of the inline PASS/FAIL list -- where it would print
		// as a bare "configuration error" against no target, saying nothing --
		// and routes it to the notes section, which shows the full text below.
		Target:     "runtime selection (config)",
		Verdict:    model.VerdictWarn,
		ErrorClass: model.ErrConfigError,
		Detail: fmt.Sprintf("%s points at %s, but the %s runtime actually used is %s — these are different installations with "+
			"separate trust stores, so this check may not reflect the one your exercises run on. Pass %s to pin it explicitly.",
			envName, redact.MaskHomeDir(root), st.Stack, redact.MaskHomeDir(st.BinaryFound), pinFlag),
	}, true
}

// inheritedGlobalJSONWarning reports a global.json in scope for the C# probe's
// build that the tool didn't put there.
//
// `dotnet` resolves global.json from the CURRENT WORKING DIRECTORY upward, not
// from the project's location. So a participant who unpacks this tool inside a
// checked-out repo or solution folder and runs it there silently hands their
// SDK pin to our build.
// If it names an SDK they don't have, the probe dies during build for a reason
// that has nothing to do with connectivity — so name the file rather than let it
// surface as an opaque build failure.
func inheritedGlobalJSONWarning(stack string) (model.ProbeFragment, bool) {
	if stack != "csharp" {
		return model.ProbeFragment{}, false
	}
	dir, err := os.Getwd()
	if err != nil {
		return model.ProbeFragment{}, false
	}
	for {
		candidate := filepath.Join(dir, "global.json")
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return model.ProbeFragment{
				Runtime: stack,
				// See the note on the runtime-selection warning above: same
				// convention, same reason.
				Target:     "SDK pin (config)",
				Verdict:    model.VerdictWarn,
				ErrorClass: model.ErrConfigError,
				Detail: fmt.Sprintf("%s applies to this run: the .NET tooling reads global.json from the working directory upward, "+
					"so a file you didn't intend for this check can pin which SDK builds it. If the C# check fails to build, "+
					"try running this tool from a directory outside that project.", redact.MaskHomeDir(candidate)),
			}, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return model.ProbeFragment{}, false
		}
		dir = parent
	}
}

// underDir reports whether path sits inside dir, comparing the way the host
// filesystem does (Windows paths are case-insensitive).
func underDir(path, dir string) bool {
	absPath, err1 := filepath.Abs(path)
	absDir, err2 := filepath.Abs(dir)
	if err1 != nil || err2 != nil {
		return false
	}
	rel, err := filepath.Rel(absDir, absPath)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// versionArgs is how each runtime is asked to identify itself.
var versionArgs = map[string][]string{
	"java":       {"-version"}, // NOT --version: only JDK 9+ accepts that form
	"python":     {"--version"},
	"typescript": {"--version"},
	"csharp":     {"--version"},
}

// runtimeVersion asks a resolved runtime binary to identify itself. The second
// return reports whether it answered successfully, which doubles as the check
// that this binary really is the runtime and not a lookalike on PATH; on
// failure the string carries whatever it said instead, for the error message.
//
// stdout and stderr are read together because the answer isn't consistently on
// either — `java -version` writes to stderr on JDK 8 and to stdout from 9 on.
func runtimeVersion(bin, stack string) (string, bool) {
	args, ok := versionArgs[stack]
	if !ok {
		return "", true // unknown stack: nothing to verify against
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
	first := ""
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			first = redact.Truncate(line, 120)
			break
		}
	}
	if err != nil {
		return first, false
	}
	return first, true
}

// SelectStacks resolves the final stack list: explicit --stacks is the
// default mechanism; --auto scans for any known runtime present on PATH
// (the unknown-language fallback). Explicit selection wins if both are
// somehow set, since it is the documented default and more specific.
func SelectStacks(explicit []string, auto bool, ov RuntimeOverrides) []string {
	if len(explicit) > 0 {
		return explicit
	}
	if !auto {
		return nil
	}
	var found []string
	for _, s := range KnownStacks {
		if DetectRuntime(s, ov).Present {
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
	// proxy-tunneling override, changing what the check actually exercises.
	// Off by default so the tool's default behavior mirrors the real,
	// unmodified SDK exactly.
	TSProxySupport bool

	// Runtimes pins which runtime installation each stack is checked with. Also
	// forwarded to the probe (CAMUNDA_JAVA_HOME / _PYTHON_BIN / _NODE_BIN /
	// _DOTNET_BIN) so the run script compiles and executes with the same
	// installation Go resolved, rather than doing its own PATH lookup and
	// possibly picking a different one.
	Runtimes RuntimeOverrides
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
func Run(ctx context.Context, layer2Dir string, stacks []string, explicitSelection bool, pc ProbeConfig, onFragment func(model.ProbeFragment)) (detected []string, skipped []string, runtimes []model.RuntimeDetail, probes []model.ProbeFragment) {
	emit := func(f model.ProbeFragment) {
		probes = append(probes, f)
		if onFragment != nil {
			onFragment(f)
		}
	}
	for _, stack := range stacks {
		status := DetectRuntime(stack, pc.Runtimes)
		entry := probeEntrypoint(layer2Dir, stack)

		// Emitted before the presence check, not after: an inherited SDK pin is
		// most often the REASON the runtime looks broken or missing, so it has to
		// accompany that failure rather than only a successful run.
		if w, ok := inheritedGlobalJSONWarning(stack); ok {
			emit(w)
		}

		if !status.Present {
			if explicitSelection {
				// Selected-but-absent = loud FAIL, not a silent skip — an operator
				// who explicitly named this stack needs to know it's missing.
				// A pin that couldn't be used is its own message: the runtime may
				// well be installed elsewhere, so "not installed" would misdirect.
				detail := fmt.Sprintf("selected runtime %q is not installed on this machine — install it, then re-run", stack)
				switch {
				case status.Pinned && status.UnusableReason != "":
					detail = fmt.Sprintf("the %s runtime you selected explicitly could not be used, and no fallback was attempted "+
						"so this run can't silently check a different installation than the one you asked for: %s", stack, status.UnusableReason)
				case status.UnusableReason != "":
					detail = status.UnusableReason
				}
				emit(model.ProbeFragment{
					Runtime:             stack,
					TrustStoreExercised: "",
					Target:              "",
					Verdict:             model.VerdictFail,
					ErrorClass:          model.ErrRuntimeAbsent,
					Detail:              detail,
				})
			}
			skipped = append(skipped, stack)
			continue
		}
		detected = append(detected, stack)
		runtimes = append(runtimes, model.RuntimeDetail{
			Stack: stack,
			// Masked: this resolved path routinely runs through a per-user profile
			// (a pyenv/nvm install, a personal venv), and this field is always in
			// the result JSON, not just --verbose -- the exact file the tool tells
			// a participant to send to a third party.
			Binary:  redact.MaskHomeDir(status.BinaryFound),
			Version: status.Version,
			Pinned:  status.Pinned,
		})
		if w, ok := pinMismatchWarning(status); ok {
			emit(w)
		}

		if entry == "" {
			// The layer2 probe directory wasn't found next to the executable
			// (findLayer2Dir refuses CWD-relative resolution for security).
			// Report SKIP rather than silently doing nothing — and never fall
			// back to a relative path that os.Stat/exec would resolve against
			// the CWD, which would let a planted script in an untrusted
			// working directory get executed instead.
			emit(model.ProbeFragment{
				Runtime: stack, Verdict: model.VerdictSkip, ErrorClass: model.ErrOK,
				Detail: fmt.Sprintf("runtime present (%s), but the layer2 folder is not next to the program — run the program from the folder you unzipped, with layer2 beside it (or set CAMUNDA_LAYER2_DIR to that layer2 folder)", redact.MaskHomeDir(status.BinaryFound)),
			})
			continue
		}

		if _, err := os.Stat(entry); err != nil {
			// A runtime can be present on PATH with no probe shipped for it
			// yet (e.g. a stack added to KnownStacks ahead of its probe).
			// Kept short and plain-language deliberately -- this ends up in
			// the participant-facing result.
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
	return detected, skipped, runtimes, probes
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

		"CAMUNDA_JAVA_HOME":  pc.Runtimes.JavaHome,
		"CAMUNDA_PYTHON_BIN": pc.Runtimes.PythonBin,
		"CAMUNDA_NODE_BIN":   pc.Runtimes.NodeBin,
		"CAMUNDA_DOTNET_BIN": pc.Runtimes.DotnetBin,
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
		// The 8.8+ spelling of the basic-auth pair. The CAMUNDA_BASIC_AUTH_*
		// names above are the older form; both are in circulation, so both have
		// to go.
		"CAMUNDA_CLIENT_AUTH_PASSWORD", "CAMUNDA_CLIENT_AUTH_USERNAME",
		// The ZEEBE_* names predate the CAMUNDA_* convention and are still what
		// the older SaaS credentials download hands out, so a participant can
		// easily have them exported without ever having typed them. Missing
		// these was the gap that mattered: this list is the only thing between
		// an inherited secret and a child process, and a value the tool never
		// saw as a flag is also a value its redaction layer cannot recognize if
		// a probe were to echo it back.
		"ZEEBE_CLIENT_SECRET", "ZEEBE_CLIENT_ID",
		"ZEEBE_AUTHORIZATION_SERVER_URL", "ZEEBE_TOKEN_AUDIENCE",
		"CAMUNDA_CONSOLE_CLIENT_SECRET", "CAMUNDA_CONSOLE_CLIENT_ID",
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

// stderrTruncateLimit bounds how much of a crashed probe's stderr gets
// embedded in its synthesized fragment.
//
// This field is the ONLY diagnostic evidence for a stack that crashed before
// producing any result, so it's deliberately generous rather than kept short
// like other truncated fields (an OAuth error_description, say): a build
// tool's error output is genuinely long, and the useful part is often past
// the first few hundred characters. Still bounded, so a looping/runaway
// build can't balloon the result file.
const stderrTruncateLimit = 4000

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
		// Every probe exits non-zero for exactly one reason: it emitted a
		// fragment whose verdict is neither PASS, WARN nor SKIP. So a non-zero
		// exit with no failing fragment among what we parsed means a tier died
		// BEFORE it could emit anything — a broken compile/build step, or the
		// process being killed on timeout mid-run — and the exit code is the
		// only evidence left. Surface it, because the alternative is a
		// false green: a stack whose mandatory trust tier never ran, but whose
		// optional SDK tier cleanly SKIPped, would otherwise report that single
		// SKIP and the whole run would print "All checks passed."
		if runErr != nil && !reportsFailure(frags) {
			partial := model.ProbeFragment{
				Runtime:    stack,
				Verdict:    model.VerdictProbeError,
				ErrorClass: model.ErrProbeCrashed,
				Detail: fmt.Sprintf("probe exited with error (%v) but reported no failing check — at least one of its checks died before producing a result, "+
					"so this stack was only partially verified (stderr: %s)", runErr, redact.Truncate(stderr.String(), stderrTruncateLimit)),
			}
			frags = append(frags, partial)
			if onFragment != nil {
				onFragment(partial)
			}
		}
		return frags
	}

	// stdout produced no parseable fragment at all — fall back to classifying
	// from the exit code, since the probe's stdout isn't parseable.
	detail := "probe produced no parseable JSON fragment on stdout"
	if runErr != nil {
		detail = fmt.Sprintf("probe exited with error: %v (stderr: %s)", runErr, redact.Truncate(stderr.String(), stderrTruncateLimit))
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

// reportsFailure reports whether a probe's own fragments already account for a
// non-zero exit code, i.e. whether at least one of them carries a verdict that
// makes every probe exit non-zero (FAIL or probe-error). Used to tell "the
// probe exited non-zero because it correctly found a problem" apart from "the
// probe exited non-zero for a reason it never managed to report".
func reportsFailure(frags []model.ProbeFragment) bool {
	for _, f := range frags {
		if f.Verdict == model.VerdictFail || f.Verdict == model.VerdictProbeError {
			return true
		}
	}
	return false
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
