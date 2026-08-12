package report

import (
	"fmt"
	"sort"
	"strings"

	"c8preflight/internal/model"
)

// Header renders the top banner (mode/region/host/proxy). Printed once,
// before any stage runs, so the runner sees something immediately instead
// of a blank terminal while slow/blocked network stages run.
func Header(r model.Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\nCamunda 8 ILT Connectivity Preflight (%s)\n", r.ToolVersion)
	fmt.Fprintf(&b, "  Mode         : %s\n", r.Mode)
	fmt.Fprintf(&b, "  Region       : %s\n", r.Target.Region)
	if r.Target.ClusterID != "" {
		fmt.Fprintf(&b, "  Cluster host : %s / %s\n", r.Target.APIHost, r.Target.ZeebeHost)
	}
	if r.Target.DetectedProxy != "" {
		fmt.Fprintf(&b, "  Proxy        : %s\n", r.Target.DetectedProxy)
	} else {
		b.WriteString("  Proxy        : (none detected)\n")
	}
	if r.StacksRequested != "" {
		fmt.Fprintf(&b, "  Stacks       : %s\n", r.StacksRequested)
	}
	b.WriteString("\n")
	return b.String()
}

// Column widths for StageLine/ProbeLine — sized so the Detail column starts
// at the SAME horizontal position in both Layer 1 and Layer 2 output (a
// verdict tag is always the same width, so it's purely nameWidth+hostWidth
// vs runtimeWidth+targetWidth that has to match — a mismatch there is what
// makes the two columns drift apart). probeTargetWidth is the one that must
// be kept in sync if either pair changes: stageNameWidth+stageHostWidth == probeRuntimeWidth+probeTargetWidth.
const (
	stageNameWidth    = 24
	stageHostWidth    = 32
	probeRuntimeWidth = 10
	probeTargetWidth  = 46
)

// shortFailHeadline maps a remediation/error code to a short, stable phrase
// safe to show inline for a FAIL/WARN/probe-error line, in place of the
// (often long — exception chain + remediation guidance) Detail text. The
// full Detail moves to Notes instead of being shown twice — full duplication
// reads as pure noise once a short version is already on screen — same
// short/inline-vs-long/Notes split PASS entries already use via
// TrustStoreExercised, just keyed off the existing ErrorClass enum instead
// of a separate field, since the code is already stable and shared across
// every language.
var shortFailHeadline = map[model.ErrorClass]string{
	model.ErrDNSFail:               "DNS resolution failed",
	model.ErrConnectRefused:        "connection refused",
	model.ErrConnectTimeout:        "connection timed out",
	model.ErrTLSHandshakeFail:      "TLS handshake failed",
	model.ErrTLSNonPublicIssuer:    "non-public certificate issuer",
	model.ErrALPNDowngradeWarn:     "ALPN downgraded",
	model.ErrProxyAuth407:          "proxy authentication required",
	model.ErrClusterEdge404:        "cluster edge unreachable",
	model.ErrClusterUnhealthy503:   "cluster reports unhealthy",
	model.ErrUnexpectedHTTPStatus:  "unexpected HTTP status",
	model.ErrOAuthTokenFail:        "OAuth token request failed",
	model.ErrOAuthRateLimited:      "OAuth rate-limited",
	model.ErrTopologyAuthFail:      "authentication rejected",
	model.ErrTopologyBadResponse:   "topology response malformed",
	model.ErrWebComponentUnreach:   "web component unreachable",
	model.ErrConfigError:           "configuration error",
	model.ErrRuntimeAbsent:         "runtime not found",
	model.ErrProbeCrashed:          "probe crashed",
	model.ErrConnectionClosed:      "connection closed unexpectedly",
	model.ErrMavenArtifactMissing:  "Maven artifact missing",
	model.ErrMavenMirrorAuth:       "Maven mirror rejected credentials",
	model.ErrMavenMirrorUnreach:    "Maven mirror unreachable",
	model.ErrMavenCentralUnreach:   "Maven Central unreachable",
	model.ErrMavenWrapperBootstrap: "Maven wrapper failed to start",
	model.ErrMavenResolveFail:      "Maven dependency resolution failed",
}

// checklistAction maps a remediation/error code to a plain-language "what
// to do next" instruction — the PRIMARY text Notes shows for that finding by
// default. Written for both audiences at once (a training participant AND
// a technical contact): concrete and imperative ("re-run with --proxy ..."),
// never assumes the reader knows this tool's internal error-class names or
// a specific runtime's SDK internals. The exact flag named (--trust-ca,
// --proxy, etc.) is the tool's own top-level flag, which the launcher
// translates into whatever each language/runtime actually needs -- so the
// SAME instruction is accurate regardless of which stage or which runtime's
// probe hit this code (see the training documentation's per-runtime env-var-name callouts for
// the one documented exception, Java full-mode + a custom CA, which is
// separately flagged by its own CONFIG_ERROR note, not folded in here).
// Codes with no entry (rare/internal cases with nothing a participant can
// fix locally) fall back to showing the raw Detail as-is -- see noteBullet.
var checklistAction = map[model.ErrorClass]string{
	model.ErrDNSFail: "Try a different network (e.g. a mobile hotspot) to see if the problem follows you. " +
		"If it does, ask your network/IT team whether their DNS resolver can reach public internet " +
		"addresses — some corporate networks block or filter DNS lookups.",
	model.ErrConnectRefused: "If this network has a corporate proxy, re-run with --proxy http://<proxy-host>:<port> " +
		"(or set HTTPS_PROXY). If that fixes it, point your training tools at the same proxy — this isn't a " +
		"firewall ticket. If it still fails, ask your network team to allow outbound HTTPS (port 443) to this host.",
	model.ErrConnectTimeout: "Same first step as a refused connection: if this network has a corporate proxy, " +
		"re-run with --proxy http://<proxy-host>:<port> (or set HTTPS_PROXY). A timeout (vs. an immediate refusal) " +
		"often means the traffic is being silently dropped rather than rejected — if a proxy doesn't help, ask " +
		"your network team to allow outbound HTTPS (port 443) to this host.",
	model.ErrTLSHandshakeFail: "This usually means a corporate proxy is inspecting your HTTPS traffic with its own " +
		"certificate, which this tool doesn't trust yet. Ask your IT team for that proxy's root certificate " +
		"(a .pem/.crt file), then re-run with --trust-ca <path-to-file>.",
	model.ErrTLSNonPublicIssuer: "A non-default certificate was presented for this connection — most likely the " +
		"same corporate proxy described above. Import its root certificate with --trust-ca <path-to-file> rather " +
		"than skipping verification.",
	model.ErrALPNDowngradeWarn: "No action needed unless your cohort specifically uses the legacy gRPC client — " +
		"the REST API this tool checks works fine either way.",
	model.ErrProxyAuth407: "Your proxy needs a username and password. Re-run with " +
		"--proxy http://user:pass@<proxy-host>:<port> (Basic auth only). If your proxy uses NTLM/Windows-integrated " +
		"auth instead, this can't be traversed automatically — ask your network team to exempt these hosts.",
	model.ErrClusterEdge404: "This is on our side, not yours — nothing to change in your own setup. Wait about 5 " +
		"minutes and re-run. If it keeps happening, contact the training team.",
	model.ErrClusterUnhealthy503: "This is on our side, not yours — nothing to change in your own setup. Wait about " +
		"5 minutes and re-run. If it keeps happening, contact the training team.",
	model.ErrUnexpectedHTTPStatus: "The server responded, but not in the way this tool expected — usually a " +
		"temporary issue, not something to fix locally. Re-run in a few minutes; if it persists, contact the " +
		"training team with this run's result file.",
	model.ErrOAuthTokenFail: "First, double-check the client ID and client secret you were given are typed " +
		"correctly and haven't expired or been rotated. If a response never came back cleanly at all (rather than " +
		"a clear rejection), a corporate proxy or captive portal may be intercepting the login request with its " +
		"own page — try --proxy http://<proxy-host>:<port> too. If neither explains it, contact the training team.",
	model.ErrOAuthRateLimited: "Too many login attempts at once from this network. Wait a few seconds and re-run, " +
		"or ask your trainer to have participants start a few seconds apart.",
	model.ErrTopologyAuthFail: "Your credentials were rejected. Confirm the client ID/secret you were given are " +
		"current and haven't been revoked; contact the training team if they look correct.",
	model.ErrTopologyBadResponse: "The server replied in a format this tool didn't expect — not something fixable " +
		"locally. Contact the training team with this run's result file.",
	model.ErrWebComponentUnreach: "Try opening this address directly in your browser. If that also fails, ask your " +
		"network team to allow outbound HTTPS to this host — the same allowlist as the main connectivity check.",
	model.ErrRuntimeAbsent: "This programming-language runtime isn't installed on this machine, so its check was " +
		"skipped. Install it if your cohort needs it for the exercises, then re-run.",
	model.ErrProbeCrashed: "This specific check crashed before finishing — usually not something you caused. " +
		"Re-run once; if it keeps crashing, contact the training team with this run's result file.",
	model.ErrConnectionClosed: "The connection opened but then closed before finishing — this is NOT necessarily a " +
		"firewall block (see whether a configuration note above explains it, e.g. a custom certificate setting). " +
		"If nothing above explains it, contact the training team with this run's result file.",
	model.ErrMavenArtifactMissing: "Your Maven mirror doesn't have this exact package version. Ask your build/DevOps " +
		"team to check the mirror's configuration.",
	model.ErrMavenMirrorAuth: "Your Maven mirror rejected the credentials it was given. Ask your build/DevOps team " +
		"to check the mirror's login details.",
	model.ErrMavenMirrorUnreach: "Your Maven mirror couldn't be reached at all. Ask your build/DevOps team to " +
		"confirm it's up and reachable from this network.",
	model.ErrMavenCentralUnreach: "Maven Central itself is unreachable — likely the same network/proxy block as " +
		"the main connectivity check above. The same fix applies: try --proxy, then ask your network team.",
	model.ErrMavenWrapperBootstrap: "The Maven wrapper itself failed to start — usually a network problem fetching " +
		"it. Try again once the main connectivity check above passes.",
	model.ErrMavenResolveFail: "Maven ran but couldn't resolve the training dependencies, and this check didn't " +
		"isolate why. Re-run with --maven-depcheck for a more specific answer.",
}

// shortInlineDetail returns the short headline for a non-PASS/non-SKIP
// verdict when one is registered, else the original detail unchanged (PASS
// and SKIP details are already short by convention, so they pass through).
func shortInlineDetail(verdict model.Verdict, code model.ErrorClass, detail string) string {
	if verdict == model.VerdictPass || verdict == model.VerdictSkip {
		return detail
	}
	if headline, ok := shortFailHeadline[code]; ok {
		return headline
	}
	return detail
}

// StageLine renders one stage's PASS/WARN/FAIL/SKIP line. Callers print this
// immediately as each stage completes (streaming), not buffered to the end
// — a blocked/slow network stage can take 10-30s, and printing nothing
// until the whole run finishes is indistinguishable from a hang.
func StageLine(s model.Stage) string {
	tag := verdictTag(s.Verdict)
	hostPort := s.Host
	if s.Port != 0 {
		hostPort = fmt.Sprintf("%s:%d", s.Host, s.Port)
	}
	detail := shortInlineDetail(s.Verdict, s.RemediationCode, s.Detail)
	if s.HTTPStatus != 0 {
		detail = fmt.Sprintf("[HTTP %d] %s", s.HTTPStatus, detail)
	}
	return fmt.Sprintf("%s %-*s %-*s %s\n", tag, stageNameWidth, s.Name, stageHostWidth, hostPort, detail)
}

// ProbeLine renders one Layer 2 probe fragment's line. The target is shown
// in its own column (mirroring StageLine) so multiple fragments from one
// runtime — e.g. the Python native probe checks both the cluster host and
// login.cloud.camunda.io — are distinguishable instead of looking identical.
// Detail is deliberately kept short at the source for PASS fragments (every
// probe, every language, writes a clean short/long split: the crucial
// outcome goes in Detail, the trust-store description goes in the separate
// TrustStoreExercised field — see Notes). FAIL/WARN/probe-error get the same
// short/long split via shortInlineDetail instead — full Detail moves to
// Notes, not duplicated here.
func ProbeLine(p model.ProbeFragment) string {
	detail := shortInlineDetail(p.Verdict, p.ErrorClass, p.Detail)
	return fmt.Sprintf("%s %-*s %-*s %s\n", verdictTag(p.Verdict), probeRuntimeWidth, p.Runtime, probeTargetWidth, p.Target, detail)
}

// configDiagnosticSuffix is the target-naming convention every Layer 2 probe
// (every language) uses for a config-level diagnostic -- e.g. "wrong env var
// name for this runtime" -- as opposed to an actual connectivity/trust check
// against a real host. See preflight/layer2/*/probe*.{java,py,js}.
const configDiagnosticSuffix = " (config)"

// IsConfigDiagnostic reports whether a probe fragment is a config-level
// diagnostic rather than a check against a real target. These belong in
// Notes only, not the live per-line stream -- printed inline, they interrupt
// the PASS/FAIL listing with a line for a target that was never actually
// probed.
func IsConfigDiagnostic(p model.ProbeFragment) bool {
	return strings.HasSuffix(p.Target, configDiagnosticSuffix)
}

// ProbesHeader renders the "Layer 2" section header, printed once before the
// first probe line if there are any probes to report.
func ProbesHeader() string {
	return "\nLayer 2 (per-runtime trust probes):\n"
}

// RuntimesSkippedLine renders the "runtimes not detected" summary line.
func RuntimesSkippedLine(skipped []string) string {
	if len(skipped) == 0 {
		return ""
	}
	return fmt.Sprintf("\nRuntimes not detected (install and re-run if your cohort needs them): %s\n", strings.Join(skipped, ", "))
}

// Footer renders the final overall verdict block. Requires Overall to
// already be computed (report.BuildOverall), so it's printed last, after
// every stage/probe has completed.
// SkippedTransportNotice is printed in place of the Layer 1 stage lines when
// --skip-transport is set, so the output doesn't look like a hang (nothing
// between the header and the Layer 2 probes) and the reader knows the Go
// transport sweep was deliberately not run.
func SkippedTransportNotice() string {
	return "\nLayer 1 (Go transport/TLS/DNS/OAuth/topology/web checks): SKIPPED (--skip-transport) — running Layer 2 runtime probes only.\n"
}

func Footer(r model.Result) string {
	var b strings.Builder
	b.WriteString("\n")
	switch r.Overall.Verdict {
	case model.VerdictPass:
		b.WriteString("All checks passed.\n")
	case model.VerdictWarn:
		b.WriteString("All checks completed. Check notes below.\n")
	default:
		fmt.Fprintf(&b, "FAILED at stage: %s\n", r.Overall.FailingStage)
	}
	if r.Overall.IsOurClusterProblem {
		b.WriteString("NOTE: this looks like a problem with OUR shared preflight cluster, not your network. Re-run in ~5 minutes.\n")
	}
	return b.String()
}

// noteEntry is one Notes bullet, its sort priority (see notePriority), and
// its verdict — entries are stably sorted by priority before rendering, so
// the most urgent/actionable finding is always first regardless of
// stage/probe order. verdict is used to split a FAILed run's notes into
// "Troubleshooting notes:" (FAIL/probe-error — why it broke) vs "General
// notes:" (WARN and informational PASS notes — worth knowing, didn't break
// anything) — EXCEPT a config diagnostic, which routes to Troubleshooting
// regardless of its own WARN verdict: a misconfigured env var is very often
// the actual root cause of a co-occurring FAIL (e.g. a
// CAMUNDA_CA_CERTIFICATE_PATH config warning explaining a ConnectionClosed
// FAIL landing in General notes would bury it away from the failure it
// explains), so it must not be demoted to "soft, non-blocking" just because
// its own verdict happens to be WARN.
type noteEntry struct {
	priority           int
	verdict            model.Verdict
	isConfigDiagnostic bool
	text               string
}

// notePriority ranks a Notes bullet for ordering — lower sorts first (most
// urgent/actionable at the top). Mirrors ExitCodeFor's already-established
// severity hierarchy (build.go) rather than inventing a new one: a genuine
// auth/network/config FAIL always outranks a cluster-side FAIL — a real,
// actionable problem must never be buried behind "it's probably just our
// cluster blipping, not your fault" — any FAIL outranks any WARN,
// and a purely-informational PASS note (e.g. which trust store a probe
// exercised) sorts last — there's nothing to act on there.
func notePriority(verdict model.Verdict, code model.ErrorClass) int {
	clusterSide := clusterProblemCodes[code]
	switch verdict {
	case model.VerdictFail, model.VerdictProbeError:
		switch {
		case authFailCodes[code]:
			return 0
		case networkFailCodes[code]:
			return 1
		case code == model.ErrConfigError:
			return 2
		case clusterSide:
			return 4
		default:
			return 3
		}
	case model.VerdictWarn:
		if clusterSide {
			return 6
		}
		return 5
	default:
		return 7 // informational PASS note
	}
}

// trustStoreKey groups PASS probe fragments by runtime + trust store used —
// every target a runtime's probes touch (native tier's cluster/OAuth hosts,
// SDK tier's status/topology calls) shares the same process-wide trust
// config, so reporting it once per runtime is exactly as informative as
// once per target, without repeating the same fact 4 times.
type trustStoreKey struct {
	runtime string
	label   string
}

// mergeKey groups a non-PASS finding by its underlying cause -- same check
// name (stage) or runtime (probe), same code, same Detail text -- so every
// affected target collapses into ONE bullet listing them together instead
// of repeating an identical cause once per target. For example, Java's
// TLS_HANDSHAKE_FAIL against two different hosts produces byte-identical
// Detail text (the underlying exception carries no host-specific info), so
// two near-duplicate bullets would add nothing a merged one wouldn't. Detail
// is part of the key deliberately -- two GENUINELY different causes for the
// same code/runtime (rare, but possible) must never merge into one.
type mergeKey struct {
	prefix string // stage Name, or probe Runtime
	code   model.ErrorClass
	detail string
}

type mergeGroup struct {
	verdict            model.Verdict
	priority           int
	isConfigDiagnostic bool
	targets            []string // Host/Target (or, for a cluster-merged group, source name), first-seen order; "" entries omitted
	sampleDetail       string   // first-seen Detail -- shown under --verbose when the group's own key.detail is blank (cluster merge)
}

// clusterMergeKeyPrefix/clusterMergeLabel special-case clusterProblemCodes:
// unlike every other code, a down shared cluster produces the SAME finding
// regardless of which stage or which of the 3 languages' probes hit it --
// e.g. a 503-unhealthy cluster would otherwise print one near-identical
// bullet per source (status stage + java + python + typescript probes, 4
// lines saying the same thing), which reads as 4 separate problems to a
// participant when it is exactly one. So these merge across every source, keyed on the code
// ALONE (no prefix, no detail -- the detail text differs per source purely
// because each check phrases "cluster said 503" slightly differently, not
// because the underlying cause differs).
const (
	clusterMergeKeyPrefix = "\x00cluster"
	clusterMergeLabel     = "shared training cluster"
)

// systemicMergeCodes are ErrorClasses where hitting the code AT ALL means the
// same underlying condition regardless of which stage or probe noticed it --
// a corporate proxy that TLS-intercepts (or a firewall that blocks/drops)
// outbound HTTPS does so identically for every host this tool touches, not
// just one. For example, a MITM proxy would otherwise produce 12
// near-identical TLS_HANDSHAKE_FAIL bullets -- both api/zeebe status stages,
// oauth reachability, all 5 web components, and all 3 language probes -- one
// per stage/runtime name (the existing per-source merge only collapses
// targets WITHIN a source, e.g. the 2 hosts inside one stage), reading as 12
// separate problems to a participant instead of "your whole network path is
// intercepted, one fix covers all of it." These merge like clusterProblemCodes
// -- keyed on the code alone, ignoring which stage/probe/host reported it --
// EXCLUDING codes whose cause is plausibly source-specific rather than
// path-wide (auth, config, probe-crash, Maven, cluster-side -- handled
// separately above).
var systemicMergeCodes = map[model.ErrorClass]bool{
	model.ErrDNSFail:          true,
	model.ErrConnectRefused:   true,
	model.ErrConnectTimeout:   true,
	model.ErrTLSHandshakeFail: true,
	model.ErrProxyAuth407:     true,
}

const (
	systemicMergeKeyPrefix = "\x00systemic"
	systemicMergeLabel     = "every check that touched the network"
)

// Notes renders a condensed, priority-ordered end-of-run recap. By default,
// every non-PASS, non-SKIP stage/probe bullet shows a plain-language "what
// to do next" instruction (see checklistAction) -- readable by a training
// participant, not just an engineer. Pass Verbose (mirrors --verbose) to
// additionally show the raw technical detail (the exact exception text)
// under each such bullet, for a technical reader who wants it. Findings
// with no mapped checklist action (rare/internal codes) fall back to
// showing Detail as the primary text, same as before. PASS entries with a
// trust-store description worth mentioning get one note per runtime, in
// full (also never shown inline). A failed run gets two headed sections —
// "Troubleshooting notes:" (FAIL/probe-error only) then "General notes:"
// (WARN + informational PASS notes) — so the actual cause of the failure
// isn't diluted by softer, non-blocking observations. A WARN-only or clean
// PASS run gets a single "Notes:" section instead. Returns "" only when
// there is truly nothing to add.
func Notes(r model.Result) string {
	var entries []noteEntry
	addEntry := func(verdict model.Verdict, priority int, isConfigDiagnostic bool, text string) {
		entries = append(entries, noteEntry{priority: priority, verdict: verdict, isConfigDiagnostic: isConfigDiagnostic, text: text})
	}

	groups := map[mergeKey]*mergeGroup{}
	var groupOrder []mergeKey
	mergeInto := func(key mergeKey, verdict model.Verdict, priority int, isConfigDiagnostic bool, target, detail string) {
		g, ok := groups[key]
		if !ok {
			g = &mergeGroup{verdict: verdict, priority: priority, isConfigDiagnostic: isConfigDiagnostic, sampleDetail: detail}
			groups[key] = g
			groupOrder = append(groupOrder, key)
		} else if priority < g.priority {
			// A more severe source merging in later must promote the whole
			// group -- e.g. one runtime reporting the shared cluster as WARN
			// and another as FAIL must show as FAIL, never masked by whichever
			// source happened to be processed first.
			g.verdict = verdict
			g.priority = priority
		}
		if target != "" {
			for _, existing := range g.targets {
				if existing == target {
					return
				}
			}
			g.targets = append(g.targets, target)
		}
	}

	for _, s := range r.Stages {
		if s.Verdict == model.VerdictPass || s.Verdict == model.VerdictSkip {
			continue
		}
		switch {
		case clusterProblemCodes[s.RemediationCode]:
			mergeInto(mergeKey{prefix: clusterMergeKeyPrefix, code: s.RemediationCode}, s.Verdict, notePriority(s.Verdict, s.RemediationCode), false, s.Name, s.Detail)
		case systemicMergeCodes[s.RemediationCode]:
			mergeInto(mergeKey{prefix: systemicMergeKeyPrefix, code: s.RemediationCode}, s.Verdict, notePriority(s.Verdict, s.RemediationCode), false, s.Name, s.Detail)
		default:
			mergeInto(mergeKey{prefix: s.Name, code: s.RemediationCode, detail: s.Detail}, s.Verdict, notePriority(s.Verdict, s.RemediationCode), false, s.Host, s.Detail)
		}
	}

	var trustStoreOrder []trustStoreKey
	seenTrustStore := map[trustStoreKey]bool{}
	for _, p := range r.Probes {
		switch p.Verdict {
		case model.VerdictSkip:
			continue
		case model.VerdictPass:
			if p.TrustStoreExercised == "" {
				continue
			}
			key := trustStoreKey{runtime: p.Runtime, label: p.TrustStoreExercised}
			if !seenTrustStore[key] {
				seenTrustStore[key] = true
				trustStoreOrder = append(trustStoreOrder, key)
			}
		default:
			isConfig := IsConfigDiagnostic(p)
			priority := notePriority(p.Verdict, p.ErrorClass)
			if isConfig {
				// Ranks like a config-error FAIL (2), not a plain WARN (5) --
				// this is very often the root cause of a co-occurring FAIL, so
				// it belongs near the top, read before the symptom it explains.
				priority = 2
			}
			switch {
			case clusterProblemCodes[p.ErrorClass]:
				mergeInto(mergeKey{prefix: clusterMergeKeyPrefix, code: p.ErrorClass}, p.Verdict, priority, isConfig, p.Runtime, p.Detail)
			case systemicMergeCodes[p.ErrorClass]:
				mergeInto(mergeKey{prefix: systemicMergeKeyPrefix, code: p.ErrorClass}, p.Verdict, priority, isConfig, p.Runtime, p.Detail)
			default:
				mergeInto(mergeKey{prefix: p.Runtime, code: p.ErrorClass, detail: p.Detail}, p.Verdict, priority, isConfig, p.Target, p.Detail)
			}
		}
	}

	for _, key := range groupOrder {
		g := groups[key]
		prefix := key.prefix
		switch prefix {
		case clusterMergeKeyPrefix:
			prefix = clusterMergeLabel
		case systemicMergeKeyPrefix:
			prefix = systemicMergeLabel
		}
		label := prefix
		if len(g.targets) > 0 {
			label = fmt.Sprintf("%s (%s)", prefix, strings.Join(g.targets, ", "))
		}
		detail := key.detail
		if detail == "" {
			detail = g.sampleDetail
		}
		addEntry(g.verdict, g.priority, g.isConfigDiagnostic, noteBullet(label, key.code, detail, r.Verbose))
	}

	for _, k := range trustStoreOrder {
		sentence := fmt.Sprintf("  * %s used %s to verify the connection.\n", k.runtime, k.label)
		addEntry(model.VerdictPass, notePriority(model.VerdictPass, model.ErrOK), false, sentence)
	}

	if len(entries) == 0 {
		return ""
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].priority < entries[j].priority })

	var b strings.Builder
	if r.Overall.Verdict != model.VerdictFail {
		b.WriteString("\nNotes:\n")
		for _, e := range entries {
			b.WriteString(e.text)
		}
		return b.String()
	}

	// A failed run gets two sections: "Troubleshooting notes" (FAIL/
	// probe-error, plus any config diagnostic — the actual reason it broke,
	// or a very likely cause of it) and "General notes" below it (other WARN
	// + informational PASS notes — worth knowing, but not why it failed).
	// Keeping them apart means scanning "Troubleshooting notes" during an
	// incident isn't diluted by softer, non-blocking observations.
	var trouble, general []noteEntry
	for _, e := range entries {
		if e.verdict == model.VerdictFail || e.verdict == model.VerdictProbeError || e.isConfigDiagnostic {
			trouble = append(trouble, e)
		} else {
			general = append(general, e)
		}
	}
	if len(trouble) > 0 {
		b.WriteString("\nTroubleshooting notes:\n")
		for _, e := range trouble {
			b.WriteString(e.text)
		}
	}
	if len(general) > 0 {
		b.WriteString("\nGeneral notes:\n")
		for _, e := range general {
			b.WriteString(e.text)
		}
	}
	return b.String()
}

// noteBullet renders one Notes line. By default the primary text is the
// plain-language checklistAction for code, when one is mapped -- readable
// by a training participant, not just an engineer. Codes with no mapped
// action (rare/internal cases with nothing fixable locally) fall back to
// showing detail as-is. verbose additionally appends the raw technical
// detail on its own indented line, for a reader who wants the exact
// exception text -- e.g. to file a bug or hand to their own IT team.
func noteBullet(label string, code model.ErrorClass, detail string, verbose bool) string {
	tag := string(code)
	if clusterProblemCodes[code] {
		tag = tag + ", cluster-side — not your network"
	}

	action, hasAction := checklistAction[code]
	primary := detail
	if hasAction {
		primary = action
	}

	var b strings.Builder
	if code == "" || code == model.ErrOK {
		fmt.Fprintf(&b, "  * %s: %s\n", label, primary)
	} else {
		fmt.Fprintf(&b, "  * %s [%s]: %s\n", label, tag, primary)
	}
	if verbose && hasAction {
		fmt.Fprintf(&b, "      Technical detail: %s\n", detail)
	}
	return b.String()
}

// HumanSummary renders the full stdout summary in one string — used for the
// --log-file content (which is written once, after the run, so streaming
// doesn't apply there). Composed from the same Header/StageLine/Footer
// pieces main.go streams to stdout, so there is one source of truth for the
// format shown to the person running the tool.
func HumanSummary(r model.Result) string {
	var b strings.Builder
	b.WriteString(Header(r))
	for _, s := range r.Stages {
		b.WriteString(StageLine(s))
	}
	if len(r.Probes) > 0 {
		b.WriteString(ProbesHeader())
		for _, p := range r.Probes {
			if IsConfigDiagnostic(p) {
				continue
			}
			b.WriteString(ProbeLine(p))
		}
	}
	b.WriteString(RuntimesSkippedLine(r.RuntimesSkipped))
	b.WriteString(Footer(r))
	b.WriteString(Notes(r))
	return b.String()
}

func verdictTag(v model.Verdict) string {
	switch v {
	case model.VerdictPass:
		return "[PASS]"
	case model.VerdictWarn:
		return "[WARN]"
	case model.VerdictSkip:
		return "[SKIP]"
	default:
		return "[FAIL]"
	}
}
