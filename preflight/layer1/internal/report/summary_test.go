package report

import (
	"strings"
	"testing"

	"c8preflight/internal/model"
)

func TestIsConfigDiagnostic(t *testing.T) {
	cases := []struct {
		target string
		want   bool
	}{
		{"bru-2.api.camunda.io (config)", true},
		{"bru-2.api.camunda.io:443", false},
		{"bru-2.api.camunda.io (sdk status)", false},
		{"", false},
	}
	for _, c := range cases {
		if got := IsConfigDiagnostic(model.ProbeFragment{Target: c.target}); got != c.want {
			t.Errorf("IsConfigDiagnostic(target=%q) = %v, want %v", c.target, got, c.want)
		}
	}
}

// HumanSummary (used for --log-file) must match what main.go streams to
// stdout: config-level diagnostics are Notes-only, never a per-line entry.
func TestHumanSummary_OmitsConfigDiagnosticsFromProbeListing(t *testing.T) {
	r := model.Result{
		Probes: []model.ProbeFragment{
			{Runtime: "java", Target: "bru-2.api.camunda.io (config)", Verdict: model.VerdictWarn, ErrorClass: model.ErrConfigError, Detail: "wrong env var name"},
			{Runtime: "java", Target: "bru-2.api.camunda.io:443", Verdict: model.VerdictPass, ErrorClass: model.ErrOK, Detail: "TLS handshake succeeded (10ms)"},
		},
		Overall: model.Overall{Verdict: model.VerdictWarn},
	}
	got := HumanSummary(r)
	if strings.Contains(got, "[WARN] java       bru-2.api.camunda.io (config)") {
		t.Fatalf("expected the config diagnostic to be omitted from the probe listing, got %q", got)
	}
	if !strings.Contains(got, "wrong env var name") {
		t.Fatalf("expected the config diagnostic's detail to still appear (in Notes), got %q", got)
	}
	if !strings.Contains(got, "bru-2.api.camunda.io:443") {
		t.Fatalf("expected the real target's PASS line to still print, got %q", got)
	}
}

func TestNotes_CleanRunProducesNothing(t *testing.T) {
	r := model.Result{
		Stages:  []model.Stage{{Name: "dns", Verdict: model.VerdictPass, RemediationCode: model.ErrOK}},
		Probes:  []model.ProbeFragment{{Runtime: "java", Target: "x:443", Verdict: model.VerdictPass, ErrorClass: model.ErrOK}},
		Overall: model.Overall{Verdict: model.VerdictPass},
	}
	if got := Notes(r); got != "" {
		t.Fatalf("expected empty Notes for a fully clean run, got %q", got)
	}
}

func TestNotes_SkipEntriesAreOmitted(t *testing.T) {
	r := model.Result{
		Probes: []model.ProbeFragment{
			{Runtime: "python", Target: "x:443", Verdict: model.VerdictSkip, ErrorClass: model.ErrOK, Detail: "runtime not detected"},
		},
		Overall: model.Overall{Verdict: model.VerdictPass},
	}
	if got := Notes(r); got != "" {
		t.Fatalf("expected SKIP-only entries to produce no Notes, got %q", got)
	}
}

func TestNotes_WarnRunUsesNotesHeadingAndFlagsClusterSide(t *testing.T) {
	r := model.Result{
		Stages: []model.Stage{
			{Name: "topology", Host: "bru-2.api.camunda.io", Verdict: model.VerdictWarn, RemediationCode: model.ErrClusterEdge404, Detail: "cluster blip"},
		},
		Overall: model.Overall{Verdict: model.VerdictWarn},
	}
	got := Notes(r)
	if !strings.HasPrefix(strings.TrimPrefix(got, "\n"), "Notes:") {
		t.Fatalf("expected a WARN-only (non-failing) run to use the 'Notes:' heading, got %q", got)
	}
	if strings.Contains(got, "Troubleshooting") {
		t.Fatalf("did not expect 'Troubleshooting' heading on a non-failing run, got %q", got)
	}
	if !strings.Contains(got, "cluster-side") {
		t.Fatalf("expected the cluster-side annotation on CLUSTER_EDGE_404, got %q", got)
	}
}

func TestNotes_FailRunUsesTroubleshootingHeading(t *testing.T) {
	r := model.Result{
		Stages: []model.Stage{
			{Name: "dns", Host: "bru-2.api.camunda.io", Verdict: model.VerdictFail, RemediationCode: model.ErrDNSFail, Detail: "hostname did not resolve"},
		},
		Overall: model.Overall{Verdict: model.VerdictFail, FailingStage: "dns"},
	}
	got := Notes(r)
	if !strings.HasPrefix(strings.TrimPrefix(got, "\n"), "Troubleshooting notes:") {
		t.Fatalf("expected a FAILed run to use the 'Troubleshooting notes:' heading, got %q", got)
	}
}

// A FAIL-only run (no WARN, no informational PASS notes) gets ONLY
// "Troubleshooting notes:" -- no empty "General notes:" heading.
func TestNotes_FailOnlyRunHasNoGeneralNotesHeading(t *testing.T) {
	r := model.Result{
		Stages:  []model.Stage{{Name: "dns", Host: "x", Verdict: model.VerdictFail, RemediationCode: model.ErrDNSFail, Detail: "hostname did not resolve"}},
		Overall: model.Overall{Verdict: model.VerdictFail, FailingStage: "dns"},
	}
	if got := Notes(r); strings.Contains(got, "General notes:") {
		t.Fatalf("did not expect a 'General notes:' heading with nothing to put in it, got %q", got)
	}
}

// A failed run with BOTH a genuine FAIL and a non-blocking WARN must split:
// the FAIL under "Troubleshooting notes:", the WARN under "General notes:"
// below it -- not lumped together, and not reordered (Troubleshooting first).
func TestNotes_FailRunSplitsWarnIntoGeneralNotes(t *testing.T) {
	r := model.Result{
		Stages: []model.Stage{
			{Name: "dns", Host: "bru-2.api.camunda.io", Verdict: model.VerdictFail, RemediationCode: model.ErrDNSFail, Detail: "hostname did not resolve"},
			{Name: "tls", Host: "bru-2.api.camunda.io", Verdict: model.VerdictWarn, RemediationCode: model.ErrTLSNonPublicIssuer, Detail: "non-public issuer"},
		},
		Overall: model.Overall{Verdict: model.VerdictFail, FailingStage: "dns"},
	}
	got := Notes(r)
	troubleIdx := strings.Index(got, "Troubleshooting notes:")
	generalIdx := strings.Index(got, "General notes:")
	// Stage bullets are a short index ("see above") now, not a repeat of
	// Detail -- already shown in full inline, so Notes just needs to point
	// at the right stage/code, not duplicate the message.
	failIdx := strings.Index(got, "every check that touched the network (dns) [DNS_FAIL]")
	warnIdx := strings.Index(got, "tls (bru-2.api.camunda.io) [TLS_NON_PUBLIC_ISSUER]")
	if troubleIdx < 0 || generalIdx < 0 {
		t.Fatalf("expected both headings to appear, got %q", got)
	}
	if troubleIdx > generalIdx {
		t.Fatalf("expected 'Troubleshooting notes:' before 'General notes:', got %q", got)
	}
	if !(troubleIdx < failIdx && failIdx < generalIdx) {
		t.Fatalf("expected the FAIL bullet strictly between the two headings, got %q", got)
	}
	if warnIdx < generalIdx {
		t.Fatalf("expected the WARN bullet to appear after 'General notes:', not before, got %q", got)
	}
}

// A FAIL stage/probe shows only a short, stable headline inline (StageLine/
// ProbeLine) -- the full Detail (exception chain + remediation guidance)
// moves to Notes instead, so it's never shown twice -- full duplication
// would read as pure noise once the same text was already on screen.
func TestStageLine_UsesShortHeadlineForFail(t *testing.T) {
	s := model.Stage{Name: "dns", Host: "x", Verdict: model.VerdictFail, RemediationCode: model.ErrDNSFail, Detail: "hostname did not resolve, a very long exception chain that belongs in Notes instead"}
	got := StageLine(s)
	if strings.Contains(got, "a very long exception chain") {
		t.Fatalf("expected the long Detail NOT to appear inline, got %q", got)
	}
	if !strings.Contains(got, "DNS resolution failed") {
		t.Fatalf("expected the short headline 'DNS resolution failed' inline, got %q", got)
	}
}

func TestProbeLine_UsesShortHeadlineForFail(t *testing.T) {
	p := model.ProbeFragment{Runtime: "java", Target: "x:443", Verdict: model.VerdictFail, ErrorClass: model.ErrTLSHandshakeFail, Detail: "certificate not trusted by your custom certificate (...): javax.net.ssl.SSLHandshakeException: a very long exception chain"}
	got := ProbeLine(p)
	if strings.Contains(got, "a very long exception chain") {
		t.Fatalf("expected the long Detail NOT to appear inline, got %q", got)
	}
	if !strings.Contains(got, "TLS handshake failed") {
		t.Fatalf("expected the short headline 'TLS handshake failed' inline, got %q", got)
	}
}

// PASS and SKIP details are already short by convention -- shortInlineDetail
// must pass them through unchanged, not apply a headline lookup.
func TestStageLine_PassAndSkipDetailsPassThroughUnchanged(t *testing.T) {
	pass := StageLine(model.Stage{Name: "dns", Verdict: model.VerdictPass, RemediationCode: model.ErrOK, Detail: "resolved to: 1.2.3.4"})
	if !strings.Contains(pass, "resolved to: 1.2.3.4") {
		t.Fatalf("expected PASS detail to pass through unchanged, got %q", pass)
	}
	skip := StageLine(model.Stage{Name: "oauth-reachability", Verdict: model.VerdictSkip, RemediationCode: model.ErrOK, Detail: "network-mode-only check"})
	if !strings.Contains(skip, "network-mode-only check") {
		t.Fatalf("expected SKIP detail to pass through unchanged, got %q", skip)
	}
}

// By default, a code with a mapped checklistAction (e.g. DNS_FAIL) shows
// that plain-language instruction in Notes, NOT the raw Detail -- readable
// by a training participant, not just an engineer. The raw Detail (exact
// exception text) only appears when Verbose is set.
func TestNotes_DefaultShowsChecklistActionNotRawDetail(t *testing.T) {
	r := model.Result{
		Stages: []model.Stage{
			{Name: "dns", Host: "x", Verdict: model.VerdictFail, RemediationCode: model.ErrDNSFail, Detail: "hostname did not resolve, a very long exception chain"},
		},
		Overall: model.Overall{Verdict: model.VerdictFail, FailingStage: "dns"},
	}
	got := Notes(r)
	if strings.Contains(got, "a very long exception chain") {
		t.Fatalf("expected the raw Detail NOT to appear by default (Verbose is false), got %q", got)
	}
	if !strings.Contains(got, "Try a different network") {
		t.Fatalf("expected the plain-language checklistAction to appear, got %q", got)
	}
}

// With Verbose set, the raw Detail appears TOO, alongside the checklist
// action -- for a technical reader who wants the exact exception text.
func TestNotes_VerboseAddsRawDetailAlongsideChecklistAction(t *testing.T) {
	r := model.Result{
		Stages: []model.Stage{
			{Name: "dns", Host: "x", Verdict: model.VerdictFail, RemediationCode: model.ErrDNSFail, Detail: "hostname did not resolve, a very long exception chain"},
		},
		Overall: model.Overall{Verdict: model.VerdictFail, FailingStage: "dns"},
		Verbose: true,
	}
	got := Notes(r)
	if !strings.Contains(got, "a very long exception chain") {
		t.Fatalf("expected the raw Detail to appear when Verbose is true, got %q", got)
	}
	if !strings.Contains(got, "Try a different network") {
		t.Fatalf("expected the plain-language checklistAction to still appear too, got %q", got)
	}
}

// CONFIG_ERROR has NO mapped checklistAction deliberately -- the specific
// fix (which env var, which flag) varies per call site and is already
// baked into Detail, so a generic action would be less useful than the
// specific text already crafted for each case. Falls back to Detail as the
// primary text, same as before -- with or without Verbose.
func TestNotes_NoActionMappedFallsBackToDetail(t *testing.T) {
	r := model.Result{
		Stages: []model.Stage{
			{Name: "oauth-token", Host: "x", Verdict: model.VerdictFail, RemediationCode: model.ErrConfigError, Detail: "could not build OAuth request: some very specific config problem"},
		},
		Overall: model.Overall{Verdict: model.VerdictFail, FailingStage: "oauth-token"},
	}
	got := Notes(r)
	if !strings.Contains(got, "could not build OAuth request: some very specific config problem") {
		t.Fatalf("expected Detail to be shown as the primary text when no action is mapped, got %q", got)
	}
}

// A config diagnostic is deliberately suppressed from the live per-line
// stream (see IsConfigDiagnostic/main.go's onProbeFragment) -- Notes is its
// ONLY appearance, so unlike other findings it must keep full detail.
func TestNotes_ConfigDiagnosticKeepsFullDetailInNotes(t *testing.T) {
	r := model.Result{
		Probes: []model.ProbeFragment{
			{Runtime: "java", Target: "bru-2.api.camunda.io (config)", Verdict: model.VerdictWarn, ErrorClass: model.ErrConfigError, Detail: "CAMUNDA_MTLS_CA_PATH is set, but Java needs a different variable name."},
		},
		Overall: model.Overall{Verdict: model.VerdictWarn},
	}
	got := Notes(r)
	if !strings.Contains(got, "CAMUNDA_MTLS_CA_PATH is set, but Java needs a different variable name.") {
		t.Fatalf("expected a config diagnostic to keep its full detail in Notes (its only appearance), got %q", got)
	}
}

// A config diagnostic (WARN verdict) is very often the root cause of a
// co-occurring FAIL -- e.g. a CAMUNDA_CA_CERTIFICATE_PATH misconfiguration
// causing a ConnectionClosedException FAIL a few lines later. It must route
// to "Troubleshooting notes:" (not "General notes:") despite its own WARN
// verdict, and rank near the top so the root cause reads before the symptom.
func TestNotes_ConfigDiagnosticRoutesToTroubleshootingWithFail(t *testing.T) {
	r := model.Result{
		Probes: []model.ProbeFragment{
			{Runtime: "java", Target: "bru-2.zeebe.camunda.io (config)", Verdict: model.VerdictWarn, ErrorClass: model.ErrConfigError, Detail: "CAMUNDA_CA_CERTIFICATE_PATH is set, but the OAuth client does not inherit it."},
			{Runtime: "java", Target: "bru-2.zeebe.camunda.io (sdk status)", Verdict: model.VerdictFail, ErrorClass: model.ErrConnectionClosed, Detail: "connection failed: ConnectionClosedException"},
		},
		Overall: model.Overall{Verdict: model.VerdictFail, FailingStage: "layer2:java"},
	}
	got := Notes(r)
	troubleIdx := strings.Index(got, "Troubleshooting notes:")
	generalIdx := strings.Index(got, "General notes:")
	// CONFIG_ERROR has no mapped checklistAction, so its raw Detail still
	// shows by default. CONNECTION_CLOSED DOES have one now, so its bullet
	// is identified by the code tag instead of the (no-longer-shown-by-
	// default) raw Detail text.
	configIdx := strings.Index(got, "CAMUNDA_CA_CERTIFICATE_PATH is set")
	failIdx := strings.Index(got, "[CONNECTION_CLOSED]")
	if configIdx < 0 || failIdx < 0 {
		t.Fatalf("expected both bullets to appear, got %q", got)
	}
	if generalIdx >= 0 && configIdx > generalIdx {
		t.Fatalf("expected the config diagnostic to appear before 'General notes:' (i.e. under Troubleshooting), got %q", got)
	}
	if troubleIdx < 0 || configIdx < troubleIdx {
		t.Fatalf("expected the config diagnostic to appear after the 'Troubleshooting notes:' heading, got %q", got)
	}
	if configIdx > failIdx {
		t.Fatalf("expected the config diagnostic (root cause) to rank before the FAIL symptom it explains, got %q", got)
	}
}

// A PASS-with-trust-store informational note on a failed run belongs in
// "General notes:", not "Troubleshooting notes:" -- it's not why it failed.
func TestNotes_FailRunPutsInformationalPassNoteInGeneralNotes(t *testing.T) {
	r := model.Result{
		Stages: []model.Stage{
			{Name: "dns", Host: "x", Verdict: model.VerdictFail, RemediationCode: model.ErrDNSFail, Detail: "hostname did not resolve"},
		},
		Probes: []model.ProbeFragment{
			{Runtime: "java", Target: "x:443", Verdict: model.VerdictPass, ErrorClass: model.ErrOK, TrustStoreExercised: "the default certificate store"},
		},
		Overall: model.Overall{Verdict: model.VerdictFail, FailingStage: "dns"},
	}
	got := Notes(r)
	generalIdx := strings.Index(got, "General notes:")
	trustIdx := strings.Index(got, "java used the default certificate store to verify the connection.")
	if generalIdx < 0 || trustIdx < 0 {
		t.Fatalf("expected both 'General notes:' and the trust-store note to appear, got %q", got)
	}
	if trustIdx < generalIdx {
		t.Fatalf("expected the trust-store note to appear under 'General notes:', not 'Troubleshooting notes:', got %q", got)
	}
}

// A probe-level crash (e.g. SdkProbe's crashFragment) carries no Target --
// the bullet's label must not end up with a stray double space.
func TestNotes_ProbeWithoutTargetHasNoDoubleSpace(t *testing.T) {
	r := model.Result{
		Probes:  []model.ProbeFragment{{Runtime: "java", Target: "", Verdict: model.VerdictFail, ErrorClass: model.ErrProbeCrashed, Detail: "probe crashed: boom"}},
		Overall: model.Overall{Verdict: model.VerdictFail, FailingStage: "layer2:java"},
	}
	got := Notes(r)
	if strings.Contains(got, "java  [") {
		t.Fatalf("expected no double space before the remediation code, got %q", got)
	}
	if !strings.Contains(got, "java [PROBE_CRASHED]") {
		t.Fatalf("expected a clean 'java [PROBE_CRASHED]' bullet, got %q", got)
	}
}

// A PASS probe fragment's TrustStoreExercised (a separate structured field —
// every probe, every language, keeps Detail short and puts the trust-store
// description here instead of duplicating it into Detail) surfaces as its
// own informational Notes bullet, even on an otherwise fully clean run.
func TestNotes_PassWithTrustStoreProducesInformationalNote(t *testing.T) {
	r := model.Result{
		Probes: []model.ProbeFragment{
			{
				Runtime: "java", Target: "bru-2.api.camunda.io:443", Verdict: model.VerdictPass,
				ErrorClass: model.ErrOK, Detail: "TLS handshake succeeded (200ms)",
				TrustStoreExercised: "custom truststore file: custom-truststore.jks",
			},
		},
		Overall: model.Overall{Verdict: model.VerdictPass},
	}
	got := Notes(r)
	if !strings.HasPrefix(strings.TrimPrefix(got, "\n"), "Notes:") {
		t.Fatalf("expected a clean PASS with trust-store detail to use the 'Notes:' heading, got %q", got)
	}
	if !strings.Contains(got, "java used custom truststore file: custom-truststore.jks to verify the connection.") {
		t.Fatalf("expected the trust-store description to appear as its own full-sentence note, got %q", got)
	}
	if strings.Contains(got, "[OK]") {
		t.Fatalf("did not expect an [OK] tag on a purely informational note, got %q", got)
	}
}

// A runtime's trust store is process-wide (or client-wide), so 4 probe
// fragments from the same runtime reporting the identical trust store (the
// real shape: native tier's 2 targets + SDK tier's status/topology calls)
// must collapse to ONE informational note, not 4 near-identical ones.
func TestNotes_GroupsTrustStoreNotesByRuntime(t *testing.T) {
	sameStore := "your custom certificate file (custom-truststore.jks)"
	r := model.Result{
		Probes: []model.ProbeFragment{
			{Runtime: "java", Target: "bru-2.api.camunda.io:443", Verdict: model.VerdictPass, ErrorClass: model.ErrOK, TrustStoreExercised: sameStore},
			{Runtime: "java", Target: "login.cloud.camunda.io:443", Verdict: model.VerdictPass, ErrorClass: model.ErrOK, TrustStoreExercised: sameStore},
			{Runtime: "java", Target: "bru-2.api.camunda.io (sdk status)", Verdict: model.VerdictPass, ErrorClass: model.ErrOK, TrustStoreExercised: sameStore},
			{Runtime: "java", Target: "bru-2.api.camunda.io (sdk topology)", Verdict: model.VerdictPass, ErrorClass: model.ErrOK, TrustStoreExercised: sameStore},
		},
		Overall: model.Overall{Verdict: model.VerdictPass},
	}
	got := Notes(r)
	if n := strings.Count(got, "to verify the connection."); n != 1 {
		t.Fatalf("expected exactly 1 trust-store note for 4 same-runtime same-store fragments, got %d in %q", n, got)
	}
	if strings.Contains(got, "bru-2.api.camunda.io:443") || strings.Contains(got, "(sdk status)") {
		t.Fatalf("expected the grouped note to drop per-target labels, got %q", got)
	}
}

// Different runtimes (or the same runtime with genuinely different trust
// stores, however unlikely) must NOT be collapsed into each other.
func TestNotes_KeepsDistinctTrustStoresSeparate(t *testing.T) {
	r := model.Result{
		Probes: []model.ProbeFragment{
			{Runtime: "java", Target: "x:443", Verdict: model.VerdictPass, ErrorClass: model.ErrOK, TrustStoreExercised: "your custom certificate file (a.jks)"},
			{Runtime: "python", Target: "x:443", Verdict: model.VerdictPass, ErrorClass: model.ErrOK, TrustStoreExercised: "the default certificate bundle"},
		},
		Overall: model.Overall{Verdict: model.VerdictPass},
	}
	got := Notes(r)
	if n := strings.Count(got, "to verify the connection."); n != 2 {
		t.Fatalf("expected 2 distinct trust-store notes (different runtimes), got %d in %q", n, got)
	}
}

// The native and SDK tier of a probe run as separate processes and can
// independently emit the byte-identical config warning (same config target,
// same message) — that must collapse to one bullet, not two.
func TestNotes_CollapsesExactDuplicateWarnings(t *testing.T) {
	r := model.Result{
		Probes: []model.ProbeFragment{
			{Runtime: "java", Target: "bru-2.api.camunda.io (config)", Verdict: model.VerdictWarn, ErrorClass: model.ErrConfigError, Detail: "CAMUNDA_MTLS_CA_PATH is set, but Java needs a different variable name."},
			{Runtime: "java", Target: "bru-2.api.camunda.io:443", Verdict: model.VerdictPass, ErrorClass: model.ErrOK, TrustStoreExercised: "the default certificate store"},
			{Runtime: "java", Target: "bru-2.api.camunda.io (config)", Verdict: model.VerdictWarn, ErrorClass: model.ErrConfigError, Detail: "CAMUNDA_MTLS_CA_PATH is set, but Java needs a different variable name."},
			{Runtime: "java", Target: "bru-2.api.camunda.io (sdk status)", Verdict: model.VerdictPass, ErrorClass: model.ErrOK, TrustStoreExercised: "the default certificate store"},
		},
		Overall: model.Overall{Verdict: model.VerdictWarn},
	}
	got := Notes(r)
	if n := strings.Count(got, "needs a different variable name"); n != 1 {
		t.Fatalf("expected the identical config warning to collapse to 1 bullet, got %d in %q", n, got)
	}
}

// A PASS probe with no TrustStoreExercised (e.g. Detail is empty/short and
// nothing else to add) contributes no bullet at all.
func TestNotes_PassWithoutTrustStoreProducesNothing(t *testing.T) {
	r := model.Result{
		Probes:  []model.ProbeFragment{{Runtime: "java", Target: "x:443", Verdict: model.VerdictPass, ErrorClass: model.ErrOK, Detail: "SDK newStatusRequest() succeeded"}},
		Overall: model.Overall{Verdict: model.VerdictPass},
	}
	if got := Notes(r); got != "" {
		t.Fatalf("expected no Notes for a PASS with nothing extra to say, got %q", got)
	}
}

// Bullets sort by severity (mirroring ExitCodeFor's hierarchy in build.go),
// not by insertion order: auth-fail first, then network-fail, config-error,
// a genuine (non-cluster-side) generic FAIL, then the cluster-side group
// (merged across sources -- see TestNotes_MergesClusterSideAcrossAllSources
// -- and promoted to its most severe source, FAIL, even though a WARN source
// was inserted first), plain WARN, and the purely-informational PASS note
// last.
func TestNotes_OrdersBySeverityNotInsertionOrder(t *testing.T) {
	r := model.Result{
		Stages: []model.Stage{
			// Inserted deliberately out of severity order.
			{Name: "cluster-warn", Verdict: model.VerdictWarn, RemediationCode: model.ErrClusterEdge404, Detail: "cluster warn"},
			{Name: "config", Verdict: model.VerdictFail, RemediationCode: model.ErrConfigError, Detail: "bad config"},
			{Name: "plain-warn", Verdict: model.VerdictWarn, RemediationCode: model.ErrTLSNonPublicIssuer, Detail: "plain warn"},
			{Name: "network", Verdict: model.VerdictFail, RemediationCode: model.ErrConnectRefused, Detail: "network fail"},
			{Name: "cluster-fail", Verdict: model.VerdictFail, RemediationCode: model.ErrClusterEdge404, Detail: "cluster fail"},
			{Name: "auth", Verdict: model.VerdictFail, RemediationCode: model.ErrOAuthTokenFail, Detail: "auth fail"},
			{Name: "generic", Verdict: model.VerdictFail, RemediationCode: model.ErrUnexpectedHTTPStatus, Detail: "generic fail"},
		},
		Probes: []model.ProbeFragment{
			{Runtime: "java", Target: "x:443", Verdict: model.VerdictPass, ErrorClass: model.ErrOK, Detail: "ok", TrustStoreExercised: "cacerts"},
		},
		Overall: model.Overall{Verdict: model.VerdictFail, FailingStage: "auth"},
	}
	got := Notes(r)
	// Stage bullets are a short index now ("see above"), not repeated
	// Detail -- check by name+code instead.
	wantOrder := []string{"auth [OAUTH_TOKEN_FAIL]", "every check that touched the network (network) [CONNECT_REFUSED]", "config [CONFIG_ERROR]", "generic [UNEXPECTED_HTTP_STATUS]", "shared training cluster (cluster-warn, cluster-fail) [CLUSTER_EDGE_404", "plain-warn [TLS_NON_PUBLIC_ISSUER]", "java used cacerts to verify the connection."}
	if strings.Count(got, "CLUSTER_EDGE_404") != 1 {
		t.Fatalf("expected the two cluster-side sources to merge into exactly one bullet, got %q", got)
	}
	lastIdx := -1
	for _, want := range wantOrder {
		idx := strings.Index(got, want)
		if idx < 0 {
			t.Fatalf("expected %q to appear in Notes output, got %q", want, got)
		}
		if idx < lastIdx {
			t.Fatalf("expected %q to appear after index %d, but found it at %d — severity order violated, got %q", want, lastIdx, idx, got)
		}
		lastIdx = idx
	}
}

// Two probe fragments from the same runtime, same code, with byte-identical
// Detail (the real-world shape: Java's TLS_HANDSHAKE_FAIL against two
// different hosts, where the underlying exception carries no host-specific
// text) must merge into ONE bullet listing both targets, not two
// near-duplicate bullets.
// Uses CONNECTION_CLOSED (Java-specific, NOT a systemicMergeCode) --
// TLS_HANDSHAKE_FAIL/CONNECT_REFUSED/etc. now merge across ALL sources
// regardless of Detail (see TestNotes_MergesSystemicNetworkFailureAcrossAllSources),
// so this test needs a code that still uses the narrower per-source merge to
// exercise it.
func TestNotes_MergesSameCauseAcrossTargets(t *testing.T) {
	sameDetail := "connection was established then closed unexpectedly before completing"
	r := model.Result{
		Probes: []model.ProbeFragment{
			{Runtime: "java", Target: "bru-2.zeebe.camunda.io:443", Verdict: model.VerdictFail, ErrorClass: model.ErrConnectionClosed, Detail: sameDetail},
			{Runtime: "java", Target: "login.cloud.camunda.io:443", Verdict: model.VerdictFail, ErrorClass: model.ErrConnectionClosed, Detail: sameDetail},
		},
		Overall: model.Overall{Verdict: model.VerdictFail, FailingStage: "layer2:java"},
	}
	got := Notes(r)
	if n := strings.Count(got, "[CONNECTION_CLOSED]"); n != 1 {
		t.Fatalf("expected exactly 1 merged bullet for the same cause across 2 targets, got %d in %q", n, got)
	}
	if !strings.Contains(got, "bru-2.zeebe.camunda.io:443") || !strings.Contains(got, "login.cloud.camunda.io:443") {
		t.Fatalf("expected both targets to be listed in the merged bullet, got %q", got)
	}
}

// Two findings for the same runtime/code but GENUINELY DIFFERENT Detail text
// must NOT merge -- Detail is part of the merge key precisely so distinct
// causes never get collapsed into one misleading bullet. (Uses
// CONNECTION_CLOSED, not a systemicMergeCode -- see comment above.)
func TestNotes_DoesNotMergeDifferentDetailForSameCode(t *testing.T) {
	r := model.Result{
		Probes: []model.ProbeFragment{
			{Runtime: "java", Target: "a:443", Verdict: model.VerdictFail, ErrorClass: model.ErrConnectionClosed, Detail: "cause A"},
			{Runtime: "java", Target: "b:443", Verdict: model.VerdictFail, ErrorClass: model.ErrConnectionClosed, Detail: "cause B"},
		},
		Overall: model.Overall{Verdict: model.VerdictFail, FailingStage: "layer2:java"},
	}
	got := Notes(r)
	if n := strings.Count(got, "[CONNECTION_CLOSED]"); n != 2 {
		t.Fatalf("expected 2 separate bullets for genuinely different causes, got %d in %q", n, got)
	}
}

// A cluster-side code (ClusterUnhealthy503/ClusterEdge404) merges across
// EVERY source -- stage and all 3 language probes -- not just across targets
// within one source, since a down shared cluster is the exact same finding
// regardless of which check noticed it. Without this, a 503-unhealthy
// cluster would print 4 near-identical bullets (status stage +
// java/python/typescript probes), reading as 4 separate problems to a
// participant when it's one.
func TestNotes_MergesClusterSideAcrossAllSources(t *testing.T) {
	r := model.Result{
		Stages: []model.Stage{
			{Name: "status", Host: "bru-2.api.camunda.io", Verdict: model.VerdictFail, RemediationCode: model.ErrClusterUnhealthy503, Detail: "status endpoint returned 503"},
		},
		Probes: []model.ProbeFragment{
			{Runtime: "java", Target: "bru-2.zeebe.camunda.io (sdk status)", Verdict: model.VerdictFail, ErrorClass: model.ErrClusterUnhealthy503, Detail: "java sdk status 503"},
			{Runtime: "python", Target: "bru-2.zeebe.camunda.io (sdk status)", Verdict: model.VerdictFail, ErrorClass: model.ErrClusterUnhealthy503, Detail: "python sdk status 503"},
			{Runtime: "typescript", Target: "bru-2.zeebe.camunda.io (sdk status)", Verdict: model.VerdictFail, ErrorClass: model.ErrClusterUnhealthy503, Detail: "typescript sdk status 503"},
		},
		Overall: model.Overall{Verdict: model.VerdictFail, FailingStage: "status", IsOurClusterProblem: true},
	}
	got := Notes(r)
	if n := strings.Count(got, "[CLUSTER_UNHEALTHY_503"); n != 1 {
		t.Fatalf("expected exactly 1 merged bullet across stage+3 probes, got %d in %q", n, got)
	}
	if !strings.Contains(got, "shared training cluster (status, java, python, typescript)") {
		t.Fatalf("expected all 4 sources named in the merged label, got %q", got)
	}
	// Non-verbose: only the checklist action, no per-source raw detail text
	// (the ErrorClass tag itself legitimately contains "503" -- check for the
	// raw sentence, not the substring).
	if strings.Contains(got, "status endpoint returned 503") {
		t.Fatalf("did not expect raw per-source detail text by default, got %q", got)
	}

	r.Verbose = true
	gotVerbose := Notes(r)
	if !strings.Contains(gotVerbose, "Technical detail: status endpoint returned 503") {
		t.Fatalf("expected the first-seen source's detail as the verbose technical-detail example, got %q", gotVerbose)
	}
}

// A systemic network/TLS code (TLS_HANDSHAKE_FAIL, CONNECT_REFUSED, etc.)
// merges across EVERY source too, same as a cluster-side code -- without
// this, a MITM-intercepting proxy would produce 12 near-identical
// TLS_HANDSHAKE_FAIL bullets across 2 Layer 1 stages, 6 more Layer 1 stages,
// and 3 Layer 2 probes, each with host-specific (so non-identical) Detail
// text baked in from the underlying Go error -- meaning a per-source,
// same-Detail merge alone could never collapse these even within one
// stage/runtime, let alone across stages. One proxy misconfiguration must
// read as one problem.
func TestNotes_MergesSystemicNetworkFailureAcrossAllSources(t *testing.T) {
	r := model.Result{
		Stages: []model.Stage{
			{Name: "status", Host: "bru-2.api.camunda.io", Verdict: model.VerdictFail, RemediationCode: model.ErrTLSHandshakeFail, Detail: "TLS handshake failed for bru-2.api.camunda.io: x509: certificate signed by unknown authority"},
			{Name: "webcomponent-console", Host: "console.cloud.camunda.io", Verdict: model.VerdictFail, RemediationCode: model.ErrTLSHandshakeFail, Detail: "TLS handshake failed for console.cloud.camunda.io: x509: certificate signed by unknown authority"},
		},
		Probes: []model.ProbeFragment{
			{Runtime: "java", Target: "bru-2.zeebe.camunda.io:443", Verdict: model.VerdictFail, ErrorClass: model.ErrTLSHandshakeFail, Detail: "javax.net.ssl.SSLHandshakeException: PKIX path building failed"},
			{Runtime: "python", Target: "bru-2.zeebe.camunda.io:443", Verdict: model.VerdictFail, ErrorClass: model.ErrTLSHandshakeFail, Detail: "ssl.SSLCertVerificationError: unable to get local issuer certificate"},
		},
		Overall: model.Overall{Verdict: model.VerdictFail, FailingStage: "status"},
	}
	got := Notes(r)
	if n := strings.Count(got, "[TLS_HANDSHAKE_FAIL]"); n != 1 {
		t.Fatalf("expected exactly 1 merged bullet across 2 stages + 2 probes despite differing Detail text, got %d in %q", n, got)
	}
	if !strings.Contains(got, "every check that touched the network (status, webcomponent-console, java, python)") {
		t.Fatalf("expected all 4 sources named in the merged label, got %q", got)
	}
}

// A stage merge (not just probes) works the same way -- e.g. the tls stage
// failing identically against both the api and zeebe host families.
func TestNotes_MergesSameCauseAcrossStageHosts(t *testing.T) {
	sameDetail := "issuer: CN=mitmproxy — NOT trusted by the system root store"
	r := model.Result{
		Stages: []model.Stage{
			{Name: "tls", Host: "bru-2.api.camunda.io", Verdict: model.VerdictWarn, RemediationCode: model.ErrTLSNonPublicIssuer, Detail: sameDetail},
			{Name: "tls", Host: "bru-2.zeebe.camunda.io", Verdict: model.VerdictWarn, RemediationCode: model.ErrTLSNonPublicIssuer, Detail: sameDetail},
		},
		Overall: model.Overall{Verdict: model.VerdictWarn},
	}
	got := Notes(r)
	if n := strings.Count(got, "[TLS_NON_PUBLIC_ISSUER]"); n != 1 {
		t.Fatalf("expected exactly 1 merged bullet for the same stage cause across 2 hosts, got %d in %q", n, got)
	}
	if !strings.Contains(got, "bru-2.api.camunda.io") || !strings.Contains(got, "bru-2.zeebe.camunda.io") {
		t.Fatalf("expected both hosts to be listed in the merged bullet, got %q", got)
	}
}
