// Command preflight is the Camunda 8 ILT connectivity preflight Layer 1
// tool. Stdlib only.
package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"c8preflight/internal/checks"
	"c8preflight/internal/config"
	"c8preflight/internal/launcher"
	"c8preflight/internal/model"
	"c8preflight/internal/redact"
	"c8preflight/internal/report"
)

// ToolVersion is overridable at build time via -ldflags "-X main.ToolVersion=x.y.z".
var ToolVersion = "0.5.0-dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(argv []string) int {
	cfg, err := config.Parse(argv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		return int(model.ExitConfigError)
	}

	if cfg.DiagnosticInsecureSkipVerify {
		fmt.Fprintln(os.Stderr, "*** WARNING: --diagnostic-insecure-skip-verify is active. TLS verification is DISABLED for real")
		fmt.Fprintln(os.Stderr, "*** application calls. This is a debugging aid ONLY — it is never the documented fix, and any")
		fmt.Fprintln(os.Stderr, "*** stage that ran with it cannot report a clean PASS in the result.")
	}

	client, err := checks.NewHTTPClient(checks.ClientOptions{
		CustomCAPath:                 cfg.CustomCAPath,
		ExplicitProxyURL:             cfg.ProxyURL,
		DiagnosticInsecureSkipVerify: cfg.DiagnosticInsecureSkipVerify,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not build HTTP client: %v\n", err)
		return int(model.ExitConfigError)
	}

	rootPool, err := checks.BuildRootPool(cfg.CustomCAPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not build trust pool: %v\n", err)
		return int(model.ExitConfigError)
	}

	ctx := context.Background()
	secrets := redact.Secrets{ClientSecret: cfg.ClientSecret, ClientID: cfg.ClientID, ProxyPassword: proxyPassword(cfg.ProxyURL, cfg.Target.APIHost), JavaTrustStorePassword: cfg.JavaTrustStorePassword}

	detectedProxy := checks.DetectedProxy("https://"+cfg.Target.APIHost, cfg.ProxyURL)
	// Tailors the CONNECT_REFUSED/CONNECT_TIMEOUT remediation hint: only
	// suggest "try --proxy" when no proxy is already active for this run.
	checks.SetProxyConfigured(detectedProxy != "")

	// Read separately from detectedProxy, and never folded into it: this is what
	// the OS has configured, not what this run used.
	systemProxy := checks.DetectSystemProxy()

	// Presence is always shown; the hostname/IP itself is masked by default
	// (see UnmaskedHostnames' doc comment) — computed once here and reused for
	// both the persisted Target fields and the WARN below, so the two can never
	// disagree about whether this run reveals the real value.
	detectedProxyDisplay := detectedProxy
	systemProxyDisplay := systemProxy.Summary()
	if !cfg.UnmaskedHostnames {
		detectedProxyDisplay = redact.MaskProxyValue(detectedProxyDisplay)
		systemProxyDisplay = redact.MaskProxyValue(systemProxyDisplay)
	}

	result := model.Result{
		SchemaVersion:   model.SchemaVersion,
		ToolVersion:     ToolVersion,
		Mode:            cfg.Mode,
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		OS:              runtime.GOOS,
		Arch:            runtime.GOARCH,
		TrainingGroupID: cfg.TrainingGroupID,
		// Non-nil so a --skip-transport run (which never calls add()) still
		// marshals "stages": [] rather than null — a nil Go slice serializes
		// as JSON null, which downstream consumers must not have to special-case.
		Stages: []model.Stage{},
		Target: model.Target{
			Region:        cfg.Target.Region,
			ClusterID:     cfg.Target.ClusterID,
			APIHost:       cfg.Target.APIHost,
			ZeebeHost:     cfg.Target.ZeebeHost,
			OAuthHost:     cfg.Target.OAuthHost,
			ResolvedIPs:   map[string][]string{},
			DetectedProxy: detectedProxyDisplay,
			SystemProxy:   systemProxyDisplay,
		},
	}
	switch {
	case cfg.AutoDetect:
		result.StacksRequested = "(auto-detect)"
	case len(cfg.Stacks) > 0:
		result.StacksRequested = strings.Join(cfg.Stacks, ", ")
	}
	result.Verbose = cfg.Verbose
	for _, w := range cfg.Target.Warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}

	result.DiagnosticInsecure = cfg.DiagnosticInsecureSkipVerify

	// add appends a stage, streams it, and enforces two security invariants
	// that every stage line must satisfy:
	//   - if --diagnostic-insecure-skip-verify is active, any PASS from a stage
	//     that used the verification-disabled HTTP client is downgraded to WARN
	//     with a loud marker — the tool must never present a trustworthy-looking
	//     PASS when TLS verification was off.
	//   - the streamed line is scrubbed of any known secret before printing —
	//     the file writers refuse-to-emit on a leak.
	//     The closure captures `secrets`, so the access token set
	//     mid-run below is covered from that point on.
	add := func(s model.Stage) {
		if cfg.DiagnosticInsecureSkipVerify && usesInsecureHTTPClient(s.Name) && s.Verdict == model.VerdictPass {
			s.Verdict = model.VerdictWarn
			s.RemediationCode = model.ErrTLSHandshakeFail
			s.Detail = insecureStageMarker + s.Detail
		}
		result.Stages = append(result.Stages, s)
		fmt.Print(secrets.Scrub(report.StageLine(s)))
	}

	// Print the header immediately, before any stage runs. A blocked/slow
	// network stage can take 10-30s each; printing nothing until the whole
	// run finishes is indistinguishable from a hang.
	fmt.Print(secrets.Scrub(report.Header(result)))

	// A proxy the OS has configured but this run did not use means the checks
	// below travel a different path than the training tooling will: .NET follows
	// the system settings, so a green result here can coexist with a C# exercise
	// that routes somewhere else entirely. Reported before the checks run, so the
	// reader has that caveat in hand while reading them.
	//
	// WARN rather than FAIL: reaching the cluster directly is a perfectly valid
	// outcome even with a proxy configured, and on this evidence the tool cannot
	// tell whether the proxy is required, optional, or destination-specific.
	if systemProxy.Configured && detectedProxy == "" {
		add(model.Stage{
			Name:            "proxy-config",
			Verdict:         model.VerdictWarn,
			RemediationCode: model.ErrConfigError,
			Detail: "this machine has a system proxy configured (" + systemProxyDisplay + "), but the checks in this run " +
				"connected directly, because they follow the HTTP_PROXY/HTTPS_PROXY environment variables and neither is set. " +
				"The .NET tooling reads the system setting instead, so C# exercises may take a different route than the results below. " +
				"To test the proxied path, re-run with --proxy pointing at it.",
		})
	}

	// webComponents is needed later for the firewall-allowlist block regardless
	// of whether the transport checks that exercise them run, so compute it up
	// front (before the --skip-transport guard).
	webComponents := checks.WebComponentHosts(cfg.Target.Region)

	// --skip-transport runs ONLY the Layer 2 runtime probes — useful when the
	// operator has already confirmed the network path (or is diagnosing a
	// runtime trust-store issue specifically) and doesn't want the full Go
	// transport sweep repeated. Everything below to the Layer 2 launcher is the
	// Go/Layer 1 work, so it is all gated here.
	if cfg.SkipTransport {
		fmt.Print(secrets.Scrub(report.SkippedTransportNotice()))
	} else {
		// --- Transport stages, both cluster host families ---
		for _, host := range []string{cfg.Target.APIHost, cfg.Target.ZeebeHost} {
			result.Target.ResolvedIPs[host] = checks.ResolvedIPs(ctx, host)
			runHostStages(ctx, client, rootPool, cfg, host, &result, add)
		}
		result.Target.ResolvedIPs[cfg.Target.OAuthHost] = checks.ResolvedIPs(ctx, cfg.Target.OAuthHost)

		// --- OAuth host reachability (network mode only — full mode's real
		// token exchange below is the stronger proof, so there's nothing
		// worth reporting here in full mode: no stage at all, not even SKIP —
		// it's an expected, permanent fact of running in full mode, not a
		// diagnostic finding). ---
		if cfg.Mode == model.ModeNetwork {
			add(checks.CheckOAuthHostReachable(ctx, client, cfg.OAuthURL))
		}

		// --- Full mode: OAuth token (once) + authenticated topology (both host families) ---
		if cfg.Mode == model.ModeFull {
			token, tokenStage := checks.AcquireToken(ctx, client, cfg.OAuthURL, cfg.ClientID, cfg.ClientSecret, cfg.Audience)
			add(tokenStage)
			if token != "" {
				secrets.AccessToken = token
				for _, host := range []string{cfg.Target.APIHost, cfg.Target.ZeebeHost} {
					restBase := cfg.Target.RESTBase(host)
					add(checks.CheckTopology(ctx, client, restBase, host, token))
				}
			} else {
				for _, host := range []string{cfg.Target.APIHost, cfg.Target.ZeebeHost} {
					add(model.Stage{
						Name: "topology", Host: host,
						Verdict: model.VerdictSkip, RemediationCode: model.ErrOK,
						Detail: "skipped — no valid OAuth token was acquired",
					})
				}
			}
		}

		// --- Web component reachability ---
		for _, wc := range webComponents {
			add(checks.CheckWebComponent(ctx, client, wc.Name, wc.Host))
		}
	}

	// --- Layer 2 launcher ---
	runtimeOverrides := launcher.RuntimeOverrides{
		JavaHome:  cfg.JavaHome,
		PythonBin: cfg.PythonBin,
		NodeBin:   cfg.NodeBin,
		DotnetBin: cfg.DotnetBin,
	}
	stacks := launcher.SelectStacks(cfg.Stacks, cfg.AutoDetect, runtimeOverrides)
	explicitSelection := len(cfg.Stacks) > 0
	layer2Dir := findLayer2Dir()
	// Forward the fully-resolved config so probes hit the same target/path.
	// Pass the operator's RAW explicit host when they gave one, so a probe can
	// still detect + WARN about the Console copy-paste ":443" form; otherwise a
	// canonical URL derived from the resolved target (region/cluster-id path).
	restAddress := cfg.Host
	if restAddress == "" && cfg.Target.ClusterID != "" {
		restAddress = cfg.Target.RESTBase(cfg.Target.APIHost)
	}
	probeCfg := launcher.ProbeConfig{
		Mode:                   string(cfg.Mode),
		RESTAddress:            restAddress,
		ExplicitProxy:          cfg.ProxyURL,
		CACertPath:             cfg.CustomCAPath,
		Verbose:                cfg.Verbose,
		JavaTrustStorePath:     cfg.JavaTrustStorePath,
		JavaTrustStorePassword: cfg.JavaTrustStorePassword,
		MavenDepcheck:          cfg.MavenDepcheck,
		MavenMirror:            cfg.MavenMirror,
		MavenSettings:          cfg.MavenSettings,
		MavenCentralOnly:       cfg.MavenCentralOnly,
		TSProxySupport:         cfg.TSProxySupport,
		Runtimes:               runtimeOverrides,
	}
	// Print the header BEFORE any probe runs, and stream each fragment the
	// moment it's produced (rather than collecting everything and printing
	// only after every stack's subprocess has exited) — a probe can take
	// minutes (e.g. the Maven dependency-resolution check's real network
	// fetches), and printing nothing until the whole thing finishes is
	// indistinguishable from a hang.
	if len(stacks) > 0 {
		fmt.Print(report.ProbesHeader())
	}
	onProbeFragment := func(p model.ProbeFragment) {
		// Config-level diagnostics (e.g. wrong env var name for this runtime)
		// aren't a check against a real target -- printed inline they'd
		// interrupt the PASS/FAIL listing with a line for a host that was
		// never actually probed. They still reach result.Probes (collected by
		// launcher.Run independently of this callback), so Notes() still
		// reports them -- just not duplicated into the live stream too.
		if report.IsConfigDiagnostic(p) {
			return
		}
		fmt.Print(secrets.Scrub(report.ProbeLine(p)))
	}
	detected, skipped, runtimes, probes := launcher.Run(ctx, layer2Dir, stacks, explicitSelection, probeCfg, onProbeFragment)
	result.RuntimesDetected = detected
	result.RuntimesSkipped = skipped
	result.Runtimes = runtimes
	result.Probes = probes
	// Which runtime version each stack was checked with is shown by default: a
	// Layer 2 verdict is only meaningful against a specific installation, so on a
	// machine with several of them the reader would otherwise have to assume.
	// The resolved paths are the part kept for --verbose (and the result file,
	// always) — they're what tells two same-version installations apart.
	fmt.Print(report.RuntimesUsedLine(runtimes))
	if cfg.Verbose {
		fmt.Print(report.RuntimeDetailLines(runtimes))
	}
	fmt.Print(report.RuntimesSkippedLine(skipped))

	// --- Overall + output ---
	result.Overall = report.BuildOverall(result.Stages, result.Probes)
	exitCode := report.ExitCodeFor(result)

	fmt.Print(secrets.Scrub(report.Footer(result)))
	fmt.Print(secrets.Scrub(report.Notes(result)))
	// The allowlist block is a "hand this to your network team" remedy — only
	// useful when something is actually blocked on the customer's side. On a
	// clean all-pass run there is nothing to fix, so printing it just adds
	// noise/confusion — same reasoning excludes a run that failed/warned for
	// ExitOurClusterProblem reasons only.
	if cfg.Mode == model.ModeNetwork && result.Overall.Verdict != model.VerdictPass && exitCode != model.ExitOurClusterProblem {
		fmt.Print(report.AllowlistBlock(cfg.Target, webComponents))
	}

	// A run with TLS verification disabled must never look like a
	// clean success. Every affected stage is already downgraded off PASS above;
	// here we also print a loud banner and refuse a zero (success) exit code so
	// nothing scripting against $LASTEXITCODE mistakes it for a good result.
	if cfg.DiagnosticInsecureSkipVerify {
		fmt.Println("\n*** TLS verification was DISABLED (--diagnostic-insecure-skip-verify). No PASS or exit 0")
		fmt.Println("*** from this run is trustworthy. This mode is for transport debugging only.")
		if exitCode == model.ExitOK {
			exitCode = model.ExitGenericError
		}
	}

	writtenPath, writeErr := report.WriteResultJSON(result, cfg.OutPath, secrets)
	if writeErr != nil {
		fmt.Fprintf(os.Stderr, "\ncould not write result JSON: %v\n", writeErr)
		return int(model.ExitGenericError)
	}
	fmt.Printf("\nResults written to: %s\n", writtenPath)
	fmt.Println("Share this file with your training contact if asked.")
	// Only the default result filename is gitignored.
	// If the file landed inside a git working tree (e.g. a custom
	// --out into the repo), warn — it could carry the real clusterId into a
	// commit. A .gitignore pattern can't catch arbitrary --out names, so warn
	// on the actual path regardless of filename.
	//
	if repo := gitRepoRoot(writtenPath); repo != "" {
		fmt.Fprintf(os.Stderr, "warning: the result was written inside a git repository (%s). It may contain the real clusterId — move it out of the repo or add it to .gitignore before committing.\n", repo)
	}

	if cfg.LogFilePath != "" {
		if logErr := report.WriteLogFile(cfg.LogFilePath, report.HumanSummary(result), secrets); logErr != nil {
			fmt.Fprintf(os.Stderr, "could not write log file: %v\n", logErr)
		}
	}

	return int(exitCode)
}

// insecureStageMarker prefixes the detail of any stage whose PASS was
// suppressed because --diagnostic-insecure-skip-verify disabled TLS
// verification for the HTTP client it used.
const insecureStageMarker = "[diagnostic-insecure: TLS verification was DISABLED for this call — PASS suppressed, this result is NOT trustworthy] "

// proxyPassword extracts the password from an effective proxy's userinfo so
// the redaction self-check can treat it as a known secret — a corporate
// proxy password is real credential material and must never reach output.
// Prefers the explicit --proxy; otherwise resolves whatever HTTP(S)_PROXY the
// target would use. Returns "" when there's no proxy or no password.
func proxyPassword(explicitProxy, apiHost string) string {
	raw := checks.DetectedProxy("https://"+apiHost, explicitProxy)
	// DetectedProxy masks userinfo, so re-resolve the unmasked URL for the
	// password itself: explicit flag wins, else env.
	src := explicitProxy
	if src == "" {
		if raw == "" {
			return ""
		}
		if p, err := http.ProxyFromEnvironment(&http.Request{URL: mustURL("https://" + apiHost)}); err == nil && p != nil {
			src = p.String()
		}
	}
	u, err := url.Parse(src)
	if err != nil || u.User == nil {
		return ""
	}
	if pw, ok := u.User.Password(); ok {
		return pw
	}
	return ""
}

func mustURL(s string) *url.URL {
	u, _ := url.Parse(s)
	return u
}

// gitRepoRoot walks up from path's directory looking for a .git entry, and
// returns the repo root if found, else "" — used to warn when a result file
// (which can carry the real clusterId) is written inside a git repo.
func gitRepoRoot(path string) string {
	dir := filepath.Dir(path)
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// usesInsecureHTTPClient reports whether a stage name corresponds to a check
// that runs through the shared HTTP client (which honors
// --diagnostic-insecure-skip-verify). The transport stages dns/tcp/tls/alpn do
// NOT use it — tls does its own independent verification regardless of the flag
// — so their verdicts stay honest and are not downgraded.
func usesInsecureHTTPClient(name string) bool {
	switch name {
	case "status", "oauth-reachability", "oauth-token", "topology":
		return true
	}
	return strings.HasPrefix(name, "webcomponent")
}

// runHostStages runs the DNS -> TCP -> TLS -> ALPN -> status sequence for
// one cluster host family and appends everything to result.
func runHostStages(ctx context.Context, client *http.Client, rootPool *x509.CertPool, cfg *config.Config, host string, result *model.Result, add func(model.Stage)) {
	dnsStage := checks.ResolveDNS(ctx, host)
	add(dnsStage)
	if dnsStage.Verdict != model.VerdictPass {
		skipRest(add, host, "tcp", "tls", "alpn", "status")
		return
	}

	// Resolve the proxy the same way the HTTP-client stages do, so tcp/tls/
	// alpn traverse the proxy's CONNECT tunnel when one is configured — the
	// transport stages and the status/oauth/topology stages now agree.
	proxy, _ := checks.ResolveProxyForHost("https://"+host, cfg.ProxyURL)

	conn, tcpStage := checks.TCPConnect(ctx, host, 443, proxy)
	add(tcpStage)
	if tcpStage.Verdict != model.VerdictPass {
		skipRest(add, host, "tls", "alpn", "status")
		return
	}

	inspect := checks.TLSInspect(ctx, conn, host, 443, rootPool)
	alpnStage := inspect.ALPNStage
	if cfg.GRPCClient && alpnStage.Verdict == model.VerdictWarn && alpnStage.RemediationCode == model.ErrALPNDowngradeWarn {
		alpnStage.Verdict = model.VerdictFail
		alpnStage.Detail += " (escalated to FAIL: --grpc-client was set for this training group)"
	}
	add(inspect.TLSStage)
	add(alpnStage)
	result.TLS = append(result.TLS, inspect.Info)

	if inspect.TLSStage.Verdict == model.VerdictFail {
		skipRest(add, host, "status")
		return
	}

	restBase := cfg.Target.RESTBase(host)
	add(checks.CheckStatus(ctx, client, restBase, host))
}

func skipRest(add func(model.Stage), host string, names ...string) {
	for _, n := range names {
		add(model.Stage{
			Name: n, Host: host, Verdict: model.VerdictSkip, RemediationCode: model.ErrOK,
			Detail: "skipped — an earlier stage for this host did not complete",
		})
	}
}

// findLayer2Dir locates the layer2 probes directory. It resolves ONLY relative
// to the running executable's own location, never the current working directory:
// the launcher executes run.cmd/run.sh from this
// directory, so a CWD-relative lookup would let anyone who can choose the CWD —
// e.g. launching the tool from an attacker-writable Downloads or shared temp
// dir containing a planted layer2/<stack>/run.cmd — get that script executed
// with the operator's full environment. Both candidates below are anchored to
// the executable path, which an attacker can't influence by CWD choice:
//
//	<exeDir>/layer2      — the real distribution layout (binary + layer2/ shipped together)
//	<exeDir>/../layer2   — the repo layout (binary in preflight/releases/, probes in preflight/layer2/)
//
// An explicit CAMUNDA_LAYER2_DIR override is honored first for controlled/dev
// use (operator-set, not CWD-derived). Returns "" when none is found, which the
// launcher treats as "no probe available" (SKIP), not an error.
func findLayer2Dir() string {
	if override := strings.TrimSpace(os.Getenv("CAMUNDA_LAYER2_DIR")); override != "" {
		// Absolute and a real directory, or ignored. A relative value would be
		// resolved against the working directory by the os.Stat and exec calls
		// downstream, which reintroduces exactly the CWD-relative probe
		// execution the anchored lookup below exists to prevent — and the
		// tool's own "set CAMUNDA_LAYER2_DIR" hint invites a relative answer.
		if !filepath.IsAbs(override) {
			fmt.Fprintf(os.Stderr, "warning: ignoring CAMUNDA_LAYER2_DIR %q — it must be an absolute path\n", override)
		} else if st, err := os.Stat(override); err != nil || !st.IsDir() {
			fmt.Fprintf(os.Stderr, "warning: ignoring CAMUNDA_LAYER2_DIR %q — not a directory\n", override)
		} else {
			return override
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	exeDir := filepath.Dir(exe)
	for _, candidate := range []string{
		filepath.Join(exeDir, "layer2"),
		filepath.Join(exeDir, "..", "layer2"),
	} {
		if st, err := os.Stat(candidate); err == nil && st.IsDir() {
			return candidate
		}
	}
	return ""
}
