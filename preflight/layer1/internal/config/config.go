// Package config parses flags and environment variables into a single
// resolved configuration, implementing the tool's documented precedence
// rules (explicit host wins over region; explicit mode flag wins over
// auto-detect; explicit --stacks is the default selection mechanism).
package config

import (
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	"c8preflight/internal/hostset"
	"c8preflight/internal/launcher"
	"c8preflight/internal/model"
)

type Config struct {
	Host      string // --host / CAMUNDA_REST_ADDRESS
	Region    string // --region / CAMUNDA_REGION
	ClusterID string // --cluster-id / CAMUNDA_CLUSTER_ID

	ClientID     string // CAMUNDA_CLIENT_ID
	ClientSecret string // CAMUNDA_CLIENT_SECRET
	OAuthURL     string // CAMUNDA_OAUTH_URL
	Audience     string // CAMUNDA_TOKEN_AUDIENCE

	Mode         model.Mode // resolved network|full
	ModeExplicit bool

	Stacks     []string // --stacks (explicit selection, default mechanism)
	AutoDetect bool     // --auto (opt-in fallback)

	GRPCClient bool // --grpc-client: escalate ALPN downgrade WARN to FAIL
	Verbose    bool // --verbose: surface extra diagnostic fragments (e.g. the Console-URL normalization notice) that are hidden by default to avoid confusing participants

	SkipTransport bool // --skip-transport: skip the Go/Layer 1 checks (transport, TLS, DNS, OAuth reachability, topology, web components) and run only the Layer 2 runtime probes

	// UnmaskedHostnames: --unmasked-hostnames. A detected proxy's hostname/IP
	// (and the auto-config script URL, if any) is masked by default -- its
	// PRESENCE still shows, but not what it is -- since it reveals internal
	// network naming to whoever the result file is shared with (the training
	// team). This flag opts back into the real value for whoever is actually
	// diagnosing the proxy. Off by default so the privacy-conscious behavior
	// is what a participant gets without having to know to ask for it.
	UnmaskedHostnames bool

	CustomCAPath string // --trust-ca (--ca is a deprecated alias) / CAMUNDA_MTLS_CA_PATH
	ProxyURL     string // --proxy (explicit override; else HTTP_PROXY/HTTPS_PROXY/NO_PROXY are auto-detected)

	// JavaTrustStorePath/Password: --java-truststore / CAMUNDA_JAVA_TRUSTSTORE.
	// Java-specific alternative to --trust-ca: a path to a JKS/PKCS12 truststore file,
	// applied by the Java probes as -Djavax.net.ssl.trustStore before any SSL
	// work. Unlike CAMUNDA_CA_CERTIFICATE_PATH (which REPLACES the trust store
	// entirely), an operator can build this
	// file as a copy of cacerts with a corporate CA merged in via keytool, so
	// public CAs stay trusted. Ignored (with a WARN) if CAMUNDA_CA_CERTIFICATE_PATH
	// is also set. Password is a secret — never seeded into a flag default (see
	// the STATIC-defaults note above) and scrubbed from all output via redact.Secrets.
	JavaTrustStorePath     string // CAMUNDA_JAVA_TRUSTSTORE
	JavaTrustStorePassword string // CAMUNDA_JAVA_TRUSTSTORE_PASSWORD

	// Maven dependency-resolution check (Java stack). Opt-in because
	// it does real network fetches. The heavy lifting lives in the Java
	// DepCheck probe; these just plumb the operator's intent/config down via env.
	MavenDepcheck    bool   // --maven-depcheck -> CAMUNDA_MAVEN_DEPCHECK
	MavenMirror      string // --maven-mirror -> CAMUNDA_MAVEN_MIRROR (generate a mirrorOf=* settings)
	MavenSettings    string // --maven-settings -> CAMUNDA_MAVEN_SETTINGS (settings.xml path)
	MavenCentralOnly bool   // --maven-central-only -> CAMUNDA_MAVEN_CENTRAL_ONLY

	// NoSDKInstall: --no-sdk-install -> CAMUNDA_SDK_AUTO_INSTALL=0. The tier-2
	// SDK checks fetch their pinned, lockfile-verified SDK when it isn't already
	// present, because a tier that silently SKIPs answers nothing about whether
	// the real client can reach the cluster — the question the participant is
	// actually here to settle. This opts out for a machine where writing into
	// the language's package cache is unwanted, at the cost of that coverage.
	NoSDKInstall bool

	// TSProxySupport: --ts-proxy-support -> CAMUNDA_TS_PROXY_SUPPORT. Opt-in
	// because it changes what the TypeScript tier-2 (SDK-snippet) check
	// actually exercises. Off by default: the real @camunda8/orchestration-
	// cluster-api SDK's own fetch has ZERO proxy handling (confirmed from
	// source) and silently bypasses --proxy, connecting directly instead —
	// the tool's DEFAULT behavior mirrors that real, unmodified SDK exactly
	// (matching what a training group's own job-worker code would do out of the box).
	// Enabling this flag swaps in a hand-written proxy-tunneling `fetch`
	// override so the check actually routes through --proxy, at the cost of
	// no longer testing the real SDK's own (nonexistent) proxy behavior.
	TSProxySupport bool

	// Runtime pins for the Layer 2 stacks. A machine can carry several JDKs, a
	// system interpreter next to a project venv, or more than one Node major;
	// each installation has its own trust store, so "whichever came first on
	// PATH" is not necessarily the one the training exercises will run on. These
	// let an operator name the right one explicitly.
	JavaHome  string // --java-home  -> CAMUNDA_JAVA_HOME  (a JDK directory)
	PythonBin string // --python-bin -> CAMUNDA_PYTHON_BIN (an interpreter binary)
	NodeBin   string // --node-bin   -> CAMUNDA_NODE_BIN
	DotnetBin string // --dotnet-bin -> CAMUNDA_DOTNET_BIN

	TrainingGroupID string // --training-group (opaque label only)

	OutPath     string // --out
	LogFilePath string // --log-file

	// DiagnosticInsecureSkipVerify exists ONLY for the operator's own
	// debugging — clearly labelled diagnostic-only, and never suggested as a
	// remediation anywhere in this tool's output.
	DiagnosticInsecureSkipVerify bool

	Target hostset.Target
}

// Parse reads flags + environment and resolves the full configuration.
// argv should exclude the program name (os.Args[1:]).
func Parse(argv []string) (*Config, error) {
	fs := flag.NewFlagSet("preflight", flag.ContinueOnError)

	// IMPORTANT: flag defaults must be STATIC, never populated from the
	// environment. Go's flag package prints every non-empty default in --help,
	// so using an env value as a default would leak CAMUNDA_CLIENT_SECRET (and the
	// client id, clusterId, etc.) straight into `preflight --help` whenever
	// those env vars are set. Env values are applied AFTER parsing via the
	// resolve() helper below, which keeps them out of the usage text while
	// preserving precedence:
	// an explicit flag wins over env, env wins over the static default.
	host := fs.String("host", "", "full cluster REST base URL, e.g. https://bru-2.api.camunda.io/<clusterId> (env: CAMUNDA_REST_ADDRESS)")
	region := fs.String("region", "", "region slug override, e.g. bru-2 (env: CAMUNDA_REGION)")
	clusterID := fs.String("cluster-id", "", "cluster UUID (only needed if --host is not given) (env: CAMUNDA_CLUSTER_ID)")

	clientID := fs.String("client-id", "", "OAuth client id — presence triggers full mode (env: CAMUNDA_CLIENT_ID)")
	clientSecret := fs.String("client-secret", "", "OAuth client secret (env: CAMUNDA_CLIENT_SECRET)")
	oauthURL := fs.String("oauth-url", "https://login.cloud.camunda.io/oauth/token", "OAuth token endpoint (env: CAMUNDA_OAUTH_URL)")
	audience := fs.String("audience", "zeebe.camunda.io", "OAuth token audience (env: CAMUNDA_TOKEN_AUDIENCE)")

	modeFlag := fs.String("mode", "", "network|full (default: network -- full is opt-in, never auto-detected from credential presence)")
	stacksFlag := fs.String("stacks", "", "comma-separated training-group stacks to run Layer 2 for, e.g. java,python (default selection mechanism)")
	autoFlag := fs.Bool("auto", false, "auto-detect installed runtimes on PATH instead of explicit --stacks (opt-in fallback for the unknown-language case)")
	grpcFlag := fs.Bool("grpc-client", false, "escalate an ALPN downgrade (HTTP/2->1.1) from WARN to FAIL because the training group uses the legacy gRPC Zeebe client")
	verboseFlag := fs.Bool("verbose", false, "surface extra technical detail hidden by default -- the Console-URL normalization notice, plus the raw exception text under each Troubleshooting/General note (the default view shows a plain-language 'what to do' instruction instead). Useful for the operator/trainer; hidden from participants otherwise")
	skipTransportFlag := fs.Bool("skip-transport", false, "skip the Go/Layer 1 transport checks (TLS, DNS, OAuth reachability, topology, web components) and run only the Layer 2 runtime probes")
	unmaskedHostnamesFlag := fs.Bool("unmasked-hostnames", false, "show a detected proxy's real hostname/IP instead of a masked placeholder -- off by default since the result file is often shared with the training team, and the internal proxy address isn't needed for that unless someone is specifically diagnosing it")

	trustCA := fs.String("trust-ca", "", "path to a custom CA PEM to trust in addition to the system store — reaches every runtime (Go/Python/TypeScript directly, Java too unless --java-truststore is also set) (env: CAMUNDA_MTLS_CA_PATH)")
	legacyCA := fs.String("ca", "", "deprecated alias for --trust-ca — will be removed in a future version")
	proxyURL := fs.String("proxy", "", "explicit proxy URL, e.g. http://proxy.corp:8080 (default: auto-detect from HTTP_PROXY/HTTPS_PROXY/NO_PROXY)")
	javaTrustStore := fs.String("java-truststore", "", "Java-only: path to a JKS/PKCS12 truststore file, applied as -Djavax.net.ssl.trustStore (env: CAMUNDA_JAVA_TRUSTSTORE). Appends, unlike --trust-ca on Java (which replaces the trust store entirely) — build this as a cacerts copy with your CA merged in via keytool. Ignored (with a WARN) if --trust-ca is also set.")
	javaTrustStorePassword := fs.String("java-truststore-password", "", "password for --java-truststore, if any (env: CAMUNDA_JAVA_TRUSTSTORE_PASSWORD) — only guards an integrity check on a pure truststore, so a wrong/missing value still loads the certs fine")

	mavenDepcheck := fs.Bool("maven-depcheck", false, "Java only: run the Maven dependency-resolution check — verifies the Camunda training artifacts actually resolve through your Maven mirror (catches a broken corporate Nexus/Artifactory). Opt-in: does real network fetches. Requires --stacks java (or --auto).")
	mavenMirror := fs.String("maven-mirror", "", "Java only: explicit Maven mirror URL to test (generates a mirrorOf=* settings); implies --maven-depcheck")
	mavenSettings := fs.String("maven-settings", "", "Java only: path to a settings.xml to use for the Maven dependency-resolution check; implies --maven-depcheck")
	mavenCentralOnly := fs.Bool("maven-central-only", false, "Java only: restrict the Maven dependency-resolution check to the Maven Central baseline (skip the customer-mirror leg); implies --maven-depcheck")
	noSDKInstall := fs.Bool("no-sdk-install", false, "Do not fetch the pinned Camunda SDK for the tier-2 checks when it isn't already installed. Those checks then report SKIP instead of confirming the real SDK reaches the cluster (env: CAMUNDA_SDK_AUTO_INSTALL=0)")
	tsProxySupport := fs.Bool("ts-proxy-support", false, "TypeScript only: route the SDK-snippet (tier 2) check through --proxy via a hand-written fetch override, instead of the default behavior of mirroring the real SDK exactly (which has zero proxy support and silently connects direct). Opt-in because it changes what's actually being tested (env: CAMUNDA_TS_PROXY_SUPPORT)")

	javaHome := fs.String("java-home", "", "Java only: the JDK to check with (a directory; its bin/java is used), instead of whichever javac/java comes first on PATH. Use when the machine has several JDKs and the exercises run on a specific one — each JDK has its own cacerts trust store (env: CAMUNDA_JAVA_HOME)")
	pythonBin := fs.String("python-bin", "", "Python only: the interpreter to check with (a path to a python binary), instead of whichever python3/python comes first on PATH. Use when the exercises run in a venv — each interpreter has its own certifi CA bundle (env: CAMUNDA_PYTHON_BIN)")
	nodeBin := fs.String("node-bin", "", "TypeScript only: the node binary to check with, instead of whichever node comes first on PATH. Use when several Node majors are installed — the TLS stack and bundled CA set differ between them (env: CAMUNDA_NODE_BIN)")
	dotnetBin := fs.String("dotnet-bin", "", "C# only: the dotnet binary to check with, instead of whichever dotnet comes first on PATH (env: CAMUNDA_DOTNET_BIN)")

	trainingGroup := fs.String("training-group", "", "opaque label identifying this training group in the result JSON")
	outPath := fs.String("out", "", "path to write the result JSON (default: current directory, falls back to temp dir if unwritable)")
	logFile := fs.String("log-file", "", "optional path for a verbose diagnostic log (redacted, local only)")

	diagnosticInsecure := fs.Bool("diagnostic-insecure-skip-verify", false,
		"DIAGNOSTIC ONLY. Never a real fix. Skips TLS verification for the raw inspection stage's own troubleshooting output. Do not use this as a workaround.")

	if err := fs.Parse(argv); err != nil {
		return nil, err
	}

	// Which flags were explicitly passed on the command line — used to keep the
	// flag-wins-over-env precedence now that env is applied post-parse.
	setFlags := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { setFlags[f.Name] = true })
	resolve := func(name, flagVal, envKey string) string {
		if setFlags[name] {
			return flagVal // explicit flag wins
		}
		if v := os.Getenv(envKey); v != "" {
			return v // then env
		}
		return flagVal // then the static default
	}

	// --trust-ca (current name) wins over --ca (deprecated alias, kept for
	// compatibility with existing muscle memory/scripts), which wins over the
	// env var, same precedence shape as resolve() above but across two flag
	// names instead of one.
	resolveCA := func() string {
		if setFlags["trust-ca"] {
			return *trustCA
		}
		if setFlags["ca"] {
			fmt.Fprintln(os.Stderr, "warning: --ca is deprecated, use --trust-ca instead (will be removed in a future version)")
			return *legacyCA
		}
		if v := os.Getenv("CAMUNDA_MTLS_CA_PATH"); v != "" {
			return v
		}
		return *trustCA
	}

	cfg := &Config{
		Host:         strings.TrimSpace(resolve("host", *host, "CAMUNDA_REST_ADDRESS")),
		Region:       strings.TrimSpace(resolve("region", *region, "CAMUNDA_REGION")),
		ClusterID:    strings.TrimSpace(resolve("cluster-id", *clusterID, "CAMUNDA_CLUSTER_ID")),
		ClientID:     strings.TrimSpace(resolve("client-id", *clientID, "CAMUNDA_CLIENT_ID")),
		ClientSecret: strings.TrimSpace(resolve("client-secret", *clientSecret, "CAMUNDA_CLIENT_SECRET")),
		OAuthURL:     strings.TrimSpace(resolve("oauth-url", *oauthURL, "CAMUNDA_OAUTH_URL")),
		Audience:     strings.TrimSpace(resolve("audience", *audience, "CAMUNDA_TOKEN_AUDIENCE")),
		GRPCClient:   *grpcFlag, Verbose: *verboseFlag, SkipTransport: *skipTransportFlag, UnmaskedHostnames: *unmaskedHostnamesFlag, CustomCAPath: strings.TrimSpace(resolveCA()), ProxyURL: strings.TrimSpace(*proxyURL),
		JavaTrustStorePath:     strings.TrimSpace(resolve("java-truststore", *javaTrustStore, "CAMUNDA_JAVA_TRUSTSTORE")),
		JavaTrustStorePassword: strings.TrimSpace(resolve("java-truststore-password", *javaTrustStorePassword, "CAMUNDA_JAVA_TRUSTSTORE_PASSWORD")),
		MavenMirror:            strings.TrimSpace(resolve("maven-mirror", *mavenMirror, "CAMUNDA_MAVEN_MIRROR")),
		MavenSettings:          strings.TrimSpace(resolve("maven-settings", *mavenSettings, "CAMUNDA_MAVEN_SETTINGS")),
		MavenCentralOnly:       *mavenCentralOnly,
		TSProxySupport:         *tsProxySupport,
		JavaHome:               strings.TrimSpace(resolve("java-home", *javaHome, "CAMUNDA_JAVA_HOME")),
		PythonBin:              strings.TrimSpace(resolve("python-bin", *pythonBin, "CAMUNDA_PYTHON_BIN")),
		NodeBin:                strings.TrimSpace(resolve("node-bin", *nodeBin, "CAMUNDA_NODE_BIN")),
		DotnetBin:              strings.TrimSpace(resolve("dotnet-bin", *dotnetBin, "CAMUNDA_DOTNET_BIN")),
		TrainingGroupID:        strings.TrimSpace(*trainingGroup), OutPath: strings.TrimSpace(*outPath), LogFilePath: strings.TrimSpace(*logFile),
		DiagnosticInsecureSkipVerify: *diagnosticInsecure,
		AutoDetect:                   *autoFlag,
	}

	// Providing any --maven-* config implies the operator wants the depcheck to
	// run, so treat it as opt-in too (matches the Java probe's own logic).
	cfg.MavenDepcheck = *mavenDepcheck || cfg.MavenCentralOnly || cfg.MavenMirror != "" || cfg.MavenSettings != ""

	// The SDK fetch is opt-OUT, so the env form has to be able to turn it off
	// on its own, unlike the opt-in flags above. Explicit flag still wins.
	cfg.NoSDKInstall = *noSDKInstall
	if !setFlags["no-sdk-install"] {
		if v := strings.ToLower(strings.TrimSpace(os.Getenv("CAMUNDA_SDK_AUTO_INSTALL"))); v != "" {
			cfg.NoSDKInstall = v == "0" || v == "false" || v == "no" || v == "off"
		}
	}

	if cfg.ProxyURL != "" {
		if err := validateProxyScheme(cfg.ProxyURL); err != nil {
			return nil, err
		}
	}

	if cfg.JavaTrustStorePassword != "" && cfg.JavaTrustStorePath == "" {
		return nil, errors.New("--java-truststore-password was given without --java-truststore — it has nothing to unlock")
	}

	if cfg.JavaTrustStorePath != "" {
		// A typo'd/missing path is not just "file not found" for this specific
		// JVM system property — the JDK's default TrustManagerFactory SILENTLY
		// falls back to the regular cacerts trust store when the file named by
		// javax.net.ssl.trustStore doesn't exist (documented JSSE behavior, not
		// a bug), so a broken path produces a quiet false PASS against any
		// publicly-trusted host instead of an error. Catch it here, loudly,
		// before it ever reaches the JVM.
		if _, err := os.Stat(cfg.JavaTrustStorePath); err != nil {
			return nil, fmt.Errorf("--java-truststore %q: %w (a missing file here fails SILENTLY inside the JVM — it falls back to the default cacerts rather than erroring, which would look like a false PASS)", cfg.JavaTrustStorePath, err)
		}
	}

	if *stacksFlag != "" {
		for _, s := range strings.Split(*stacksFlag, ",") {
			s = strings.TrimSpace(strings.ToLower(s))
			if s != "" {
				cfg.Stacks = append(cfg.Stacks, s)
			}
		}
	}

	// Reject an unknown --stacks value UP FRONT — before any Go transport
	// checks run. A typo like "jav" is not a real runtime, so treating it as a
	// "runtime not installed" FAIL (which is what the launcher would do) is
	// misleading: the fix is a corrected flag, not installing something. A
	// genuine-but-absent runtime (e.g. "java" with no JDK) still flows through
	// to the launcher's not-installed handling.
	for _, s := range cfg.Stacks {
		if !launcher.IsKnownStack(s) {
			msg := fmt.Sprintf("unknown --stacks value %q: valid runtimes are %s", s, strings.Join(launcher.KnownStacks, ", "))
			if hint := launcher.SuggestStack(s); hint != "" {
				msg += fmt.Sprintf(" (did you mean %q?)", hint)
			}
			return nil, errors.New(msg)
		}
	}

	// --skip-transport with no runtime selection would run NOTHING and still
	// print "All checks passed" — a false-green. Require an explicit --stacks or
	// --auto so there is actually a Layer 2 probe to run.
	if *skipTransportFlag && len(cfg.Stacks) == 0 && !*autoFlag {
		return nil, errors.New("--skip-transport runs only the Layer 2 runtime probes, so it needs a runtime to run: pass --stacks (e.g. --stacks java,python) or --auto")
	}

	// The Maven depcheck runs only inside the java probe, so opting into it
	// without selecting the java stack would silently do nothing. Require an
	// explicit --stacks including java (or --auto, which will pick java up if
	// present) — same false-negative guard as --skip-transport.
	if cfg.MavenDepcheck && !cfg.AutoDetect {
		hasJava := false
		for _, s := range cfg.Stacks {
			if s == "java" {
				hasJava = true
			}
		}
		if !hasJava {
			return nil, errors.New("the Maven dependency-resolution check (--maven-depcheck / --maven-mirror / --maven-settings / --maven-central-only) runs inside the Java probe, so it needs the java stack: pass --stacks java (or --auto)")
		}
	}

	// Mode: network is the hard default. No auto-detect from credential
	// presence -- CAMUNDA_CLIENT_ID/SECRET being set in the environment
	// (e.g. left over from an earlier, unrelated run) does not switch the
	// mode. Full mode is opt-in: pass --mode full explicitly.
	modeArg := strings.ToLower(strings.TrimSpace(*modeFlag))
	switch modeArg {
	case "network", "":
		cfg.Mode = model.ModeNetwork
		cfg.ModeExplicit = modeArg == "network"
	case "full":
		cfg.Mode = model.ModeFull
		cfg.ModeExplicit = true
	default:
		return nil, fmt.Errorf("invalid --mode %q: must be 'network' or 'full'", *modeFlag)
	}

	if cfg.Mode == model.ModeFull && (cfg.ClientID == "" || cfg.ClientSecret == "") {
		return nil, fmt.Errorf("full mode requires both CAMUNDA_CLIENT_ID and CAMUNDA_CLIENT_SECRET (or --client-id/--client-secret)")
	}

	// SECURITY: never perform the authenticated OAuth exchange over a
	// connection whose TLS is not verified — that would disclose the client
	// secret to any man-in-the-middle presenting any certificate. Refuse the
	// combination outright rather than silently POSTing credentials through
	// the InsecureSkipVerify client. The diagnostic flag is for debugging
	// transport/TLS in network mode.
	if cfg.Mode == model.ModeFull && cfg.DiagnosticInsecureSkipVerify {
		return nil, fmt.Errorf("--diagnostic-insecure-skip-verify cannot be combined with full mode: it would send the client secret over an unverified TLS connection. Use network mode for insecure transport debugging, or drop the flag for full mode")
	}

	target, err := hostset.Resolve(hostset.Inputs{ExplicitHost: cfg.Host, Region: cfg.Region, ClusterID: cfg.ClusterID})
	if err != nil {
		return nil, err
	}
	cfg.Target = target

	return cfg, nil
}

// validateProxyScheme rejects a --proxy URL scheme we don't actually
// support, with a clear error, instead of letting it through to fail later
// with a confusing dial error. Without this, passing socks5://host:port
// would be silently accepted, then the CONNECT-tunnel dialer would try to
// speak HTTP CONNECT to it — against a real SOCKS server that would produce
// a protocol-mismatch error, not a clear "unsupported" message. Only the
// explicit --proxy flag is validated here; an
// HTTP(S)_PROXY env var pointing at a non-http(s) scheme is not (Go's own
// http.ProxyFromEnvironment resolves that path, not this config layer).
func validateProxyScheme(proxyURL string) error {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return fmt.Errorf("could not parse --proxy %q: %w", proxyURL, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return nil
	default:
		return fmt.Errorf(
			"--proxy %q has scheme %q, which this tool does not support — only http:// and https:// proxies are supported (no SOCKS, no NTLM/Negotiate auth); if this network only offers a SOCKS proxy, that's a genuine gap to report, not something to work around here",
			proxyURL, u.Scheme)
	}
}
