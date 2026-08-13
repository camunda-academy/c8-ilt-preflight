// Package model defines the unified result schema. This is the single
// contract shared by the Layer 1 Go binary and every Layer 2 per-runtime
// probe (via the cross-runtime probe contract) — do not create a second,
// divergent result shape.
package model

// SchemaVersion is bumped on any breaking change to this structure so that
// aggregation of results across tool versions stays stable.
const SchemaVersion = 1

// Verdict is the shared vocabulary used by both Layer 1 stages and Layer 2
// probe fragments.
type Verdict string

const (
	VerdictPass       Verdict = "PASS"
	VerdictWarn       Verdict = "WARN"
	VerdictFail       Verdict = "FAIL"
	VerdictSkip       Verdict = "SKIP"
	VerdictProbeError Verdict = "probe-error"
)

// ErrorClass is the stable remediation-code enum family shared across Layer 1
// stages and Layer 2 probe fragments, so findings aggregate cleanly by code
// instead of requiring prose-parsing.
type ErrorClass string

const (
	ErrOK                   ErrorClass = "OK"
	ErrDNSFail              ErrorClass = "DNS_FAIL"
	ErrConnectRefused       ErrorClass = "CONNECT_REFUSED"
	ErrConnectTimeout       ErrorClass = "CONNECT_TIMEOUT"
	ErrTLSHandshakeFail     ErrorClass = "TLS_HANDSHAKE_FAIL"
	ErrTLSNonPublicIssuer   ErrorClass = "TLS_NON_PUBLIC_ISSUER"
	ErrALPNDowngradeWarn    ErrorClass = "ALPN_DOWNGRADE_WARN"
	ErrProxyAuth407         ErrorClass = "PROXY_AUTH_407"
	ErrClusterEdge404       ErrorClass = "CLUSTER_EDGE_404"
	ErrClusterUnhealthy503  ErrorClass = "CLUSTER_UNHEALTHY_503"
	ErrUnexpectedHTTPStatus ErrorClass = "UNEXPECTED_HTTP_STATUS"
	ErrOAuthTokenFail       ErrorClass = "OAUTH_TOKEN_FAIL"
	ErrOAuthRateLimited     ErrorClass = "OAUTH_RATE_LIMITED"
	ErrTopologyAuthFail     ErrorClass = "TOPOLOGY_AUTH_FAIL"
	ErrTopologyBadResponse  ErrorClass = "TOPOLOGY_BAD_RESPONSE"
	ErrWebComponentUnreach  ErrorClass = "WEBCOMPONENT_UNREACHABLE"
	ErrConfigError          ErrorClass = "CONFIG_ERROR"
	ErrRuntimeAbsent        ErrorClass = "RUNTIME_ABSENT"
	ErrProbeCrashed         ErrorClass = "PROBE_CRASHED"
	// ErrConnectionClosed is for a connection that was ESTABLISHED then
	// closed unexpectedly mid-request (e.g. Java's
	// org.apache.hc.core5.http.ConnectionClosedException) -- deliberately
	// distinct from ErrConnectRefused (which means the connection was never
	// established at all, e.g. a firewall drop). Found live: this exact
	// class of error was being mislabeled CONNECT_REFUSED, wrongly implying
	// a firewall block, when a real cause found in this project was a
	// config-side trust-store gap in a request interceptor that ran before
	// the request completed -- not a network block at all. Not in
	// networkFailCodes (build.go): the cause is genuinely ambiguous (could
	// be a stale proxy, a misbehaving interceptor, or something server-side)
	// so it must not claim "your network," and it must not outrank a
	// co-occurring config diagnostic that may well be the actual cause.
	ErrConnectionClosed      ErrorClass = "CONNECTION_CLOSED"
	ErrMavenArtifactMissing  ErrorClass = "MAVEN_ARTIFACT_MISSING"
	ErrMavenMirrorAuth       ErrorClass = "MAVEN_MIRROR_AUTH"
	ErrMavenMirrorUnreach    ErrorClass = "MAVEN_MIRROR_UNREACHABLE"
	ErrMavenCentralUnreach   ErrorClass = "MAVEN_CENTRAL_UNREACHABLE"
	ErrMavenWrapperBootstrap ErrorClass = "MAVEN_WRAPPER_BOOTSTRAP_FAIL"
	// ErrMavenResolveFail is the GENERIC "Maven ran but couldn't resolve the
	// artifact, cause not isolated" class. The SDK-snippet probe (SdkProbe /
	// run.sh|run.cmd) emits it when its own opt-in dependency fetch fails —
	// it deliberately does NOT try to distinguish mirror-down vs 401 vs
	// artifact-missing vs Central-blocked (that's the dedicated Maven
	// dependency-resolution check's job, via its Central-vs-mirror comparison).
	// The more specific MAVEN_* classes above are reserved for that probe,
	// which actually isolates the cause.
	ErrMavenResolveFail ErrorClass = "MAVEN_RESOLVE_FAIL"
)

// Mode is the run mode: network (credential-free) or full (authenticated).
type Mode string

const (
	ModeNetwork Mode = "network"
	ModeFull    Mode = "full"
)

// Stage is one Layer 1 transport/health check result.
type Stage struct {
	Name            string     `json:"name"`
	Host            string     `json:"host"`
	Port            int        `json:"port,omitempty"`
	Verdict         Verdict    `json:"verdict"`
	HTTPStatus      int        `json:"httpStatus,omitempty"`
	RemediationCode ErrorClass `json:"remediationCode"`
	Detail          string     `json:"detail"`
	ElapsedMs       int64      `json:"elapsedMs"`
}

// TLSInfo is the certificate summary for one probed host.
type TLSInfo struct {
	Host           string `json:"host"`
	Issuer         string `json:"issuer"`
	Subject        string `json:"subject"`
	IsPublicCA     bool   `json:"isPublicCA"`
	NotAfter       string `json:"notAfter,omitempty"`
	NegotiatedALPN string `json:"negotiatedALPN,omitempty"`
}

// ProbeFragment is what each Layer 2 native probe emits on stdout (the
// cross-runtime probe contract). The launcher stamps schemaVersion/
// toolVersion/timestamp centrally and merges these into Probes below —
// probes themselves never emit the full envelope.
type ProbeFragment struct {
	Runtime             string     `json:"runtime"`
	TrustStoreExercised string     `json:"trustStoreExercised"`
	Target              string     `json:"target"`
	Verdict             Verdict    `json:"verdict"`
	ErrorClass          ErrorClass `json:"errorClass"`
	Detail              string     `json:"detail"`
}

// Target describes the resolved connection target for this run.
type Target struct {
	Region      string              `json:"region"`
	ClusterID   string              `json:"clusterId,omitempty"`
	APIHost     string              `json:"apiHost"`
	ZeebeHost   string              `json:"zeebeHost"`
	ResolvedIPs map[string][]string `json:"resolvedIPs,omitempty"`
	OAuthHost   string              `json:"oauthHost"`
	// DetectedProxy: credentials are always masked; the hostname/IP itself is
	// ALSO masked by default (--unmasked-hostnames opts out) since this file is
	// routinely shared with a third party (the training team) and the proxy
	// address reveals internal network naming. Empty = no proxy in effect.
	DetectedProxy string `json:"detectedProxy,omitempty"`

	// SystemProxy is what the OS itself has configured, which is a different
	// source from the environment variables DetectedProxy reflects. Recorded
	// separately, and never merged into DetectedProxy, because the tool did NOT
	// route through it: conflating them would claim a path that was never taken.
	// Subject to the same --unmasked-hostnames masking as DetectedProxy. Empty
	// means either nothing configured or a platform where this isn't read.
	SystemProxy string `json:"systemProxy,omitempty"`
}

// Overall is the top-line verdict summary.
type Overall struct {
	Verdict             Verdict `json:"verdict"`
	FailingStage        string  `json:"failingStage,omitempty"`
	IsOurClusterProblem bool    `json:"isOurClusterProblem"`
}

// RuntimeDetail identifies the exact runtime installation a Layer 2 stack was
// actually checked with — not just which language, but which binary and which
// version of it.
//
// A trust store belongs to a runtime *installation*, not to a language: Java
// reads the cacerts of whichever JDK ran, Python the certifi of whichever
// interpreter ran, Node a CA set that varies by major version. A machine with
// several JDKs (or a system Python next to a project venv) will hand the probe
// whichever one happens to come first on PATH, which may not be the one the
// training exercises use. When that happens the probe validates a different
// trust store than training day will, so recording the identity of what ran is
// what makes a green result meaningful and a red one diagnosable.
type RuntimeDetail struct {
	Stack   string `json:"stack"`
	Binary  string `json:"binary,omitempty"`  // resolved absolute path
	Version string `json:"version,omitempty"` // as self-reported, first line
	// Pinned records that an operator selected this installation explicitly
	// (--java-home and friends) rather than it being whatever PATH offered.
	Pinned bool `json:"pinned,omitempty"`
}

// Result is the unified, versioned document written by every run.
type Result struct {
	SchemaVersion   int    `json:"schemaVersion"`
	ToolVersion     string `json:"toolVersion"`
	Mode            Mode   `json:"mode"`
	Timestamp       string `json:"timestamp"`
	OS              string `json:"os"`
	Arch            string `json:"arch"`
	TrainingGroupID string `json:"trainingGroupId,omitempty"`

	// StacksRequested is the human-readable --stacks/--auto selection (e.g.
	// "java, python" or "(auto-detect)"), shown in the terminal Header before
	// Layer 2 runs -- it reflects what was REQUESTED, not RuntimesDetected
	// (which isn't known yet at header-print time, since detection happens
	// later). Presentation-only: excluded from the persisted JSON (json:"-")
	// since it's not part of the cross-runtime result schema and adds nothing
	// the training dashboard needs.
	StacksRequested string `json:"-"`

	// Verbose mirrors --verbose/CAMUNDA_PREFLIGHT_VERBOSE. Notes() uses it to
	// decide whether to append the raw technical detail (exception text,
	// remediation-code cross-references) under each Troubleshooting/General
	// bullet, or keep the default view to just the plain-language checklist
	// action -- readable by a training participant, not just an engineer.
	// Presentation-only: excluded from the persisted JSON, same reasoning as
	// StacksRequested above.
	Verbose bool `json:"-"`

	// DiagnosticInsecure records that --diagnostic-insecure-skip-verify was
	// active. When true, any HTTPS-client stage ran with TLS verification
	// DISABLED and its verdict is NOT trustworthy — the tool suppresses PASS
	// verdicts for those stages. Present so a reader/aggregator
	// can never mistake such a run for a clean result.
	DiagnosticInsecure bool `json:"diagnosticInsecureSkipVerify,omitempty"`

	Target Target `json:"target"`

	Stages []Stage   `json:"stages"`
	TLS    []TLSInfo `json:"tls"`

	RuntimesDetected []string        `json:"runtimesDetected,omitempty"`
	RuntimesSkipped  []string        `json:"runtimesSkipped,omitempty"`
	Runtimes         []RuntimeDetail `json:"runtimes,omitempty"`
	Probes           []ProbeFragment `json:"probes,omitempty"`

	Overall Overall `json:"overall"`
}

// ExitCode maps the documented exit-code table to a value.
type ExitCode int

const (
	ExitOK                ExitCode = 0
	ExitGenericError      ExitCode = 1
	ExitNetworkFail       ExitCode = 2
	ExitFullModeAuthFail  ExitCode = 3
	ExitConfigError       ExitCode = 4
	ExitOurClusterProblem ExitCode = 5
)
