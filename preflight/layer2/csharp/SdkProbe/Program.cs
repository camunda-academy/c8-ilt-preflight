// Layer 2 SDK-snippet confirmation -- C#/.NET, tier 2.
//
// Standalone (requires the real SDK restored - see run.sh/run.cmd, which run
// `dotnet restore --locked-mode` against the committed packages.lock.json
// when CAMUNDA_SDK_AUTO_INSTALL=1 / --install is set):
//
//   dotnet build SdkProbe.csproj -c Release -o out && dotnet out/SdkProbe.dll
//
// This is the "literal SDK connects + gets topology" real confirmation
// meant to run alongside the SDK-free native probe (Probe/Program.cs) --
// catching proxy-handling/config issues the raw probe can't.
//
// ---------------------------------------------------------------------------
// Package/version - see SdkProbe.csproj's own comment for the full verified
// finding (Camunda.Orchestration.Sdk, exact-pinned 9.1.3, corrected from an
// initial "9.*" range guess; a 10.0.0 stable exists on NuGet but is
// unlisted).
//
// Client construction / methods - verified against the real SDK's source at
// git tag v9.1.3 (CamundaClient.cs, Generated/CamundaClient.Generated.cs), NOT
// trusted from the original literal guess until confirmed:
//   - CamundaClient.Create(CamundaOptions?) matches the original guess exactly.
//   - GetTopologyAsync() also matches the original guess exactly - returns
//     TopologyResponse with a Brokers list, matching this tool's convention.
//   - GetStatusAsync() (the network-mode analog, NOT part of the original
//     guess, which only covered GetTopologyAsync) - a Task with no return
//     value; throws HttpSdkException with a real HTTP status for any non-2xx
//     response, including 503 (cluster unhealthy) and a stray 404 (edge/no
//     route). No response body is required (204 -> success).
//
// Env vars - verified against ConfigurationHydrator.cs source, not assumed:
//   CAMUNDA_REST_ADDRESS      SDK auto-appends /v2 if missing - but does NOT
//       do UUID extraction or stray-segment stripping, so it has the SAME
//       Console copy-paste ":443" gap already confirmed for the Python/Java/
//       TypeScript SDKs (see NormalizeRestBase below).
//   CAMUNDA_AUTH_STRATEGY     NONE/OAUTH/BASIC, default NONE - but
//       ConfigurationHydrator.Hydrate SILENTLY auto-upgrades NONE -> OAUTH the
//       moment CAMUNDA_CLIENT_ID/CAMUNDA_CLIENT_SECRET are BOTH present in the
//       environment and the caller never set CAMUNDA_AUTH_STRATEGY explicitly
//       - the EXACT SAME auto-upgrade gap the TypeScript SDK has too
//       (a different mechanism, same risk: a network-mode run that merely
//       left auth unconfigured would silently authenticate if credentials
//       happen to be in the shell). Fixed here by explicitly passing
//       CAMUNDA_AUTH_STRATEGY=NONE via the Config override in network mode.
//   CAMUNDA_CLIENT_ID / CAMUNDA_CLIENT_SECRET     OAuth credentials.
//   CAMUNDA_OAUTH_URL         defaults to
//       https://login.cloud.camunda.io/oauth/token - the SAME default this
//       tool's Go binary uses. Unlike Java (whose raw SDK uses a DIFFERENT
//       name, CAMUNDA_AUTHORIZATION_SERVER_URL, with no equivalent default),
//       there is no name-mismatch or missing-default gap here.
//   CAMUNDA_TOKEN_AUDIENCE    defaults to "zeebe.camunda.io" - again the SAME
//       default the Go binary uses (Java's raw SDK has NO built-in default at
//       all and crashes without it - not the case here).
//   CAMUNDA_MTLS_CA_PATH      the SAME env var name Go/Python/TypeScript read
//       (verified in the SDK's own README + ConfigurationHydrator.cs) - unlike
//       Java (CAMUNDA_CA_CERTIFICATE_PATH, a different name needing its own
//       mismatch WARN), there is no name trap for C# either.
//
// Trust-store nuance for this tier - see Shared.cs's TrustContext doc comment
// for the full verified finding: the real SDK's TlsHelper.BuildHandler
// produces functionally APPEND semantics (OS store OR custom CA), the
// OPPOSITE of Java's/TypeScript's true replace-the-whole-store behavior.
// Because AuthHandler.SendAsync explicitly builds its OAuth token-fetch
// HttpClient from the SAME TlsHelper.BuildHandler(_config.Tls) as the main
// client (verified in AuthHandler.cs source), there is NO separate
// un-wired-trust-config gap for the OAuth call the way there is in Java's raw
// SDK (where the OAuth client's trust store is a completely separate,
// unwired config surface) - a genuine positive finding, not assumed.
//
// A missing/unreadable CAMUNDA_MTLS_CA_PATH file throws a loud
// FileNotFoundException at CamundaClient.Create() time (TlsHelper.ReadPath) -
// the OPPOSITE of Java's silent javax.net.ssl.trustStore-missing-file
// footgun. This probe catches that (and CamundaConfigurationException, thrown
// for other invalid config combinations) and turns it into a CONFIG_ERROR WARN
// fragment rather than a raw crash.
//
// Proxy - NOT addressed by this SDK's own code (no HTTP(S)_PROXY handling
// anywhere in its source); it builds a plain HttpClientHandler with no Proxy
// override when no custom TLS config forces a custom handler, so it inherits
// .NET's OWN default proxy resolution (HttpClient.DefaultProxy /
// HttpEnvironmentProxy), which DOES check HTTP_PROXY/HTTPS_PROXY environment
// variables cross-platform since .NET Core - a genuine, positive difference
// from Node (whose fetch ignores these vars entirely) and Java (which needs
// JVM system properties, not env vars). Verified live via mitmproxy.
//
// Logging / stdout-contamination finding, verified against
// SdkConsoleLoggerFactory.cs + CamundaConfig.cs source, NOT a credential leak
// like Python's/TypeScript's client_id-at-debug-level gap, but a DIFFERENT and
// arguably more disruptive risk for THIS project specifically: when no custom
// ILoggerFactory is supplied, the SDK's own built-in console logger routes
// Trace/Debug/Information/Warning-level lines to Console.Out (STDOUT) and only
// Error/Critical to stderr. The default CAMUNDA_SDK_LOG_LEVEL ("error") means
// nothing reaches stdout by default - but if a user raises it (e.g.
// CAMUNDA_SDK_LOG_LEVEL=debug for troubleshooting, a completely reasonable
// thing to try), human-readable log lines would interleave with this probe's
// newline-delimited JSON fragments on stdout and corrupt the launcher's
// parsing, which requires exactly one JSON object on stdout and nothing
// else. No client_id/secret is logged anywhere in the paths exercised by
// this probe (CamundaClient's own debug line only logs the auth STRATEGY name,
// and OAuthManager's logs never include client_id) - a genuine, verified
// ABSENCE of the Python/TypeScript-style credential leak. Fixed defensively
// here (belt-and-suspenders) by ALWAYS passing LoggerFactory =
// NullLoggerFactory.Instance, regardless of CAMUNDA_SDK_LOG_LEVEL, so the
// stdout contract can never be put at risk by an operator's own log-level
// choice.
// ---------------------------------------------------------------------------

using Camunda.Orchestration.Sdk;
using CamundaPreflight;
using Microsoft.Extensions.Logging.Abstractions;

const string Usage = "Layer 2 SDK-snippet confirmation -- C#/.NET.\n" +
    "Requires Camunda.Orchestration.Sdk 9.1.3 - see run.sh/run.cmd or CAMUNDA_SDK_AUTO_INSTALL.\n" +
    "Supported env vars are listed in this probe's source header.";

if (Array.IndexOf(args, "-h") >= 0 || Array.IndexOf(args, "--help") >= 0)
{
    Console.Error.WriteLine(Usage);
    return 0;
}

try
{
    return await RunAsync(args);
}
catch (Exception ex)
{
    // Last-resort: never let an unhandled exception produce a bare stack
    // trace on stdout that the launcher can't parse -- emit a proper
    // probe-error fragment instead, per the cross-runtime probe contract.
    Console.WriteLine(Shared.CrashFragment(ex.ToString()));
    return 1;
}

async Task<int> RunAsync(string[] a)
{
    var restBase = Shared.NormalizeRestBase();
    var exitCode = 0;

    // Emit the normalization notice only in verbose mode: useful to the
    // operator/trainer but confusing noise for a participant (the
    // normalization still happens silently, so the check is valid regardless)
    // -- mirrors every other language's identical convention.
    if (restBase.WasNormalized && Shared.IsVerbose(a))
    {
        Console.WriteLine(Shared.EmitFragment(
            restBase.Host + " (config)",
            "WARN",
            "CONFIG_ERROR",
            "your CAMUNDA_REST_ADDRESS is Camunda Console's copy-paste form (stray ':443' path segment). " +
            "This preflight normalized it to " + restBase.Value + " so the check is valid -- BUT the C# SDK does " +
            "NOT do this itself (it only conditionally appends '/v2' when missing; verified in its own " +
            "ConfigurationHydrator.Hydrate source) -- pasting the raw Console string straight into your SDK config " +
            "yields the same opaque 'default backend - 404' already confirmed for the Python/Java/TypeScript SDKs. " +
            "Use the canonical form " + restBase.Value + " in participant SDK config."));
    }

    var customCa = (Environment.GetEnvironmentVariable("CAMUNDA_MTLS_CA_PATH") ?? "").Trim();
    var trustLabel = string.IsNullOrEmpty(customCa)
        ? "the OS certificate store"
        : $"the OS certificate store, plus your custom certificate ({customCa})";

    var hasCreds = !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("CAMUNDA_CLIENT_ID"))
                && !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("CAMUNDA_CLIENT_SECRET"));
    var isFull = Shared.ResolveIsFull(Environment.GetEnvironmentVariable("CAMUNDA_PREFLIGHT_MODE"), hasCreds);

    var config = new Dictionary<string, string> { ["CAMUNDA_REST_ADDRESS"] = restBase.Value };
    if (!isFull)
    {
        // Force credential-free even if CAMUNDA_CLIENT_ID/SECRET happen to be
        // present -- see the module doc comment's "auth-strategy auto-upgrade"
        // finding, verified in ConfigurationHydrator.Hydrate source.
        config["CAMUNDA_AUTH_STRATEGY"] = "NONE";
    }

    CamundaClient client;
    try
    {
        client = CamundaClient.Create(new CamundaOptions
        {
            Config = config,
            // REQUIRED, not optional -- see the module doc comment's "stdout
            // contamination" finding. Forcing NullLoggerFactory here means the
            // SDK's own console logger (which would otherwise write
            // Trace/Debug/Information/Warning lines to stdout) can never fire,
            // regardless of what CAMUNDA_SDK_LOG_LEVEL the environment sets.
            LoggerFactory = NullLoggerFactory.Instance,
        });
    }
    catch (Exception e)
    {
        // Construction-time failures: a missing/unreadable custom CA/cert/key
        // file throws FileNotFoundException (TlsHelper.ReadPath); invalid
        // config (e.g. BASIC without a username) throws
        // CamundaConfigurationException. Both are configuration mistakes, not
        // network/trust findings -- surface as a CONFIG_ERROR WARN rather than
        // a raw probe-error/crash fragment.
        Console.WriteLine(Shared.EmitFragment(
            restBase.Host + " (config)",
            "WARN",
            "CONFIG_ERROR",
            "CamundaClient.Create() failed during construction -- check your CAMUNDA_MTLS_CA_PATH/CERT/KEY paths " +
            "and other CAMUNDA_* configuration: " + e.Message));
        return 1;
    }

    using (client)
    {
        var statusTarget = restBase.Host + " (sdk status)";
        try
        {
            await client.GetStatusAsync();
            Console.WriteLine(Shared.EmitFragment(statusTarget, "PASS", "OK", "SDK GetStatusAsync() succeeded", trustLabel));
        }
        catch (CamundaAuthException cae)
        {
            // A rejected/misconfigured OAuth token fetch (e.g. a bad client
            // secret) -- verified live with deliberately fake credentials.
            // CamundaAuthException is NOT
            // an HttpSdkException (the rejection happens against the OAuth
            // token endpoint, not the cluster's own REST API) and carries no
            // structural HTTP-status/socket info ClassifyTransportError can
            // key off, so without this dedicated catch it fell through to
            // ClassifyTransportError's generic text-matching fallback and was
            // mislabeled CONNECT_REFUSED -- wrongly implying a firewall block
            // for what is really a credential/config problem. Caught here
            // explicitly and classified as OAUTH_TOKEN_FAIL (the shared enum
            // already has this exact class -- schema.go's ErrOAuthTokenFail).
            Console.WriteLine(Shared.EmitFragment(statusTarget, "FAIL", "OAUTH_TOKEN_FAIL", "OAuth token request failed: " + cae.Message, trustLabel));
            exitCode = 1;
        }
        catch (HttpSdkException hse)
        {
            // Mirrors the Go binary's status.go classification and every
            // other language's SDK-tier precedent: a completed TLS
            // handshake plus ANY clean HTTP response means transport reached
            // the cluster edge, so it is NEVER a customer-side network FAIL.
            // 204 = healthy (the try-block above); 503 = cluster unhealthy;
            // ANY other status (incl. a stray 404 from a paused/blipping
            // cluster) = reached-the-edge-no-route.
            if (hse.Status == 503)
            {
                Console.WriteLine(Shared.EmitFragment(
                    statusTarget,
                    "FAIL",
                    "CLUSTER_UNHEALTHY_503",
                    "cluster reachable but unhealthy (503) -- likely our shared preflight cluster, not your network: " + hse.Message,
                    trustLabel));
            }
            else
            {
                Console.WriteLine(Shared.EmitFragment(statusTarget, "FAIL", "CLUSTER_EDGE_404", ClusterEdgeDetail(hse.Status), trustLabel));
            }
            exitCode = 1;
        }
        catch (Exception e)
        {
            var (errorClass, detail) = Shared.ClassifyTransportError(e);
            Console.WriteLine(Shared.EmitFragment(statusTarget, "FAIL", errorClass, detail, trustLabel));
            exitCode = 1;
        }

        // GetTopologyAsync() is the authenticated, FULL-MODE-ONLY analog. In
        // network mode emit NO fragment at all -- matching the Go binary and
        // every other language's probe, which simply omit their topology
        // stage in network mode.
        var topologyTarget = restBase.Host + " (sdk topology)";
        if (!isFull)
        {
            // network mode: credential-free, topology omitted (no line), like Go.
        }
        else if (!hasCreds)
        {
            Console.WriteLine(Shared.EmitFragment(
                topologyTarget,
                "SKIP",
                "OK",
                "full mode requested but CAMUNDA_CLIENT_ID/CAMUNDA_CLIENT_SECRET are not set -- cannot run the authenticated GetTopologyAsync() check"));
        }
        else
        {
            try
            {
                var topo = await client.GetTopologyAsync();
                var brokerCount = topo.Brokers?.Count ?? 0;
                Console.WriteLine(Shared.EmitFragment(
                    topologyTarget,
                    "PASS",
                    "OK",
                    $"SDK GetTopologyAsync() succeeded, {brokerCount} broker(s)",
                    trustLabel));
            }
            catch (CamundaAuthException cae)
            {
                // See the identical catch on the status check above -- same
                // OAuth-token-fetch-failure class, verified live with fake
                // credentials.
                Console.WriteLine(Shared.EmitFragment(topologyTarget, "FAIL", "OAUTH_TOKEN_FAIL", "OAuth token request failed: " + cae.Message, trustLabel));
                exitCode = 1;
            }
            catch (HttpSdkException hse)
            {
                // 401 = a real, actionable auth failure (customer/config side)
                // -> FAIL. Any other non-200 status = reached the cluster
                // edge, our side not yours -> also FAIL (blocks training right
                // now), same reasoning as the status check above.
                if (hse.Status == 401)
                {
                    Console.WriteLine(Shared.EmitFragment(
                        topologyTarget,
                        "FAIL",
                        "TOPOLOGY_AUTH_FAIL",
                        "authenticated topology request rejected (401): " + hse.Message,
                        trustLabel));
                }
                else
                {
                    Console.WriteLine(Shared.EmitFragment(topologyTarget, "FAIL", "CLUSTER_EDGE_404", ClusterEdgeDetail(hse.Status), trustLabel));
                }
                exitCode = 1;
            }
            catch (Exception e)
            {
                var (errorClass, detail) = Shared.ClassifyTransportError(e);
                Console.WriteLine(Shared.EmitFragment(topologyTarget, "FAIL", errorClass, detail, trustLabel));
                exitCode = 1;
            }
        }
    }

    return exitCode;
}

string ClusterEdgeDetail(int? code) =>
    $"reached the cluster edge (HTTP {code}) but got no valid cluster route -- this typically means our shared " +
    "preflight cluster is paused or in a transient edge blip, NOT a problem with your network. Re-run in ~5 " +
    "minutes; if it persists, contact the training team.";
