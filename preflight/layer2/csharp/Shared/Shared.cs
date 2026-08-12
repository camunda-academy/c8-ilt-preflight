// Shared helpers for the C#/.NET Layer 2 probes (Probe/Program.cs,
// SdkProbe/Program.cs). Mirrors preflight/layer2/typescript/_shared.js's
// (and _shared.py's / Shared.java's) structure and division of labor --
// centralized so probes never carry two independently-drifting copies of the
// same fragment-emission / classification / redaction logic, keeping one
// shared vocabulary across every language's probe.
//
// This file is compiled into BOTH Probe.csproj (zero NuGet dependencies) and
// SdkProbe.csproj (references Camunda.Orchestration.Sdk) via an explicit
// <Compile Include> link in each project -- mirroring Java's precedent of
// compiling Shared.java into both Probe.java and SdkProbe.java separately, so
// a tier-2 issue can never take down the mandatory tier-1 probe. Uses
// System.Text.Json for fragment serialization: this is part of the .NET base
// class library since .NET Core 3.0, not a third-party NuGet package -- the
// "no JSON library" rule the other languages follow exists because THEY have
// no JSON serializer in their standard library at all (Java, Python's stdlib,
// Node's stdlib all hand-roll or avoid one for exactly that reason); C# does
// ship one, so using it is the idiomatic choice here, not a violation of that
// rule's intent.
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace CamundaPreflight;

public static class Shared
{
    public const string Runtime = "csharp";

    // Matches inline URL credentials (scheme://user:pass@host) so they can be
    // masked out of any text before it's emitted, mirrored from
    // _shared.py's scrub_url_creds / _shared.js's scrubUrlCreds /
    // Shared.java's scrubUrlCreds.
    private static readonly Regex UrlCredsRe = new(@"(\w+://)[^/@\s:]+:[^/@\s]+@", RegexOptions.Compiled);

    private static readonly Regex UuidRe = new(
        @"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly JsonSerializerOptions FragmentJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public static string ScrubUrlCreds(string? text)
    {
        if (string.IsNullOrEmpty(text)) return text ?? "";
        return UrlCredsRe.Replace(text, "$1****:****@");
    }

    // Field order/names here (via PascalCase -> camelCase policy) produce
    // exactly {runtime, trustStoreExercised, target, verdict, errorClass,
    // detail} -- the cross-runtime probe contract, matched against
    // model.ProbeFragment in preflight/layer1/internal/model/schema.go.
    public sealed record ProbeFragment(
        [property: JsonPropertyName("runtime")] string Runtime,
        [property: JsonPropertyName("trustStoreExercised")] string TrustStoreExercised,
        [property: JsonPropertyName("target")] string Target,
        [property: JsonPropertyName("verdict")] string Verdict,
        [property: JsonPropertyName("errorClass")] string ErrorClass,
        [property: JsonPropertyName("detail")] string Detail);

    public static string EmitFragment(string target, string verdict, string errorClass, string detail, string trustStore = "")
    {
        // Scrub URL credentials from the detail as a universal backstop --
        // every emitted fragment funnels through here, so a proxy password
        // embedded in an exception string can't leak to stdout regardless of
        // which code path built the detail (mirrors every other language's
        // fragment() helper).
        var frag = new ProbeFragment(Runtime, trustStore, target, verdict, errorClass, ScrubUrlCreds(detail));
        return JsonSerializer.Serialize(frag, FragmentJsonOptions);
    }

    public static string CrashFragment(string detail) =>
        EmitFragment("", "probe-error", "PROBE_CRASHED", "probe crashed: " + detail);

    /// <summary>
    /// Whether to surface extra diagnostic fragments hidden by default (e.g.
    /// the Console-URL normalization notice) -- useful to the
    /// operator/trainer, but confusing noise for participants. Set by the
    /// launcher via CAMUNDA_PREFLIGHT_VERBOSE (from the Go binary's
    /// --verbose), or by passing --verbose when running a probe standalone.
    /// </summary>
    public static bool IsVerbose(string[] args)
    {
        if (Array.IndexOf(args, "--verbose") >= 0) return true;
        var v = (Environment.GetEnvironmentVariable("CAMUNDA_PREFLIGHT_VERBOSE") ?? "").Trim().ToLowerInvariant();
        return v is "1" or "true" or "yes";
    }

    /// <summary>
    /// Mirrors the Go binary's network-vs-full decision so probes never
    /// diverge from it: network mode must be credential-free -- status
    /// only, no authenticated topology, no token. An explicit mode
    /// (passed by the launcher via CAMUNDA_PREFLIGHT_MODE) wins; when unset
    /// (probe run standalone by hand) fall back to creds-presence
    /// auto-detect, the same default the Go binary uses.
    /// </summary>
    public static bool ResolveIsFull(string? mode, bool hasCreds)
    {
        var m = (mode ?? "").Trim().ToLowerInvariant();
        if (m == "network") return false;
        if (m == "full") return true;
        return hasCreds;
    }

    public static string? GetProxyUrl()
    {
        foreach (var name in new[] { "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy" })
        {
            var v = Environment.GetEnvironmentVariable(name);
            if (!string.IsNullOrEmpty(v)) return v;
        }
        return null;
    }

    public static string MaskProxy(string? proxyUrl)
    {
        if (string.IsNullOrEmpty(proxyUrl)) return "";
        try
        {
            var u = new Uri(proxyUrl);
            var userInfo = u.UserInfo;
            if (string.IsNullOrEmpty(userInfo)) return proxyUrl;
            var builder = new UriBuilder(u) { UserName = "****", Password = "****" };
            return builder.Uri.ToString();
        }
        catch
        {
            return proxyUrl;
        }
    }

    /// <summary>
    /// Same config-source precedence as the Go binary and every other
    /// language's probe: an explicit CAMUNDA_REST_ADDRESS host wins over
    /// CAMUNDA_REGION.
    /// </summary>
    public static string ResolveApiHost()
    {
        var restAddress = (Environment.GetEnvironmentVariable("CAMUNDA_REST_ADDRESS") ?? "").Trim();
        var region = (Environment.GetEnvironmentVariable("CAMUNDA_REGION") ?? "").Trim();
        if (string.IsNullOrEmpty(region)) region = "bru-2";

        if (!string.IsNullOrEmpty(restAddress))
        {
            var candidate = restAddress.Contains("://") ? restAddress : "https://" + restAddress;
            if (Uri.TryCreate(candidate, UriKind.Absolute, out var uri) && !string.IsNullOrEmpty(uri.Host))
                return uri.Host;
        }
        return region + ".api.camunda.io";
    }

    public readonly record struct RestBase(string Value, string Host, bool WasNormalized);

    /// <summary>
    /// Rebuild a canonical https://&lt;host&gt;/&lt;clusterId&gt; REST base,
    /// mirroring the Go binary's hostset.parseExplicitHost tolerance (UUID-
    /// anywhere-in-path + authority-port stripping) and Python's
    /// _shared.normalize_rest_base / Java's Shared.normalizeRestBase /
    /// TypeScript's _shared.js normalizeRestBase.
    ///
    /// This exists because Camunda Console's copy-paste CAMUNDA_REST_ADDRESS
    /// form embeds a stray ':443' path segment
    /// (https://&lt;host&gt;/:443/&lt;clusterId&gt;/v2/) that the real C# SDK
    /// does NOT tolerate either -- verified against its own
    /// ConfigurationHydrator.Hydrate source (the "Normalize restAddress to
    /// /v2" step only conditionally appends '/v2' when the trimmed string
    /// doesn't already end with it; there is no UUID extraction or
    /// stray-segment stripping) -- the SAME known gap already confirmed for
    /// the Python, Java, and TypeScript SDKs.
    /// </summary>
    public static RestBase NormalizeRestBase()
    {
        var raw = (Environment.GetEnvironmentVariable("CAMUNDA_REST_ADDRESS") ?? "").Trim();
        var region = (Environment.GetEnvironmentVariable("CAMUNDA_REGION") ?? "").Trim();
        if (string.IsNullOrEmpty(region)) region = "bru-2";
        var clusterIdEnv = (Environment.GetEnvironmentVariable("CAMUNDA_CLUSTER_ID") ?? "").Trim();

        if (string.IsNullOrEmpty(raw))
        {
            var host = region + ".api.camunda.io";
            var restBase = string.IsNullOrEmpty(clusterIdEnv) ? "https://" + host : "https://" + host + "/" + clusterIdEnv;
            return new RestBase(restBase, host, false);
        }

        var candidate = raw.Contains("://") ? raw : "https://" + raw;
        if (!Uri.TryCreate(candidate, UriKind.Absolute, out var parsed))
            return new RestBase(candidate, region + ".api.camunda.io", false);

        var hostOut = !string.IsNullOrEmpty(parsed.Host) ? parsed.Host : region + ".api.camunda.io";
        var segments = parsed.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        string? clusterId = Array.Find(segments, s => UuidRe.IsMatch(s));
        if (string.IsNullOrEmpty(clusterId)) clusterId = clusterIdEnv;

        if (string.IsNullOrEmpty(clusterId))
        {
            // No UUID anywhere -- return the input untouched rather than
            // guessing; the SDK will surface its own error and the native
            // probe still runs.
            return new RestBase(candidate, hostOut, false);
        }

        var canonical = "https://" + hostOut + "/" + clusterId;
        var strayCount = 0;
        foreach (var seg in segments)
        {
            if (seg != clusterId && seg != "v2") strayCount++;
        }
        // An explicit authority port (e.g. Console's raw ":443" form, when it
        // lands as a literal authority port rather than a stray path segment
        // depending on how the string is assembled) is the other signal worth
        // a WARN -- mirrors TS's `parsed.port !== ''` / Java's
        // `parsed.getPort() != -1` checks.
        var explicitPort = Regex.IsMatch(candidate, @"^https?://[^/]+:\d+", RegexOptions.IgnoreCase);
        var wasNormalized = strayCount > 0 || explicitPort;
        return new RestBase(canonical, hostOut, wasNormalized);
    }

    // ---- error classification ----
    // Mirrors probe.py's classify_transport_error / Shared.java's
    // classifyTransportError / _shared.js's classifyTransportError:
    // structural (typed-exception) checks first, then substring matching on
    // the chained exception text for wrapped/opaque cases -- the same
    // layered approach used across every language in this project.

    public static (string ErrorClass, string Detail) ClassifyTransportError(Exception ex)
    {
        var chain = new List<Exception>();
        var seen = new HashSet<Exception>();
        Exception? cur = ex;
        while (cur != null && seen.Add(cur))
        {
            chain.Add(cur);
            cur = cur.InnerException;
        }
        if (chain.Count == 0) chain.Add(ex);

        foreach (var e in chain)
        {
            if (e is System.Net.Sockets.SocketException se)
            {
                switch (se.SocketErrorCode)
                {
                    case System.Net.Sockets.SocketError.HostNotFound:
                    case System.Net.Sockets.SocketError.TryAgain:
                    case System.Net.Sockets.SocketError.NoData:
                        return ("DNS_FAIL", "hostname did not resolve: " + e.Message);
                    case System.Net.Sockets.SocketError.ConnectionRefused:
                    case System.Net.Sockets.SocketError.AccessDenied:
                    case System.Net.Sockets.SocketError.HostUnreachable:
                    case System.Net.Sockets.SocketError.NetworkUnreachable:
                        return ("CONNECT_REFUSED", "connection refused -- port 443 likely blocked by firewall: " + e.Message);
                    case System.Net.Sockets.SocketError.TimedOut:
                        return ("CONNECT_TIMEOUT", "connection timed out -- port 443 likely blocked/dropped by firewall: " + e.Message);
                    case System.Net.Sockets.SocketError.ConnectionReset:
                    case System.Net.Sockets.SocketError.ConnectionAborted:
                        return ("CONNECTION_CLOSED", "connection was established then closed unexpectedly before completing: " + e.Message);
                }
            }
            if (e is System.Security.Authentication.AuthenticationException)
            {
                return ("TLS_HANDSHAKE_FAIL", "certificate not trusted: " + e.Message);
            }
            if (e is TimeoutException)
            {
                return ("CONNECT_TIMEOUT", "connection timed out -- port 443 likely blocked/dropped by firewall: " + e.Message);
            }
            if (e is OperationCanceledException)
            {
                return ("CONNECT_TIMEOUT", "connection timed out -- port 443 likely blocked/dropped by firewall: " + e.Message);
            }
        }

        var text = string.Join(" | ", chain.ConvertAll(e => e.Message)).ToLowerInvariant();
        if (text.Contains("timed out") || text.Contains("timeout"))
            return ("CONNECT_TIMEOUT", "connection timed out -- port 443 likely blocked/dropped by firewall: " + chain[0].Message);
        if (text.Contains("refused") || text.Contains("actively refused") || text.Contains("forbidden by its access permissions"))
            return ("CONNECT_REFUSED", "connection refused -- port 443 likely blocked by firewall: " + chain[0].Message);
        if (text.Contains("no such host") || text.Contains("name or service not known") || text.Contains("getaddrinfo") || text.Contains("nodename nor servname"))
            return ("DNS_FAIL", "hostname did not resolve: " + chain[0].Message);
        if (text.Contains("cert") || text.Contains("ssl") || text.Contains("tls") || text.Contains("handshake"))
            return ("TLS_HANDSHAKE_FAIL", "TLS handshake failed: " + chain[0].Message);
        if (text.Contains("closed") || text.Contains("reset by peer") || text.Contains("connection reset"))
            return ("CONNECTION_CLOSED", "connection was established then closed unexpectedly before completing: " + chain[0].Message);
        return ("CONNECT_REFUSED", "connection failed: " + chain[0].Message);
    }

    // ---- trust context (tier-1 native probe) ----
    //
    // Deliberately mirrors the REAL SDK's own TlsHelper.BuildHandler logic
    // (verified against Camunda.Orchestration.Sdk 9.1.3 source,
    // src/Camunda.Orchestration.Sdk/Runtime/TlsHelper.cs), not just its
    // *semantics* -- see ValidateWithCustomCa below. This is the "false-green
    // principle": tier 1 must exercise the SAME trust decision the SDK
    // exercises for the SAME env var, or it's worthless as a proxy for "does
    // the SDK trust this."
    //
    // CRITICAL FINDING, verified against source (NOT assumed from the
    // general ".NET also trusts the OS store" claim, which by itself says
    // nothing about what happens once a custom CA is ALSO configured):
    //
    // The real SDK's ServerCertificateCustomValidationCallback (1) returns
    // true immediately if the DEFAULT OS-store validation already succeeded
    // (sslPolicyErrors == None) -- so any host the OS store already trusts
    // keeps working; (2) only when the OS store validation FAILED, and only
    // for chain-trust errors specifically (not e.g. a hostname mismatch), does
    // it fall back to building a fresh chain trusting ONLY the custom CA
    // collection (X509ChainTrustMode.CustomRootTrust). Net effect: a host is
    // trusted if EITHER the OS store trusts it OR the custom CA trusts it --
    // functionally APPEND semantics (any endpoint covered by either store
    // passes), the OPPOSITE of Java's and TypeScript's real "replace the
    // whole trust store" behavior, and matching Go's/Python's append
    // precedent instead. This is a genuine correction to the ambiguous
    // general claim, verified from source.
    //
    // Also verified: a missing/unreadable custom CA file throws
    // FileNotFoundException at TlsHelper.ReadPath -- a LOUD failure at
    // CamundaClient.Create() time, the OPPOSITE of Java's silent
    // javax.net.ssl.trustStore-missing-file footgun (RUNBOOK). This probe
    // mirrors that by WARNing (not silently falling back) when the file is
    // missing, so the same misconfiguration is visible in tier 1 too, before
    // tier 2 ever throws.

    public sealed class TrustContext
    {
        public X509Certificate2Collection? CustomCa;
        public string Label = "the OS certificate store";
        public string? Warning;
    }

    public static TrustContext BuildTrustContext(string configTarget)
    {
        var customCaPath = (Environment.GetEnvironmentVariable("CAMUNDA_MTLS_CA_PATH") ?? "").Trim();
        if (string.IsNullOrEmpty(customCaPath))
            return new TrustContext();

        if (!File.Exists(customCaPath))
        {
            return new TrustContext
            {
                Label = "the OS certificate store (your custom certificate path is unreadable -- NOT applied)",
                Warning = EmitFragment(
                    configTarget,
                    "WARN",
                    "CONFIG_ERROR",
                    $"CAMUNDA_MTLS_CA_PATH is set to {customCaPath}, but that file does not exist -- proceeding " +
                    "WITHOUT the custom CA. (The real SDK would throw a FileNotFoundException at " +
                    "CamundaClient.Create() time for this exact case -- this probe WARNs instead so both hosts " +
                    "still get checked against the default trust store.)"),
            };
        }

        try
        {
            var certs = new X509Certificate2Collection();
            certs.ImportFromPemFile(customCaPath);
            return new TrustContext
            {
                CustomCa = certs,
                Label = $"the OS certificate store, plus your custom certificate ({customCaPath})",
            };
        }
        catch (Exception e)
        {
            return new TrustContext
            {
                Label = "the OS certificate store (your custom certificate could not be parsed -- NOT applied)",
                Warning = EmitFragment(
                    configTarget,
                    "WARN",
                    "CONFIG_ERROR",
                    $"CAMUNDA_MTLS_CA_PATH is set to {customCaPath}, but it could not be parsed as a PEM bundle " +
                    $"({e.Message}) -- proceeding WITHOUT the custom CA."),
            };
        }
    }

    /// <summary>
    /// The exact validation logic the real SDK's TlsHelper.BuildHandler uses
    /// (ported, not reimplemented from a description) -- see the TrustContext
    /// doc comment above for the verified append-semantics finding this
    /// produces.
    /// </summary>
    public static bool ValidateWithCustomCa(
        X509Certificate2Collection caCerts,
        X509Certificate2? cert,
        X509Chain? chain,
        System.Net.Security.SslPolicyErrors errors)
    {
        if (errors == System.Net.Security.SslPolicyErrors.None)
            return true;

        // Only override chain trust errors. Hostname mismatch or
        // cert-not-available must still fail to preserve TLS security --
        // ported verbatim from the real SDK's TlsHelper.cs.
        if ((errors & ~System.Net.Security.SslPolicyErrors.RemoteCertificateChainErrors) != 0)
            return false;

        if (cert == null || chain == null)
            return false;

        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Clear();
        chain.ChainPolicy.CustomTrustStore.AddRange(caCerts);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        return chain.Build(cert);
    }
}
