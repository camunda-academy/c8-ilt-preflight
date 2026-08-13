// Layer 2 native trust probe -- C#/.NET, tier 1.
//
// Standalone: dotnet build Probe.csproj -c Release -o out && dotnet out/Probe.dll
// (or just run preflight/layer2/csharp/run.sh / run.cmd, which do exactly
// this). No Camunda SDK required -- System.Net.Sockets/Security/Security.
// Cryptography.X509Certificates only, all part of the .NET base class
// library, not a NuGet dependency.
//
// Env vars:
//   CAMUNDA_REST_ADDRESS   full cluster REST URL (wins over CAMUNDA_REGION)
//   CAMUNDA_REGION         region slug, default bru-2
//   CAMUNDA_MTLS_CA_PATH   extra CA PEM -- the SAME env var name the real
//       Camunda.Orchestration.Sdk itself reads (verified in its own README +
//       ConfigurationHydrator.cs source). Unlike Java (whose real client
//       reads a DIFFERENT name, CAMUNDA_CA_CERTIFICATE_PATH, and needed its
//       own cross-name mismatch WARN), there is no name trap here -- same as
//       TypeScript.
//   HTTPS_PROXY / HTTP_PROXY (or lowercase)   explicit proxy, CONNECT-tunneled
//
// Emits one JSON fragment per line on stdout, per target, per the
// cross-runtime probe contract:
//   {runtime, trustStoreExercised, target, verdict, errorClass, detail}
//
// ---------------------------------------------------------------------------
// CRITICAL, verified against the real SDK's own source (Camunda.Orchestration.
// Sdk 9.2.0, src/Camunda.Orchestration.Sdk/Runtime/TlsHelper.cs) - what
// happens once a custom CA is ALSO configured, which ".NET trusts the OS
// store" by itself does not answer:
//
// The real SDK's ServerCertificateCustomValidationCallback (1) returns true
// immediately if the default OS-store validation already succeeded, and (2)
// only when that failed -- and only for chain-trust errors specifically --
// falls back to a chain built with ONLY the custom CA
// (X509ChainTrustMode.CustomRootTrust). Net effect: a host is trusted if
// EITHER the OS store trusts it OR the custom CA trusts it -- this is
// functionally APPEND semantics, the OPPOSITE of Java's and TypeScript's real
// "replace the whole trust store" behavior for their SDKs, and matching Go's/
// Python's append precedent instead. Shared.ValidateWithCustomCa (see
// Shared.cs) ports this exact logic (not a re-derived equivalent), so this
// probe's SslStream.RemoteCertificateValidationCallback below faithfully
// mirrors what CamundaClient actually trusts for the same CAMUNDA_MTLS_CA_PATH
// value -- the whole point of keeping tier-1 and tier-2 trust-store behavior
// consistent.
// ---------------------------------------------------------------------------

using System.Diagnostics;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CamundaPreflight;

const int ConnectTimeoutMs = 10_000;
const string OauthHost = "login.cloud.camunda.io";

const string Usage = "Layer 2 native trust probe -- C#/.NET.\n" +
    "Standalone: dotnet build Probe.csproj -c Release -o out && dotnet out/Probe.dll\n" +
    "Targets whichever .NET major the installed SDK provides; override with -p:TargetFramework=netX.0.\n" +
    "Supported env vars are listed in this probe's source header.";

if (Array.IndexOf(args, "-h") >= 0 || Array.IndexOf(args, "--help") >= 0)
{
    Console.Error.WriteLine(Usage);
    return 0;
}

try
{
    return await RunAsync();
}
catch (Exception ex)
{
    // Last-resort: never let an unhandled exception produce a bare stack
    // trace on stdout that the launcher can't parse -- emit a proper
    // probe-error fragment instead, per the cross-runtime probe contract.
    Console.WriteLine(Shared.CrashFragment(ex.ToString()));
    return 1;
}

async Task<int> RunAsync()
{
    var apiHost = Shared.ResolveApiHost();
    var configTarget = apiHost + " (config)";
    var trust = Shared.BuildTrustContext(configTarget);
    if (trust.Warning != null)
        Console.WriteLine(trust.Warning);

    var proxyUrl = Shared.GetProxyUrl();
    if (proxyUrl != null)
        Console.Error.WriteLine("[csharp probe] using proxy: " + Shared.MaskProxy(proxyUrl));
    Console.Error.WriteLine("[csharp probe] trust store: " + trust.Label);

    var exitCode = 0;
    foreach (var host in new[] { apiHost, OauthHost })
    {
        var frag = await ProbeTargetAsync(host, 443, trust, proxyUrl);
        Console.WriteLine(frag);
        if (!(frag.Contains("\"verdict\":\"PASS\"") || frag.Contains("\"verdict\":\"WARN\"") || frag.Contains("\"verdict\":\"SKIP\"")))
            exitCode = 1;
    }
    return exitCode;
}

async Task<string> ProbeTargetAsync(string host, int port, Shared.TrustContext trust, string? proxyUrl)
{
    var target = $"{host}:{port}";
    var sw = Stopwatch.StartNew();

    Stream rawStream;
    TcpClient tcp;
    try
    {
        (rawStream, tcp) = proxyUrl != null
            ? await ConnectViaProxyAsync(proxyUrl, host, port)
            : await ConnectPlainAsync(host, port);
    }
    catch (ProxyException pe)
    {
        if (pe.StatusLine.Contains("407"))
        {
            return Shared.EmitFragment(
                target,
                "FAIL",
                "PROXY_AUTH_407",
                "authenticated corporate proxy in path -- supply credentials in the proxy URL " +
                "(Basic auth only; export HTTPS_PROXY=http://user:pass@<proxy>:<port>) " +
                "or ask IT to exempt these hosts. Proxy response: " + pe.StatusLine);
        }
        return Shared.EmitFragment(target, "FAIL", "CONNECT_REFUSED", "proxy CONNECT tunnel failed: " + pe.StatusLine);
    }
    catch (Exception e)
    {
        var (errorClass, detail) = Shared.ClassifyTransportError(e);
        return Shared.EmitFragment(target, "FAIL", errorClass, detail);
    }

    using (tcp)
    {
        SslStream? ssl = null;
        try
        {
            ssl = new SslStream(rawStream, leaveInnerStreamOpen: false, (_, cert, chain, errors) =>
            {
                if (trust.CustomCa == null)
                    return errors == SslPolicyErrors.None;
                var cert2 = cert != null ? new X509Certificate2(cert) : null;
                return Shared.ValidateWithCustomCa(trust.CustomCa, cert2, chain, errors);
            });

            using var cts = new CancellationTokenSource(ConnectTimeoutMs);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = host }, cts.Token);

            var elapsedMs = sw.ElapsedMilliseconds;
            return Shared.EmitFragment(target, "PASS", "OK", $"TLS handshake succeeded ({elapsedMs}ms)", trust.Label);
        }
        catch (Exception e)
        {
            var (errorClass, detail) = Shared.ClassifyTransportError(e);
            if (errorClass == "TLS_HANDSHAKE_FAIL")
            {
                return Shared.EmitFragment(
                    target,
                    "FAIL",
                    "TLS_HANDSHAKE_FAIL",
                    $"certificate not trusted by {trust.Label}: {e.Message} -- likely a TLS-intercepting proxy; " +
                    "import its root CA via CAMUNDA_MTLS_CA_PATH",
                    trust.Label);
            }
            return Shared.EmitFragment(target, "FAIL", errorClass, detail, trust.Label);
        }
        finally
        {
            ssl?.Dispose();
        }
    }
}

async Task<(Stream Stream, TcpClient Tcp)> ConnectPlainAsync(string host, int port)
{
    var tcp = new TcpClient();
    try
    {
        using var cts = new CancellationTokenSource(ConnectTimeoutMs);
        await tcp.ConnectAsync(host, port, cts.Token);
    }
    catch (OperationCanceledException)
    {
        tcp.Dispose();
        throw new SocketException((int)SocketError.TimedOut);
    }
    catch
    {
        tcp.Dispose();
        throw;
    }
    return (tcp.GetStream(), tcp);
}

/// <summary>
/// Opens an HTTP CONNECT tunnel through proxyUrl to host:port -- mirrors
/// probe.py's connect_via_proxy / Shared.java's connectViaProxy / _shared.js's
/// connectViaProxy: raw socket, manual CONNECT handshake, Basic proxy-auth
/// from the URL's userinfo, upgrading to TLS only after the tunnel is
/// established. Raw sockets never auto-tunnel through env-var proxies (only
/// higher-level HTTP clients do), so this manual tunnel is the only way this
/// probe's proxy support works at all.
/// </summary>
async Task<(Stream Stream, TcpClient Tcp)> ConnectViaProxyAsync(string proxyUrl, string host, int port)
{
    var proxy = new Uri(proxyUrl);
    var (rawStream, tcp) = await ConnectPlainAsync(proxy.Host, proxy.Port);

    Stream stream = rawStream;
    if (proxy.Scheme == "https")
    {
        var proxyTls = new SslStream(rawStream, leaveInnerStreamOpen: false);
        await proxyTls.AuthenticateAsClientAsync(proxy.Host);
        stream = proxyTls;
    }

    var sb = new StringBuilder();
    sb.Append($"CONNECT {host}:{port} HTTP/1.1\r\n");
    sb.Append($"Host: {host}:{port}\r\n");
    var userInfo = proxy.UserInfo;
    if (!string.IsNullOrEmpty(userInfo))
    {
        var parts = userInfo.Split(':', 2);
        var user = Uri.UnescapeDataString(parts[0]);
        var pass = parts.Length > 1 ? Uri.UnescapeDataString(parts[1]) : "";
        var cred = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{user}:{pass}"));
        sb.Append($"Proxy-Authorization: Basic {cred}\r\n");
    }
    sb.Append("\r\n");

    var reqBytes = Encoding.UTF8.GetBytes(sb.ToString());
    using (var cts = new CancellationTokenSource(ConnectTimeoutMs))
    {
        await stream.WriteAsync(reqBytes, cts.Token);
        await stream.FlushAsync(cts.Token);
    }

    string statusLine;
    using (var cts = new CancellationTokenSource(ConnectTimeoutMs))
    {
        statusLine = await ReadStatusLineAsync(stream, cts.Token);
    }
    if (!statusLine.Contains(" 200"))
    {
        tcp.Dispose();
        throw new ProxyException(string.IsNullOrEmpty(statusLine) ? "no response from proxy" : statusLine);
    }
    return (stream, tcp);
}

/// <summary>
/// Reads bytes up to and including the first CRLFCRLF, and returns just the
/// status line (first line) -- enough to check the CONNECT response code
/// without pulling in an HTTP client dependency. Mirrors Shared.java's
/// readStatusLine.
/// </summary>
async Task<string> ReadStatusLineAsync(Stream stream, CancellationToken ct)
{
    var buf = new List<byte>();
    var single = new byte[1];
    var matched = 0;
    while (true)
    {
        var n = await stream.ReadAsync(single.AsMemory(0, 1), ct);
        if (n == 0) break;
        var b = single[0];
        buf.Add(b);
        if (matched == 0 && b == (byte)'\r') matched = 1;
        else if (matched == 1 && b == (byte)'\n') matched = 2;
        else if (matched == 2 && b == (byte)'\r') matched = 3;
        else if (matched == 3 && b == (byte)'\n') break;
        else matched = b == (byte)'\r' ? 1 : 0;
    }
    var all = Encoding.Latin1.GetString(buf.ToArray());
    var idx = all.IndexOf("\r\n", StringComparison.Ordinal);
    return idx >= 0 ? all[..idx] : all;
}

/// <summary>Raised when the CONNECT tunnel itself fails (bad status line).</summary>
sealed class ProxyException(string statusLine) : Exception(statusLine)
{
    public string StatusLine { get; } = statusLine;
}
