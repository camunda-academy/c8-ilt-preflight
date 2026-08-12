import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.Collection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

/**
 * Layer 2 native trust probe -- Java.
 *
 * Standalone: javac Probe.java Shared.java &amp;&amp; java Probe
 * (no Camunda SDK required -- javax.net.ssl only. The real camunda-client-java
 * SDK requires JDK 17+; this native probe only needs javax.net.ssl, which has
 * been stable since early JDKs, but the training cohort's JDK 17+ requirement
 * applies regardless since they'll need it for the SDK anyway.)
 *
 * Env vars:
 *   CAMUNDA_REST_ADDRESS         full cluster REST URL (wins over CAMUNDA_REGION)
 *   CAMUNDA_REGION               region slug, default bru-2
 *   CAMUNDA_CA_CERTIFICATE_PATH  extra CA PEM -- the REAL env var name the Java
 *       SDK reads (verified against camunda-client-java 8.9.11 source,
 *       CamundaClientEnvironmentVariables.CA_CERTIFICATE_VAR). This is
 *       DELIBERATELY NOT the same name as CAMUNDA_MTLS_CA_PATH used by the
 *       Go/Python/TypeScript probes -- if a customer sets CAMUNDA_MTLS_CA_PATH
 *       instead (the natural mistake after reading the rest of this tool's
 *       docs), the real Java client silently ignores it. This probe detects
 *       that exact mismatch and WARNs about it (see buildTrustContext()).
 *   CAMUNDA_JAVA_TRUSTSTORE      path to a JKS/PKCS12 truststore file, applied
 *       as -Djavax.net.ssl.trustStore before any SSL work (this tool's own
 *       --java-truststore flag). Lets an operator hand the JVM a merged
 *       cacerts-copy-plus-corporate-CA file -- appends, unlike
 *       CAMUNDA_CA_CERTIFICATE_PATH, which replaces. Ignored (with a WARN) if
 *       CAMUNDA_CA_CERTIFICATE_PATH is also set -- that code path never
 *       consults this property.
 *   CAMUNDA_JAVA_TRUSTSTORE_PASSWORD  password for the above, if any
 *   HTTPS_PROXY / HTTP_PROXY (or lowercase)  explicit proxy, CONNECT-tunneled
 *
 * Emits one JSON fragment per line on stdout, per target, per the
 * cross-runtime probe contract shared by every language's probe in this
 * project:
 *   {runtime, trustStoreExercised, target, verdict, errorClass, detail}
 *
 * Trust-store behavior, verified against camunda-client-java 8.9.11 source
 * (io.camunda.client.impl.http.HttpClientFactory.createSslContext /
 * createKeyStore), NOT assumed:
 *
 *  - With no custom CA path set, the real client's REST transport (Apache
 *    HttpClient 5) uses SSLContexts.createDefault() -- the JVM's own default
 *    trust store (cacerts) -- the SAME store this probe's SSLContext.getDefault()
 *    uses. Unlike Python (certifi vs the stdlib default's OS store), Java's
 *    native probe and the real SDK already agree on the default -- no special
 *    import trick is needed to match this case.
 *
 *  - Once a custom CA path IS set, the real client's trust store logic
 *    REPLACES cacerts entirely with a fresh, otherwise-empty KeyStore
 *    containing ONLY the certs parsed from that one PEM file (see
 *    createKeyStore: KeyStore.getInstance(...); store.load(null); then only
 *    the PEM's certs are added -- cacerts is never consulted again). This is
 *    the OPPOSITE of Go's BuildRootPool (appends to the system pool) and
 *    Python's certifi-plus-custom-CA approach. This probe's custom-CA path
 *    REPLACES too, to faithfully mirror what the real SDK will actually
 *    trust -- a probe that merely appended (like Go/Python do) would risk a
 *    false PASS in exactly the scenario where the real client, having
 *    discarded the public CAs, fails to trust some other public endpoint
 *    (e.g. the OAuth host, if it's not behind the same interception point).
 */
public final class Probe {
  private static final int CONNECT_TIMEOUT_MS = 10_000;
  private static final String OAUTH_HOST = "login.cloud.camunda.io";

  private static final String USAGE =
      "Layer 2 native trust probe -- Java.\n"
          + "Standalone: javac Probe.java Shared.java && java Probe\n"
          + "See the RUNBOOK's Java section for env vars and the\n"
          + "CAMUNDA_CA_CERTIFICATE_PATH vs CAMUNDA_MTLS_CA_PATH distinction.";

  public static void main(String[] args) {
    for (String a : args) {
      if (a.equals("-h") || a.equals("--help")) {
        System.err.println(USAGE);
        return;
      }
    }

    try {
      System.exit(run());
    } catch (Throwable t) {
      // Last-resort: never let an unhandled exception produce a bare
      // traceback on stdout that the launcher can't parse -- emit a proper
      // probe-error fragment instead, in the same schema every probe in this
      // project uses.
      System.out.println(Shared.crashFragment(String.valueOf(t)));
      System.exit(1);
    }
  }

  private static int run() throws Exception {
    // Must happen before buildTrustContext()/any SSLContext.getDefault() call
    // in this process -- see Shared.applyJavaTrustStoreSystemProperty().
    String trustStoreWarning = Shared.applyJavaTrustStoreSystemProperty(apiHostConfigTarget());
    if (trustStoreWarning != null) {
      System.out.println(trustStoreWarning);
    }

    TrustContext trust = buildTrustContext();
    if (trust.configWarning != null) {
      System.out.println(trust.configWarning);
    }

    String proxyUrl = Shared.getProxyUrl();
    if (proxyUrl != null) {
      System.err.println("[java probe] using proxy: " + Shared.scrubUrlCreds(proxyUrl));
    }
    System.err.println("[java probe] trust store: " + trust.label);

    String apiHost = Shared.resolveApiHost();
    String[] hosts = {apiHost, OAUTH_HOST};

    int exitCode = 0;
    for (String host : hosts) {
      String fragment = probeTarget(host, 443, trust, proxyUrl);
      System.out.println(fragment);
      System.out.flush();
      if (!(fragment.contains("\"verdict\":\"PASS\"")
          || fragment.contains("\"verdict\":\"WARN\"")
          || fragment.contains("\"verdict\":\"SKIP\""))) {
        exitCode = 1;
      }
    }
    return exitCode;
  }

  /** Bundles the constructed SSLContext with a human-readable label of which
   * trust store it exercises, plus an optional WARN fragment (already fully
   * formed) to emit first if a config mismatch was detected. */
  private static final class TrustContext {
    final SSLContext sslContext;
    final String label;
    final String configWarning;

    TrustContext(SSLContext sslContext, String label, String configWarning) {
      this.sslContext = sslContext;
      this.label = label;
      this.configWarning = configWarning;
    }
  }

  private static TrustContext buildTrustContext() throws Exception {
    String caPath = Shared.envOrEmpty("CAMUNDA_CA_CERTIFICATE_PATH");
    String wrongNameCaPath = Shared.envOrEmpty("CAMUNDA_MTLS_CA_PATH");

    String configWarning = null;
    if (caPath.isEmpty() && !wrongNameCaPath.isEmpty()) {
      // The exact trap this probe exists to catch: a customer who read the
      // Go/Python/TypeScript sections of the RUNBOOK sets CAMUNDA_MTLS_CA_PATH,
      // which the real Java client does not read at all -- it stays on cacerts
      // and keeps failing behind an intercepting proxy, looking like the fix
      // "didn't work" when really the wrong env var name was used.
      configWarning =
          Shared.fragment(
              apiHostConfigTarget(),
              "WARN",
              "CONFIG_ERROR",
              "CAMUNDA_MTLS_CA_PATH is set, but Java needs a different variable name: "
                  + "CAMUNDA_CA_CERTIFICATE_PATH. Your custom certificate will NOT be applied until you set "
                  + "CAMUNDA_CA_CERTIFICATE_PATH to the same path.");
    } else if (!caPath.isEmpty()) {
      configWarning = Shared.javaTrustStoreIgnoredWarning(apiHostConfigTarget(), caPath);
    }

    if (caPath.isEmpty()) {
      return new TrustContext(SSLContext.getDefault(), Shared.defaultTrustLabel(), configWarning);
    }

    // REPLACE, not append -- see the class-level doc comment. Build a fresh
    // KeyStore containing ONLY the certs from this one PEM file, exactly
    // mirroring HttpClientFactory.createKeyStore in the real SDK.
    KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null, null);
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    try (InputStream in = java.nio.file.Files.newInputStream(java.nio.file.Paths.get(caPath))) {
      Collection<? extends Certificate> certs = cf.generateCertificates(in);
      int i = 1;
      for (Certificate cert : certs) {
        keyStore.setCertificateEntry(Integer.toString(i), cert);
        i++;
      }
    }
    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init(keyStore);
    SSLContext ctx = SSLContext.getInstance("TLS");
    ctx.init(null, tmf.getTrustManagers(), null);

    // Kept short and plain-language -- this ends up in the customer-facing
    // result (Notes/FAIL details), not just an engineering log. The
    // replace-vs-append nuance is documented in RUNBOOK.md for trainers.
    String label = "your custom certificate (" + caPath + ")";
    return new TrustContext(ctx, label, configWarning);
  }

  private static String apiHostConfigTarget() {
    return Shared.resolveApiHost() + " (config)";
  }

  /** Raised when the CONNECT tunnel itself fails (bad status line). */
  private static final class ProxyException extends IOException {
    final String statusLine;

    ProxyException(String statusLine) {
      super(statusLine);
      this.statusLine = statusLine;
    }
  }

  private static String probeTarget(String host, int port, TrustContext trust, String proxyUrl) {
    long start = System.currentTimeMillis();
    String target = host + ":" + port;

    Socket rawSocket;
    try {
      rawSocket = (proxyUrl != null) ? connectViaProxy(proxyUrl, host, port) : plainConnect(host, port);
    } catch (ProxyException e) {
      if (e.statusLine != null && e.statusLine.contains("407")) {
        return Shared.fragment(
            target,
            "FAIL",
            "PROXY_AUTH_407",
            "authenticated corporate proxy in path -- supply credentials in the proxy URL "
                + "(Basic auth only; export HTTPS_PROXY=http://user:pass@<proxy>:<port>) "
                + "or ask IT to exempt these hosts. Proxy response: "
                + e.statusLine);
      }
      return Shared.fragment(
          target, "FAIL", "CONNECT_REFUSED", "proxy CONNECT tunnel failed: " + e.statusLine);
    } catch (Exception e) {
      String[] classified = Shared.classifyTransportError(e);
      return Shared.fragment(target, "FAIL", classified[0], classified[1]);
    }

    try (Socket socket = rawSocket) {
      SSLSocketFactory factory = trust.sslContext.getSocketFactory();
      try (SSLSocket tlsSocket = (SSLSocket) factory.createSocket(socket, host, port, true)) {
        tlsSocket.startHandshake();
        long elapsedMs = System.currentTimeMillis() - start;
        return Shared.fragment(
            target,
            "PASS",
            "OK",
            "TLS handshake succeeded (" + elapsedMs + "ms)",
            trust.label);
      } catch (javax.net.ssl.SSLHandshakeException e) {
        String[] classified = Shared.classifyTransportError(e);
        String errorClass = classified[0];
        String detail =
            errorClass.equals("TLS_HANDSHAKE_FAIL") && classified[1].startsWith("certificate not trusted")
                ? "certificate not trusted by "
                    + trust.label
                    + ": "
                    + e
                    + " -- likely a TLS-intercepting proxy; import its root CA via "
                    + "CAMUNDA_CA_CERTIFICATE_PATH (see RUNBOOK)"
                : classified[1];
        return Shared.fragment(target, "FAIL", errorClass, detail, trust.label);
      }
    } catch (Exception e) {
      String[] classified = Shared.classifyTransportError(e);
      return Shared.fragment(target, "FAIL", classified[0], classified[1], trust.label);
    }
  }

  private static Socket plainConnect(String host, int port) throws IOException {
    Socket socket = new Socket();
    socket.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MS);
    return socket;
  }

  /** Opens an HTTP CONNECT tunnel through proxyUrl to host:port, mirroring
   * probe.py's connect_via_proxy -- same behavior/precedent across every
   * native probe in this project (Go, Python, Java). */
  private static Socket connectViaProxy(String proxyUrl, String host, int port) throws Exception {
    URI proxy = new URI(proxyUrl);
    String proxyHost = proxy.getHost();
    int proxyPort = proxy.getPort() != -1 ? proxy.getPort() : ("https".equals(proxy.getScheme()) ? 443 : 80);

    Socket socket = new Socket();
    socket.connect(new InetSocketAddress(proxyHost, proxyPort), CONNECT_TIMEOUT_MS);
    if ("https".equals(proxy.getScheme())) {
      SSLSocketFactory f = (SSLSocketFactory) SSLSocketFactory.getDefault();
      socket = f.createSocket(socket, proxyHost, proxyPort, true);
    }

    StringBuilder req = new StringBuilder();
    req.append("CONNECT ").append(host).append(':').append(port).append(" HTTP/1.1\r\n");
    req.append("Host: ").append(host).append(':').append(port).append("\r\n");
    String userInfo = proxy.getUserInfo();
    if (userInfo != null && !userInfo.isEmpty()) {
      String cred = Base64.getEncoder().encodeToString(userInfo.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      req.append("Proxy-Authorization: Basic ").append(cred).append("\r\n");
    }
    req.append("\r\n");

    OutputStream out = socket.getOutputStream();
    out.write(req.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
    out.flush();

    socket.setSoTimeout(CONNECT_TIMEOUT_MS);
    String statusLine = readStatusLine(socket.getInputStream());
    if (!statusLine.contains(" 200")) {
      socket.close();
      throw new ProxyException(statusLine.isEmpty() ? "no response from proxy" : statusLine);
    }
    socket.setSoTimeout(0);
    return socket;
  }

  /** Reads bytes up to and including the first CRLFCRLF, and returns just the
   * status line (first line) -- enough to check the CONNECT response code
   * without pulling in an HTTP client dependency. Any bytes after the header
   * terminator are NOT consumed here; for a normal HTTPS CONNECT the client
   * (this probe) speaks first (ClientHello), so a well-behaved proxy sends
   * nothing more until then. */
  private static String readStatusLine(InputStream in) throws IOException {
    ByteArrayOutputStream buf = new ByteArrayOutputStream();
    int matched = 0;
    int b;
    while ((b = in.read()) != -1) {
      buf.write(b);
      if (matched == 0 && b == '\r') {
        matched = 1;
      } else if (matched == 1 && b == '\n') {
        matched = 2;
      } else if (matched == 2 && b == '\r') {
        matched = 3;
      } else if (matched == 3 && b == '\n') {
        break;
      } else {
        matched = (b == '\r') ? 1 : 0;
      }
    }
    String all = buf.toString(java.nio.charset.StandardCharsets.ISO_8859_1);
    int idx = all.indexOf("\r\n");
    return idx >= 0 ? all.substring(0, idx) : all;
  }
}
