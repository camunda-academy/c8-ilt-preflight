import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Shared helpers for the Java Layer 2 probes (Probe.java, future SdkProbe.java).
 *
 * Mirrors preflight/layer2/python/_shared.py's structure and division of
 * labor -- centralized so probes never carry two independently-drifting
 * copies of the same fragment-emission / classification / redaction logic --
 * one shared vocabulary across every language.
 *
 * Java's single-file source-launch (`java Probe.java`) does NOT resolve a
 * sibling top-level class the way Python's `import _shared` resolves a
 * sibling module -- `java Main.java` fails to find a class
 * defined only in a sibling Shared.java. So these Java probes are compiled
 * explicitly (`javac Probe.java Shared.java && java Probe`) rather than
 * launched via the single-file convention. Still zero third-party build
 * tooling -- javac ships with any JDK -- just an explicit compile step
 * run.sh/run.cmd perform instead of a bare `java Probe.java`.
 */
final class Shared {
  private Shared() {}

  static final String RUNTIME = "java";

  private static final Pattern URL_CREDS = Pattern.compile("(\\w+://)[^/@\\s:]+:[^/@\\s]+@");

  // ---- fragment / JSON (no JSON library required -- hand-built + escaped,
  // matching the "no JSON library required" contract every native probe in
  // this project follows) ----

  static String fragment(String target, String verdict, String errorClass, String detail) {
    return fragment(target, verdict, errorClass, detail, "");
  }

  static String fragment(
      String target, String verdict, String errorClass, String detail, String trustStore) {
    // Scrub URL credentials from the detail as a universal backstop -- every
    // emitted fragment funnels through here, so a proxy password embedded in
    // an exception string can't leak to stdout regardless of which code path
    // built the detail (mirrors the Python probes' fragment()).
    String scrubbedDetail = scrubUrlCreds(detail);
    StringBuilder sb = new StringBuilder();
    sb.append('{');
    jsonField(sb, "runtime", RUNTIME, true);
    jsonField(sb, "trustStoreExercised", trustStore, false);
    jsonField(sb, "target", target, false);
    jsonField(sb, "verdict", verdict, false);
    jsonField(sb, "errorClass", errorClass, false);
    jsonField(sb, "detail", scrubbedDetail, false);
    sb.append('}');
    return sb.toString();
  }

  private static void jsonField(StringBuilder sb, String key, String value, boolean first) {
    if (!first) {
      sb.append(',');
    }
    sb.append('"').append(key).append("\":\"").append(jsonEscape(value)).append('"');
  }

  static String jsonEscape(String s) {
    if (s == null) {
      return "";
    }
    StringBuilder out = new StringBuilder(s.length() + 16);
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch (c) {
        case '"':
          out.append("\\\"");
          break;
        case '\\':
          out.append("\\\\");
          break;
        case '\n':
          out.append("\\n");
          break;
        case '\r':
          out.append("\\r");
          break;
        case '\t':
          out.append("\\t");
          break;
        default:
          if (c < 0x20) {
            out.append(String.format("\\u%04x", (int) c));
          } else {
            out.append(c);
          }
      }
    }
    return out.toString();
  }

  static String crashFragment(String detail) {
    return fragment("", "probe-error", "PROBE_CRASHED", "probe crashed: " + detail);
  }

  /**
   * Renders a Throwable as its whole cause chain, not just its own message.
   *
   * <p>A crash fragment is often the only thing that survives a field run, and
   * the top-level exception is regularly the least informative link in the
   * chain: a gRPC/netty startup failure reports "failed to create a child event
   * loop" while the fact worth having ("Unable to establish loopback
   * connection", then the socket error under it) sits two or three causes down.
   * Reporting only the outermost message turns a diagnosable environment
   * problem into an opaque "probe crashed", and the participant can't be asked
   * to re-run with a debugger attached.
   *
   * <p>Depth is capped because cause chains can be self-referential, and the
   * result is one single-line string so it stays inside a JSON fragment.
   */
  static String describeThrowable(Throwable t) {
    if (t == null) {
      return "unknown error";
    }
    StringBuilder sb = new StringBuilder(String.valueOf(t));
    Throwable cause = t.getCause();
    for (int depth = 0; cause != null && depth < 5; depth++) {
      sb.append(" <- caused by: ").append(cause);
      if (cause == cause.getCause()) {
        break;
      }
      cause = cause.getCause();
    }
    return sb.toString();
  }

  // ---- proxy ----

  static String getProxyUrl() {
    for (String name : new String[] {"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"}) {
      String v = System.getenv(name);
      if (v != null && !v.isEmpty()) {
        return v;
      }
    }
    return null;
  }

  /** Mask user:pass@ credentials in any URL embedded in text -- applied to every
   * fragment detail before emission (mirrors _shared.py's scrub_url_creds). */
  static String scrubUrlCreds(String text) {
    if (text == null || text.isEmpty()) {
      return text;
    }
    Matcher m = URL_CREDS.matcher(text);
    return m.replaceAll("$1****:****@");
  }

  // ---- host resolution ----

  /** Same config-source precedence as the Go binary and the Python probes: an
   * explicit CAMUNDA_REST_ADDRESS host wins over CAMUNDA_REGION. */
  static String resolveApiHost() {
    String restAddress = envOrEmpty("CAMUNDA_REST_ADDRESS");
    String region = envOrDefault("CAMUNDA_REGION", "bru-2");
    if (!restAddress.isEmpty()) {
      String candidate = restAddress.contains("://") ? restAddress : "https://" + restAddress;
      try {
        URI u = new URI(candidate);
        if (u.getHost() != null) {
          return u.getHost();
        }
      } catch (URISyntaxException ignored) {
        // fall through to the region-derived default
      }
    }
    return region + ".api.camunda.io";
  }

  /** Result of {@link #normalizeRestBase()}: the canonical REST base URL, the
   * bare host, and whether the raw input needed fixing (worth a WARN). */
  static final class RestBase {
    final String restBase;
    final String host;
    final boolean wasNormalized;

    RestBase(String restBase, String host, boolean wasNormalized) {
      this.restBase = restBase;
      this.host = host;
      this.wasNormalized = wasNormalized;
    }
  }

  private static final Pattern UUID_RE =
      Pattern.compile(
          "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", Pattern.CASE_INSENSITIVE);

  /** Rebuild a canonical https://&lt;host&gt;/&lt;clusterId&gt; REST base,
   * mirroring the Go binary's hostset.parseExplicitHost tolerance (UUID-
   * anywhere-in-path + authority-port stripping) and Python's
   * _shared.normalize_rest_base -- ported here because the Java SDK needs a
   * full URI for restAddress(), not just a hostname.
   *
   * This exists because Camunda Console's copy-paste CAMUNDA_REST_ADDRESS
   * form embeds a stray ':443' path segment
   * (https://&lt;host&gt;/:443/&lt;clusterId&gt;/v2/) that real SDKs do not
   * tolerate: the raw form yields a Cloudflare 'default backend - 404' for
   * both the Python SDK and the Java SDK.
   * NOTE: for the Java SDK probe, normalizing here is necessary but not
   * sufficient -- the builder must ALSO call applyEnvironmentVariableOverrides
   * (false), or build() re-reads the raw CAMUNDA_REST_ADDRESS env and clobbers
   * this normalized value (see SdkProbe). */
  static RestBase normalizeRestBase() {
    String raw = envOrEmpty("CAMUNDA_REST_ADDRESS");
    String region = envOrDefault("CAMUNDA_REGION", "bru-2");
    String clusterIdEnv = envOrEmpty("CAMUNDA_CLUSTER_ID");

    if (raw.isEmpty()) {
      String host = region + ".api.camunda.io";
      String base = clusterIdEnv.isEmpty() ? "https://" + host : "https://" + host + "/" + clusterIdEnv;
      return new RestBase(base, host, false);
    }

    String candidate = raw.contains("://") ? raw : "https://" + raw;
    URI parsed;
    try {
      parsed = new URI(candidate);
    } catch (URISyntaxException e) {
      return new RestBase(candidate, region + ".api.camunda.io", false);
    }
    String host = parsed.getHost() != null ? parsed.getHost() : (region + ".api.camunda.io");

    String path = parsed.getPath() == null ? "" : parsed.getPath();
    String[] segments = path.split("/");
    String clusterId = null;
    for (String seg : segments) {
      if (UUID_RE.matcher(seg).matches()) {
        clusterId = seg;
        break;
      }
    }
    if (clusterId == null) {
      clusterId = clusterIdEnv;
    }
    if (clusterId == null || clusterId.isEmpty()) {
      // No UUID anywhere -- return the input untouched rather than guessing.
      return new RestBase(candidate, host, false);
    }

    String canonical = "https://" + host + "/" + clusterId;
    int strayCount = 0;
    for (String seg : segments) {
      if (!seg.isEmpty() && !seg.equals(clusterId) && !seg.equals("v2")) {
        strayCount++;
      }
    }
    boolean wasNormalized = strayCount > 0 || parsed.getPort() != -1;
    return new RestBase(canonical, host, wasNormalized);
  }

  /** Mirrors the Go binary's network-vs-full decision so probes never diverge
   * from it: network mode must be credential-free -- status only, no
   * authenticated topology, no token. An explicit mode (passed by the
   * launcher via CAMUNDA_PREFLIGHT_MODE) wins; when unset (probe run
   * standalone by hand) fall back to creds-presence auto-detect, the same
   * default the Go binary uses. */
  static boolean resolveIsFull(String mode, boolean hasCreds) {
    String m = mode == null ? "" : mode.trim().toLowerCase(Locale.ROOT);
    if (m.equals("network")) {
      return false;
    }
    if (m.equals("full")) {
      return true;
    }
    return hasCreds;
  }

  /** Whether to surface extra diagnostic fragments hidden by default (e.g. the
   * Console-URL normalization notice) -- useful to the operator/trainer, but
   * confusing noise for participants. Set by the launcher via
   * CAMUNDA_PREFLIGHT_VERBOSE (from the Go binary's --verbose), or by passing
   * --verbose when running the probe standalone. */
  static boolean isVerbose(String[] args) {
    if (args != null) {
      for (String a : args) {
        if ("--verbose".equals(a)) {
          return true;
        }
      }
    }
    String v = envOrEmpty("CAMUNDA_PREFLIGHT_VERBOSE").toLowerCase(Locale.ROOT);
    return v.equals("1") || v.equals("true") || v.equals("yes");
  }

  // ---- custom Java truststore (this tool's --java-truststore /
  // CAMUNDA_JAVA_TRUSTSTORE) ----

  /** Applies -Djavax.net.ssl.trustStore(+Password) from CAMUNDA_JAVA_TRUSTSTORE
   * (this tool's own knob, forwarded by the Go launcher's --java-truststore
   * flag) BEFORE any SSLContext/HttpClient is built in this process -- the JVM
   * only reads these system properties the first time the default trust
   * manager is initialized, so this must run before buildTrustContext()/client
   * construction. Only takes effect when CAMUNDA_CA_CERTIFICATE_PATH is NOT
   * set -- that env var's code path builds its own KeyStore from scratch and
   * never consults these properties (see javaTrustStoreIgnoredWarning).
   *
   * Returns a WARN fragment if the path doesn't exist, in which case the
   * property is deliberately NOT set: the JDK's default
   * TrustManagerFactory SILENTLY falls back to the regular cacerts trust
   * store when javax.net.ssl.trustStore names a missing file (documented JSSE
   * behavior, not a bug), which would otherwise produce a quiet false PASS
   * against any publicly-trusted host instead of surfacing the typo. The Go
   * binary also checks this before ever forwarding the flag, but the probe
   * checks again since it's runnable standalone too. */
  static String applyJavaTrustStoreSystemProperty(String configTarget) {
    String path = envOrEmpty("CAMUNDA_JAVA_TRUSTSTORE");
    if (path.isEmpty()) {
      return null;
    }
    if (!new java.io.File(path).isFile()) {
      return fragment(
          configTarget,
          "WARN",
          "CONFIG_ERROR",
          "CAMUNDA_JAVA_TRUSTSTORE is set to "
              + path
              + ", but that file does not exist -- NOT applying it. A missing file here fails "
              + "SILENTLY inside the JVM (falls back to the default cacerts rather than erroring), "
              + "which would otherwise look like a false PASS instead of a config mistake.");
    }
    if (looksLikePem(new java.io.File(path))) {
      return fragment(
          configTarget,
          "WARN",
          "CONFIG_ERROR",
          "CAMUNDA_JAVA_TRUSTSTORE is set to "
              + path
              + ", but that file looks like a raw PEM certificate, not a JKS/PKCS12 keystore -- NOT "
              + "applying it. -Djavax.net.ssl.trustStore requires an actual keystore file: build one with "
              + "e.g. `keytool -importcert -alias corporate-proxy-ca -keystore truststore.jks -file "
              + path
              + " -storepass changeit -noprompt` (ideally starting from a copy of cacerts so public CAs "
              + "stay trusted too). If you just want to trust this one PEM directly (accepting "
              + "that it REPLACES the trust store rather than appending), use --trust-ca/CAMUNDA_MTLS_CA_PATH "
              + "instead, which reads a raw PEM. Leaving this set as-is would otherwise crash the JVM's "
              + "default SSL context with a cryptic NoSuchAlgorithmException the next time it's touched.");
    }
    System.setProperty("javax.net.ssl.trustStore", path);
    String password = envOrEmpty("CAMUNDA_JAVA_TRUSTSTORE_PASSWORD");
    if (!password.isEmpty()) {
      System.setProperty("javax.net.ssl.trustStorePassword", password);
    }
    return null;
  }

  /** True only if applyJavaTrustStoreSystemProperty() would actually set the
   * system property for this file -- exists AND doesn't look like a raw PEM.
   * Used by defaultTrustLabel() so it never claims a custom truststore is in
   * effect when apply() rejected it for either reason. */
  private static boolean isApplicableTruststoreFile(java.io.File file) {
    return file.isFile() && !looksLikePem(file);
  }

  /** Cheap, deterministic sniff for "this is a PEM text file, not a binary
   * JKS/PKCS12 keystore" -- checks the first few lines for a PEM header. A
   * genuine JKS/PKCS12 file is binary and will either fail to decode as ASCII
   * (caught below, treated as "not PEM") or simply not contain this text. */
  private static boolean looksLikePem(java.io.File file) {
    try (java.io.BufferedReader r =
        java.nio.file.Files.newBufferedReader(file.toPath(), java.nio.charset.StandardCharsets.US_ASCII)) {
      String line;
      for (int i = 0; i < 5 && (line = r.readLine()) != null; i++) {
        if (line.contains("-----BEGIN")) {
          return true;
        }
      }
    } catch (java.io.IOException e) {
      // Not decodable as ASCII text at all -- consistent with a real binary
      // keystore. Let the normal load path surface whatever error (if any)
      // actually occurs.
    }
    return false;
  }

  /** Human-readable trust-store label for the caPath-empty branch --
   * distinguishes a plain JVM default from an operator-supplied custom
   * truststore file (CAMUNDA_JAVA_TRUSTSTORE), so trustStoreExercised is
   * actually informative rather than always saying "cacerts" once a custom
   * truststore is in play. Only claims the custom file when it actually
   * exists and was applied by applyJavaTrustStoreSystemProperty() -- a
   * missing path is deliberately NOT set as a system property (see there), so
   * this must not claim it's in effect either.
   *
   * Kept short and plain-language deliberately -- this string ends up in the
   * customer-facing result (Notes section / FAIL details), not just an
   * engineering log. */
  static String defaultTrustLabel() {
    String tsPath = envOrEmpty("CAMUNDA_JAVA_TRUSTSTORE");
    if (tsPath.isEmpty() || !isApplicableTruststoreFile(new java.io.File(tsPath))) {
      return "the default certificate store";
    }
    return "your custom certificate file (" + tsPath + ")";
  }

  /** WARN fragment when --java-truststore/CAMUNDA_JAVA_TRUSTSTORE is set but
   * CAMUNDA_CA_CERTIFICATE_PATH is ALSO set -- the latter's code path builds
   * its own CA-only KeyStore and never looks at the trustStore system
   * property, so the truststore would silently have no effect. Returns null
   * when there's no conflict (the two knobs are mutually exclusive by
   * construction: this only fires from the caPath-non-empty branch). */
  static String javaTrustStoreIgnoredWarning(String configTarget, String caPath) {
    String tsPath = envOrEmpty("CAMUNDA_JAVA_TRUSTSTORE");
    if (tsPath.isEmpty() || caPath.isEmpty()) {
      return null;
    }
    return fragment(
        configTarget,
        "WARN",
        "CONFIG_ERROR",
        "Both --java-truststore and --trust-ca (CAMUNDA_CA_CERTIFICATE_PATH) are set for Java -- only "
            + "--trust-ca takes effect in that case, so your --java-truststore file is being silently "
            + "ignored. Use one or the other, not both.");
  }

  static String envOrEmpty(String name) {
    String v = System.getenv(name);
    return v == null ? "" : v.trim();
  }

  static String envOrDefault(String name, String def) {
    String v = envOrEmpty(name);
    return v.isEmpty() ? def : v;
  }

  // ---- error classification ----
  // Mirrors probe.py's classify_transport_error: instanceof-based checks
  // first (structural, like Go's errors.As DNS check), falling back to
  // substring matching on the exception chain's text for wrapped/opaque
  // cases -- the same layered approach used across every language in this
  // project. Returns {errorClass, detail}.

  static String[] classifyTransportError(Throwable t) {
    List<Throwable> chain = new ArrayList<>();
    Throwable cur = t;
    while (cur != null && !chain.contains(cur)) {
      chain.add(cur);
      cur = cur.getCause();
    }

    for (Throwable e : chain) {
      if (e instanceof UnknownHostException) {
        return new String[] {"DNS_FAIL", "hostname did not resolve: " + e};
      }
      if (e instanceof ConnectException) {
        return new String[] {
          "CONNECT_REFUSED", "connection refused -- port 443 likely blocked by firewall: " + e
        };
      }
      if (e instanceof SocketTimeoutException) {
        return new String[] {
          "CONNECT_TIMEOUT",
          "connection timed out -- port 443 likely blocked/dropped by firewall: " + e
        };
      }
    }

    String text =
        chain.stream().map(String::valueOf).collect(Collectors.joining(" | ")).toLowerCase(Locale.ROOT);
    // "PKIX path building failed" is the classic JDK cert-trust error text --
    // distinct from the cert-trust error text other language runtimes in this
    // project emit for the same underlying failure.
    if (text.contains("pkix") || text.contains("unable to find valid certification path")) {
      return new String[] {"TLS_HANDSHAKE_FAIL", "certificate not trusted: " + chain.get(0)};
    }
    if (text.contains("connection refused")
        || text.contains("actively refused")
        || text.contains("forbidden by its access permissions")) {
      return new String[] {
        "CONNECT_REFUSED", "connection refused -- port 443 likely blocked by firewall: " + chain.get(0)
      };
    }
    if (text.contains("timed out") || text.contains("timeout")) {
      return new String[] {
        "CONNECT_TIMEOUT",
        "connection timed out -- port 443 likely blocked/dropped by firewall: " + chain.get(0)
      };
    }
    if (text.contains("ssl") || text.contains("tls") || text.contains("handshake")) {
      return new String[] {"TLS_HANDSHAKE_FAIL", "TLS handshake failed: " + chain.get(0)};
    }
    // Text-matched (not instanceof) deliberately -- Shared.java is compiled
    // for the native probe too, which has NO Apache HttpClient5 on its
    // classpath (zero-dependency by design), so it can't reference
    // org.apache.hc.core5.http.ConnectionClosedException directly. Note: this was previously falling through to the generic
    // CONNECT_REFUSED fallback below, wrongly implying a firewall block for
    // a connection that was actually established -- a real cause seen in
    // this project was a config-side trust-store gap breaking the OAuth
    // token fetch mid-request, not a network block at all.
    if (text.contains("connectionclosedexception") || text.contains("connection is closed")) {
      return new String[] {
        "CONNECTION_CLOSED",
        "connection was established then closed unexpectedly before completing: "
            + chain.get(0)
            + " -- NOT necessarily a firewall block (the connection did open). Check for a CONFIG_ERROR "
            + "note above (a custom CA set for full mode can break the OAuth token fetch specifically), "
            + "or a stale/misconfigured proxy."
      };
    }
    return new String[] {"CONNECT_REFUSED", "connection failed: " + chain.get(0)};
  }
}
