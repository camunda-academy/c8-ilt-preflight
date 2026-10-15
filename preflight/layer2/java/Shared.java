import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
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

  /** Whether enough config exists to build a REST base with an actual cluster
   * route -- CAMUNDA_REST_ADDRESS carries a UUID somewhere in its path, or
   * CAMUNDA_CLUSTER_ID is one itself.
   *
   * Mirrors the Go binary's own hostset.Resolve validation. That check runs
   * before the binary ever invokes a probe, so it normally catches a missing
   * cluster id before any Layer 2 code executes at all -- but this file is
   * also runnable standalone, which bypasses it. Without this, normalizeRestBase()
   * below silently falls back to a bare https://&lt;region&gt;.api.camunda.io
   * with no cluster path, and the SDK's resulting 404 reads as a transient
   * cluster problem instead of a missing --cluster-id/--host. */
  static boolean hasClusterTarget() {
    String raw = envOrEmpty("CAMUNDA_REST_ADDRESS");
    if (!raw.isEmpty()) {
      for (String seg : raw.split("/")) {
        if (UUID_RE.matcher(seg).matches()) {
          return true;
        }
      }
    }
    return UUID_RE.matcher(envOrEmpty("CAMUNDA_CLUSTER_ID")).matches();
  }

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

  // ---- Maven: proxy settings and trust store ----
  //
  // Maven reads neither HTTPS_PROXY/HTTP_PROXY nor this tool's --trust-ca. Its
  // proxy comes only from <proxies> in a settings.xml, and its TLS trust only
  // from the JVM it runs on. These helpers translate both into what Maven does
  // read, for the settings files and mvn processes the probes generate.

  static boolean isWindows() {
    return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
  }

  /** Maven 3.9's default HTTP transport sends proxy credentials on the first
   * CONNECT tunnel only; the further tunnels a dependency download opens go
   * out without them, an authenticating proxy answers 407, and the build
   * fails. The wagon transport authenticates every tunnel. Returns the mvn
   * argument selecting it when the configured proxy carries credentials,
   * otherwise an empty list. */
  static List<String> mavenProxyAuthTransportArgs() {
    ProxyParts proxy = parseProxyUrl(getProxyUrl());
    List<String> args = new ArrayList<>();
    if (proxy != null && proxy.username != null) {
      args.add("-Dmaven.resolver.transport=wagon");
    }
    return args;
  }

  /** Guidance for a Maven run on the operator's OWN settings that failed with
   * a proxy 407 -- see mavenProxyAuthTransportArgs for the cause. */
  static String mavenProxyAuthHint(String mvnOutput) {
    if (mvnOutput == null || !mvnOutput.contains("407")) {
      return "";
    }
    return " Maven got HTTP 407 from the proxy. If your settings.xml already has the proxy credentials, this "
        + "is likely Maven 3.9's default HTTP transport, which authenticates only the first tunnel through an "
        + "authenticating proxy: add -Dmaven.resolver.transport=wagon to MAVEN_OPTS or to the project's "
        + ".mvn/maven.config.";
  }

  /** A proxy URL split into the parts a Maven &lt;proxy&gt; entry takes.
   * username/password are already percent-decoded, null when absent. */
  static final class ProxyParts {
    final String host;
    final int port;
    final String username;
    final String password;

    ProxyParts(String host, int port, String username, String password) {
      this.host = host;
      this.port = port;
      this.username = username;
      this.password = password;
    }
  }

  /** Splits a proxy URL by hand rather than through java.net.URI: URI rejects
   * a password containing characters such as '&lt;', '"' or a bare '%', and
   * people do paste unencoded passwords into HTTPS_PROXY. The userinfo ends at
   * the LAST '@', so an unencoded '@' inside the password still parses.
   * Percent-escapes are decoded (the URL convention for special characters);
   * a '%' not followed by two hex digits is kept literally. Returns null when
   * no usable host/port can be extracted. Without a port, the scheme's default
   * is used (http 80, https 443), the same rule Probe.connectViaProxy applies. */
  static ProxyParts parseProxyUrl(String url) {
    if (url == null || url.trim().isEmpty()) {
      return null;
    }
    String s = url.trim();
    String scheme = "http";
    int sep = s.indexOf("://");
    if (sep >= 0) {
      scheme = s.substring(0, sep).toLowerCase(Locale.ROOT);
      s = s.substring(sep + 3);
    }
    String user = null;
    String pass = null;
    int at = s.lastIndexOf('@');
    if (at >= 0) {
      String userInfo = s.substring(0, at);
      s = s.substring(at + 1);
      int colon = userInfo.indexOf(':');
      user = percentDecode(colon >= 0 ? userInfo.substring(0, colon) : userInfo);
      if (colon >= 0) {
        pass = percentDecode(userInfo.substring(colon + 1));
      }
      if (user.isEmpty()) {
        user = null;
      }
    }
    int end = s.length();
    for (char c : new char[] {'/', '?', '#'}) {
      int i = s.indexOf(c);
      if (i >= 0 && i < end) {
        end = i;
      }
    }
    String hostPort = s.substring(0, end);
    String host;
    String portStr = "";
    if (hostPort.startsWith("[")) {
      int rb = hostPort.indexOf(']');
      if (rb < 0) {
        return null;
      }
      host = hostPort.substring(1, rb);
      String rest = hostPort.substring(rb + 1);
      if (rest.startsWith(":")) {
        portStr = rest.substring(1);
      }
    } else {
      int colon = hostPort.lastIndexOf(':');
      host = colon >= 0 ? hostPort.substring(0, colon) : hostPort;
      portStr = colon >= 0 ? hostPort.substring(colon + 1) : "";
    }
    if (host.isEmpty()) {
      return null;
    }
    int port = scheme.equals("https") ? 443 : 80;
    if (!portStr.isEmpty()) {
      try {
        port = Integer.parseInt(portStr);
      } catch (NumberFormatException e) {
        return null;
      }
      if (port < 1 || port > 65535) {
        return null;
      }
    }
    return new ProxyParts(host, port, user, pass);
  }

  /** host:port of a proxy URL for messages -- built from the parsed parts, so
   * no credential can survive into it even when an unencoded password
   * contains '@' or '/' and defeats the regex in scrubUrlCreds. */
  static String proxyDisplay(String url) {
    ProxyParts p = parseProxyUrl(url);
    if (p == null) {
      return "(unparseable proxy URL)";
    }
    String host = p.host.contains(":") ? "[" + p.host + "]" : p.host;
    return host + ":" + p.port + (p.username != null ? " with credentials" : "");
  }

  private static String percentDecode(String s) {
    byte[] raw = s.getBytes(StandardCharsets.UTF_8);
    ByteArrayOutputStream out = new ByteArrayOutputStream(raw.length);
    for (int i = 0; i < raw.length; i++) {
      int hi = i + 2 < raw.length ? Character.digit(raw[i + 1], 16) : -1;
      int lo = i + 2 < raw.length ? Character.digit(raw[i + 2], 16) : -1;
      if (raw[i] == '%' && hi >= 0 && lo >= 0) {
        out.write(hi * 16 + lo);
        i += 2;
      } else {
        out.write(raw[i]);
      }
    }
    return new String(out.toByteArray(), StandardCharsets.UTF_8);
  }

  /** Translates a NO_PROXY list into Maven's nonProxyHosts syntax ('|'
   * separated, '*' wildcards). A NO_PROXY domain entry conventionally covers
   * the domain and its subdomains, so "example.com" and ".example.com" both
   * become "example.com|*.example.com". Ports are dropped (Maven matches host
   * names only) and CIDR ranges are skipped, since Maven has no equivalent. */
  static String mavenNonProxyHosts(String noProxy) {
    if (noProxy == null) {
      return "";
    }
    List<String> out = new ArrayList<>();
    for (String raw : noProxy.split(",")) {
      String h = raw.trim();
      if (h.isEmpty() || h.contains("/") || h.contains("|")) {
        continue;
      }
      if (h.startsWith("[")) {
        int rb = h.indexOf(']');
        if (rb < 0) {
          continue;
        }
        h = h.substring(1, rb);
      } else if (h.indexOf(':') >= 0 && h.indexOf(':') == h.lastIndexOf(':')) {
        h = h.substring(0, h.indexOf(':'));
      }
      if (h.startsWith("*.")) {
        h = h.substring(2);
      } else if (h.startsWith(".")) {
        h = h.substring(1);
      }
      if (h.isEmpty()) {
        continue;
      }
      out.add(h);
      boolean isAddress = h.matches("[0-9.]+") || h.contains(":");
      if (h.contains(".") && !h.contains("*") && !isAddress) {
        out.add("*." + h);
      }
    }
    return String.join("|", out);
  }

  /** The &lt;proxies&gt; block for the given proxy, or "" when there is none.
   * Two entries, one per protocol, pointing at the same proxy: Maven picks a
   * proxy by the repository URL's protocol, so a single entry would leave
   * either http or https repositories unproxied. Every value is XML-escaped --
   * a proxy password can legitimately contain '&amp;', '&lt;' or quotes. */
  static String mavenProxiesXml(ProxyParts p, String nonProxyHosts) {
    if (p == null) {
      return "";
    }
    StringBuilder sb = new StringBuilder("<proxies>");
    for (String protocol : new String[] {"https", "http"}) {
      sb.append("<proxy><id>c8-preflight-").append(protocol).append("</id><active>true</active>");
      sb.append("<protocol>").append(protocol).append("</protocol>");
      sb.append("<host>").append(xmlEscape(p.host)).append("</host>");
      sb.append("<port>").append(p.port).append("</port>");
      if (p.username != null) {
        sb.append("<username>").append(xmlEscape(p.username)).append("</username>");
      }
      if (p.password != null) {
        sb.append("<password>").append(xmlEscape(p.password)).append("</password>");
      }
      if (nonProxyHosts != null && !nonProxyHosts.isEmpty()) {
        sb.append("<nonProxyHosts>").append(xmlEscape(nonProxyHosts)).append("</nonProxyHosts>");
      }
      sb.append("</proxy>");
    }
    sb.append("</proxies>");
    return sb.toString();
  }

  /** The proxy from HTTPS_PROXY/HTTP_PROXY as a &lt;proxies&gt; block (with
   * NO_PROXY as nonProxyHosts), or "" when no usable proxy is configured. */
  static String mavenProxiesXmlFromEnv() {
    String noProxy = System.getenv("NO_PROXY");
    if (noProxy == null || noProxy.isEmpty()) {
      noProxy = System.getenv("no_proxy");
    }
    return mavenProxiesXml(parseProxyUrl(getProxyUrl()), mavenNonProxyHosts(noProxy));
  }

  /** A settings.xml with no mirrors and no profiles -- plain Maven Central --
   * plus the given &lt;proxies&gt; block (may be ""). */
  static String centralSettingsXml(String proxiesXml) {
    return "<settings xmlns=\"http://maven.apache.org/SETTINGS/1.0.0\">"
        + (proxiesXml == null ? "" : proxiesXml)
        + "<mirrors></mirrors><profiles></profiles></settings>";
  }

  static String xmlEscape(String s) {
    return s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&apos;");
  }

  /** A temp directory for files handed to Maven. Files.createTempDirectory
   * creates it owner-only (0700 on POSIX; under the per-user profile on
   * Windows), which matters because a generated settings.xml can hold the
   * proxy password.
   *
   * <p>The trust-store path ends up inside MAVEN_OPTS, which the POSIX `mvn`
   * script word-splits without honoring quotes, so on POSIX a temp path with
   * whitespace is retried under /tmp and refused if that has whitespace too.
   * mvn.cmd passes MAVEN_OPTS through to java.exe, which does honor quotes
   * (see MavenTrust.mavenOpts). */
  static Path createMavenTempDir(String prefix) throws IOException {
    Path dir = Files.createTempDirectory(prefix);
    if (isWindows() || !hasWhitespace(dir.toString())) {
      return dir;
    }
    deleteTree(dir);
    dir = Files.createTempDirectory(Paths.get("/tmp"), prefix);
    if (hasWhitespace(dir.toString())) {
      deleteTree(dir);
      throw new IOException("no temp directory without whitespace in its path is available, and "
          + "MAVEN_OPTS cannot carry such a path");
    }
    return dir;
  }

  private static boolean hasWhitespace(String s) {
    for (int i = 0; i < s.length(); i++) {
      if (Character.isWhitespace(s.charAt(i))) {
        return true;
      }
    }
    return false;
  }

  static void deleteTree(Path dir) {
    if (dir == null) {
      return;
    }
    try (java.util.stream.Stream<Path> walk = Files.walk(dir)) {
      walk.sorted(Comparator.reverseOrder())
          .forEach(
              p -> {
                try {
                  Files.deleteIfExists(p);
                } catch (IOException ignored) {
                  // best effort -- a leftover temp file holds no secret beyond
                  // what the operator's own environment already contains
                }
              });
    } catch (IOException ignored) {
      // directory already gone
    }
  }

  /** The trust store a Maven child process is started with, if any.
   *
   * <p>file == null means Maven runs on its JVM's own default trust store,
   * either because nothing was configured or because building the store
   * failed (then problem says why). label is a short, plain-language
   * description for fragment details. */
  static final class MavenTrust {
    // A trust store holds only public certificates, so its password protects
    // nothing; it exists because the keystore format wants one.
    static final String PASSWORD = "changeit";

    final Path dir;
    final Path file;
    final String label;
    final String problem;

    MavenTrust(Path dir, Path file, String label, String problem) {
      this.dir = dir;
      this.file = file;
      this.label = label;
      this.problem = problem;
    }

    boolean isCustom() {
      return file != null;
    }

    /** existing MAVEN_OPTS (may be null/empty) with the trust-store system
     * properties appended. Appended, not prepended: for a repeated -D the JVM
     * keeps the last one, so these win over a trust store set there already,
     * while every other option the operator put in MAVEN_OPTS is kept. */
    String mavenOpts(String existing) {
      if (file == null) {
        return existing;
      }
      String path = file.toString();
      if (isWindows() && hasWhitespace(path)) {
        path = "\"" + path + "\"";
      }
      String opts = "-Djavax.net.ssl.trustStore=" + path
          + " -Djavax.net.ssl.trustStorePassword=" + PASSWORD
          + " -Djavax.net.ssl.trustStoreType=JKS";
      return existing == null || existing.trim().isEmpty() ? opts : existing + " " + opts;
    }

    /** Environment overrides for a Maven child process: MAVEN_OPTS only. */
    Map<String, String> env() {
      Map<String, String> env = new HashMap<>();
      if (file != null) {
        env.put("MAVEN_OPTS", mavenOpts(System.getenv("MAVEN_OPTS")));
      }
      return env;
    }

    void cleanup() {
      deleteTree(dir);
    }
  }

  /** Builds the trust store Maven child processes should use, from the same
   * env vars the Java probes read, in the same precedence as Probe:
   *
   * <ul>
   *   <li>CAMUNDA_CA_CERTIFICATE_PATH (--trust-ca), else CAMUNDA_MTLS_CA_PATH:
   *       the JDK's default CAs PLUS the certificates in that PEM file. Appended,
   *       not replaced as in the SDK: Maven reaches repositories that may well
   *       not sit behind the intercepting proxy, and those still need the
   *       public CAs.
   *   <li>CAMUNDA_JAVA_TRUSTSTORE (--java-truststore): the certificates of that
   *       store, as they are.
   * </ul>
   *
   * <p>The result is always a fresh JKS file in a temp directory, also for
   * --java-truststore: re-writing it keeps the operator's own path (which may
   * contain spaces) and password out of MAVEN_OPTS, and JKS is the one format
   * every JVM Maven may run on can read -- a PKCS12 file written by a current
   * JDK uses algorithms older Java 8 updates cannot load. */
  static MavenTrust prepareMavenTrust() {
    String caPath = envOrEmpty("CAMUNDA_CA_CERTIFICATE_PATH");
    String tsPath = envOrEmpty("CAMUNDA_JAVA_TRUSTSTORE");
    if (caPath.isEmpty() && tsPath.isEmpty()) {
      caPath = envOrEmpty("CAMUNDA_MTLS_CA_PATH");
    }
    String defaultLabel = "the default trust store of the JDK Maven runs on";
    if (caPath.isEmpty() && tsPath.isEmpty()) {
      return new MavenTrust(null, null, defaultLabel, null);
    }
    boolean fromCa = !caPath.isEmpty();
    String source = fromCa
        ? "your --trust-ca certificate (" + caPath + ")"
        : "your --java-truststore file (" + tsPath + ")";
    Path dir = null;
    try {
      KeyStore ks = KeyStore.getInstance("JKS");
      ks.load(null, null);
      String label;
      if (fromCa) {
        int defaults = addDefaultCas(ks);
        int added = addPemCertificates(ks, caPath);
        label = "the JDK's " + defaults + " default CAs plus " + added + " certificate"
            + (added == 1 ? "" : "s") + " from " + source;
      } else {
        java.io.File f = new java.io.File(tsPath);
        if (!f.isFile()) {
          throw new IOException("the file does not exist");
        }
        if (looksLikePem(f)) {
          throw new IOException("it is a PEM certificate, not a JKS/PKCS12 keystore -- pass a PEM with "
              + "--trust-ca instead");
        }
        int copied = copyCertificates(f, envOrEmpty("CAMUNDA_JAVA_TRUSTSTORE_PASSWORD"), ks);
        label = "the " + copied + " certificate" + (copied == 1 ? "" : "s") + " in " + source;
      }
      dir = createMavenTempDir("c8-maven-trust");
      Path file = dir.resolve("truststore.jks");
      try (OutputStream out = Files.newOutputStream(file)) {
        ks.store(out, MavenTrust.PASSWORD.toCharArray());
      }
      return new MavenTrust(dir, file, label, null);
    } catch (Exception e) {
      deleteTree(dir);
      return new MavenTrust(null, null, defaultLabel,
          "could not hand " + source + " to Maven, so Maven ran with " + defaultLabel + ": "
              + describeThrowable(e));
    }
  }

  /** Adds every CA the JVM's default trust manager accepts -- the JDK's
   * cacerts (or jssecacerts, when present), exactly what an unconfigured JVM
   * trusts. */
  private static int addDefaultCas(KeyStore ks) throws Exception {
    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init((KeyStore) null);
    int n = 0;
    for (TrustManager tm : tmf.getTrustManagers()) {
      if (tm instanceof X509TrustManager) {
        for (X509Certificate c : ((X509TrustManager) tm).getAcceptedIssuers()) {
          ks.setCertificateEntry("default-" + n, c);
          n++;
        }
      }
    }
    return n;
  }

  private static int addPemCertificates(KeyStore ks, String pemPath) throws Exception {
    Collection<? extends Certificate> certs;
    try (InputStream in = Files.newInputStream(Paths.get(pemPath))) {
      certs = CertificateFactory.getInstance("X.509").generateCertificates(in);
    }
    if (certs.isEmpty()) {
      throw new IOException("no certificate found in " + pemPath);
    }
    int n = 0;
    for (Certificate c : certs) {
      ks.setCertificateEntry("custom-" + n, c);
      n++;
    }
    return n;
  }

  /** Copies the trusted-certificate entries of an existing JKS/PKCS12 store --
   * the only entries a JSSE trust manager uses. An empty password means none,
   * as with javax.net.ssl.trustStorePassword left unset. A password that does
   * not match is retried without one: on a pure trust store the password only
   * guards an integrity check, and the certificates load without it. */
  private static int copyCertificates(java.io.File src, String password, KeyStore dst) throws Exception {
    KeyStore in;
    boolean passwordRejected = false;
    try {
      in = KeyStore.getInstance(src, password.isEmpty() ? null : password.toCharArray());
    } catch (IOException e) {
      if (password.isEmpty()) {
        throw e;
      }
      in = KeyStore.getInstance(src, (char[]) null);
      passwordRejected = true;
    }
    int n = 0;
    for (Enumeration<String> aliases = in.aliases(); aliases.hasMoreElements(); ) {
      String alias = aliases.nextElement();
      if (in.isCertificateEntry(alias)) {
        dst.setCertificateEntry("store-" + n, in.getCertificate(alias));
        n++;
      }
    }
    if (n == 0) {
      // A PKCS12 store usually encrypts its certificates too, so without the
      // right password none can be read.
      throw new IOException(passwordRejected
          ? "the --java-truststore-password does not match this store, and without it no certificate can be read"
          : password.isEmpty()
              ? "no trusted certificate could be read -- if the store has a password, pass it with "
                  + "--java-truststore-password"
              : "the store holds no trusted certificates");
    }
    return n;
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
    // org.apache.hc.core5.http.ConnectionClosedException directly. Without
    // this match the case falls through to the generic CONNECT_REFUSED
    // fallback below, wrongly implying a firewall block for a connection
    // that was actually established -- one cause is a config-side
    // trust-store gap breaking the OAuth token fetch mid-request, not a
    // network block at all.
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
