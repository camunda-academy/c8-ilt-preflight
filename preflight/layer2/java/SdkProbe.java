import io.camunda.client.CamundaClient;
import io.camunda.client.CamundaClientBuilder;
import io.camunda.client.CredentialsProvider;
import io.camunda.client.api.command.ClientException;
import io.camunda.client.api.command.ClientHttpException;
import io.camunda.client.api.response.Topology;
import io.camunda.client.impl.NoopCredentialsProvider;
import io.camunda.client.impl.oauth.OAuthCredentialsProviderBuilder;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.URI;

/**
 * Layer 2 SDK-snippet confirmation -- Java.
 *
 * Standalone (requires the real SDK on the classpath -- see run.sh/run.cmd,
 * which resolve it via a scratch Maven project; requires Maven on PATH and
 * CAMUNDA_SDK_AUTO_INSTALL=1 / --install, opt-in for the same reason as the
 * Python probe's pip auto-install -- an automated preflight run on a broken
 * network shouldn't silently spend time fetching a dependency in exactly the
 * scenario it exists to catch):
 *
 *   javac -encoding UTF-8 -cp &lt;resolved classpath&gt; SdkProbe.java Shared.java
 *   java -Dstdout.encoding=UTF-8 -cp out:&lt;resolved classpath&gt; SdkProbe
 *
 * The vanilla client (io.camunda:camunda-client-java:8.9.11) is used directly
 * -- no Spring Boot Starter, no Spring context. This is the "literal SDK
 * connects + gets topology" real confirmation that complements the SDK-free
 * native probe (Probe.java) -- catching proxy-handling/config issues the raw
 * probe can't.
 *
 * Real facts below verified against camunda-client-java 8.9.11 source (jar +
 * sources jar from Maven Central), not assumed:
 *
 *  - CamundaClientBuilder auto-wires an OAuth CredentialsProvider whenever
 *    CAMUNDA_CLIENT_ID/CAMUNDA_CLIENT_SECRET are present in the environment
 *    (CamundaClientBuilderImpl.shouldUseOAuthCredentialsProvider) -- same
 *    env-var-driven auto-config as the Python SDK, no extra wiring needed.
 *
 *  - CRITICAL for network-mode consistency: that CredentialsProvider gets
 *    applied to EVERY request via an interceptor (HttpClientFactory:
 *    "credentialsProvider.applyCredentials(...)" runs unconditionally, not
 *    just for authenticated endpoints) -- so even the network-mode-analog
 *    get_status() call would silently authenticate if creds happen to be
 *    present, unless we force it off. The real client has NO env-var
 *    equivalent to Python's CAMUNDA_AUTH_STRATEGY=NONE; the only way to
 *    guarantee credential-free behavior is to explicitly set
 *    .credentialsProvider(new NoopCredentialsProvider()) on the builder in
 *    network mode. This probe does that -- no token is acquired
 *    in network mode even with credentials present in the environment.
 *
 *  - CRITICAL: relying on the SDK's own env-based auto-wiring for
 *    credentials has two real gaps. (1) CAMUNDA_TOKEN_AUDIENCE has NO built-in
 *    default in the raw SDK (unlike this tool's Go binary, which defaults it
 *    to "zeebe.camunda.io" in code) -- auto-wiring crashed with
 *    "Expected valid audience but none was provided" even for the
 *    network-mode-analog get_status() call, on a real .env that omits
 *    CAMUNDA_TOKEN_AUDIENCE because the Go tool never required it to be set.
 *    (2) the raw SDK's own OAuth-URL env var is CAMUNDA_AUTHORIZATION_SERVER_URL,
 *    NOT CAMUNDA_OAUTH_URL (this tool's Go/Python convention) -- yet another
 *    per-language name mismatch, on top of the CA-path one. Rather than add a
 *    third env-var-name WARN (diminishing returns), this probe builds the
 *    CredentialsProvider EXPLICITLY in full mode, reading this tool's own
 *    CAMUNDA_OAUTH_URL/CAMUNDA_TOKEN_AUDIENCE names and applying the exact
 *    same defaults as the Go binary, instead of relying on the SDK's
 *    auto-detection -- consistent config surface across every probe in this
 *    tool, and avoids depending on the raw SDK's incomplete defaults.
 *
 *  - The REST transport (Apache HttpClient 5) is built with
 *    .useSystemProperties() (HttpClientFactory.defaultClientBuilder), which
 *    reads JVM SYSTEM PROPERTIES (https.proxyHost/https.proxyPort), NOT the
 *    HTTP(S)_PROXY environment variables this tool's other probes read. A
 *    real customer setting only HTTPS_PROXY would see the raw SDK ignore it
 *    entirely. This probe translates HTTPS_PROXY/HTTP_PROXY into the
 *    corresponding system properties before building the client, so it
 *    faithfully tests what happens once that translation is done -- a real
 *    Java app needs -Dhttps.proxyHost/Port (or the system-property
 *    equivalent) set itself, not just the env var.
 *
 *  - send().join() unwraps the real cause directly (HttpCamundaFuture
 *    .unwrapExecutionException) -- catching ClientHttpException (which
 *    carries a real HTTP status via .code()) is sufficient for 401/503/etc.
 *    without parsing exception text, mirroring the Python SDK's typed errors.
 */
public final class SdkProbe {
  private static final String USAGE =
      "Layer 2 SDK-snippet confirmation -- Java.\n"
          + "Requires camunda-client-java on the classpath -- see run.sh/run.cmd.";

  public static void main(String[] args) {
    for (String a : args) {
      if (a.equals("-h") || a.equals("--help")) {
        System.err.println(USAGE);
        return;
      }
    }

    try {
      System.exit(run(args));
    } catch (Throwable t) {
      System.out.println(Shared.crashFragment(Shared.describeThrowable(t)));
      System.exit(1);
    }
  }

  private static int run(String[] args) {
    Shared.RestBase restBase = Shared.normalizeRestBase();
    int exitCode = 0;

    // Must happen before any HttpClient/SSLContext is built in this process --
    // see Shared.applyJavaTrustStoreSystemProperty(). Apache HttpClient5's
    // .useSystemProperties() (used below when no CAMUNDA_CA_CERTIFICATE_PATH
    // is set) honors -Djavax.net.ssl.trustStore the same way the native
    // probe's SSLContext.getDefault() does.
    String trustStoreWarning = Shared.applyJavaTrustStoreSystemProperty(restBase.host + " (config)");
    if (trustStoreWarning != null) {
      System.out.println(trustStoreWarning);
    }

    // Emit the normalization notice only in verbose mode: useful to the
    // operator/trainer but confusing noise for a participant (the
    // normalization still happens silently, so the check is valid regardless).
    if (restBase.wasNormalized && Shared.isVerbose(args)) {
      System.out.println(
          Shared.fragment(
              restBase.host + " (config)",
              "WARN",
              "CONFIG_ERROR",
              "your CAMUNDA_REST_ADDRESS is Camunda Console's copy-paste form (stray ':443' path "
                  + "segment). The real Java SDK does NOT tolerate it (it yields a "
                  + "'default backend - 404'); this probe normalized it to "
                  + restBase.restBase
                  + " to run the check. Use the canonical form (no ':443', no '/v2') in real application config."));
    }

    String caPath = Shared.envOrEmpty("CAMUNDA_CA_CERTIFICATE_PATH");
    String wrongNameCaPath = Shared.envOrEmpty("CAMUNDA_MTLS_CA_PATH");
    if (caPath.isEmpty() && !wrongNameCaPath.isEmpty()) {
      System.out.println(
          Shared.fragment(
              restBase.host + " (config)",
              "WARN",
              "CONFIG_ERROR",
              "CAMUNDA_MTLS_CA_PATH is set, but Java needs a different variable name: "
                  + "CAMUNDA_CA_CERTIFICATE_PATH. Your custom certificate will NOT be applied until you set "
                  + "CAMUNDA_CA_CERTIFICATE_PATH to the same path."));
    } else if (!caPath.isEmpty()) {
      String tsIgnoredWarning = Shared.javaTrustStoreIgnoredWarning(restBase.host + " (config)", caPath);
      if (tsIgnoredWarning != null) {
        System.out.println(tsIgnoredWarning);
      }
    }

    // Translate this tool's HTTPS_PROXY/HTTP_PROXY convention into the JVM
    // system properties Apache HttpClient5's useSystemProperties() actually
    // reads -- see the class doc comment. Must happen before the client is
    // built.
    String proxyUrl = Shared.getProxyUrl();
    if (proxyUrl != null) {
      applyProxySystemProperties(proxyUrl);
      System.err.println("[java sdk-probe] using proxy: " + Shared.scrubUrlCreds(proxyUrl));
    }

    boolean hasCreds =
        !Shared.envOrEmpty("CAMUNDA_CLIENT_ID").isEmpty() && !Shared.envOrEmpty("CAMUNDA_CLIENT_SECRET").isEmpty();
    boolean isFull = Shared.resolveIsFull(System.getenv("CAMUNDA_PREFLIGHT_MODE"), hasCreds);

    String trustLabel = caPath.isEmpty() ? Shared.defaultTrustLabel() : "your custom certificate (" + caPath + ")";

    // applyEnvironmentVariableOverrides(false) is CRITICAL: it defaults to
    // true, and build() then re-reads CAMUNDA_REST_ADDRESS from
    // the environment and OVERWRITES the restAddress we set below
    // (CamundaClientBuilderImpl.applyOverrides -> restAddress(getURIFromString(env))).
    // Our env holds the raw Console ":443" copy-paste form, so the override
    // silently undid our normalization and the SDK hit .../:443/.../v2/status ->
    // Cloudflare "default backend - 404". We set restAddress, credentials, and
    // caCertificatePath explicitly here, so we want NONE of the env re-reads.
    // (This also confirms live that the raw Console form genuinely breaks the
    // Java SDK -- previously unverified for Java specifically.)
    CamundaClientBuilder builder =
        CamundaClient.newClientBuilder()
            .applyEnvironmentVariableOverrides(false)
            .restAddress(URI.create(restBase.restBase));
    if (!caPath.isEmpty()) {
      builder.caCertificatePath(caPath);
    }
    if (!isFull) {
      // Force credential-free even if CAMUNDA_CLIENT_ID/SECRET happen to be
      // present -- see the class doc comment. Without this, applyCredentials
      // runs on every request regardless of which one we call.
      builder.credentialsProvider(new NoopCredentialsProvider());
    } else if (hasCreds) {
      // Build explicitly rather than relying on the SDK's env auto-detection
      // -- see the class doc comment for why (no built-in audience default,
      // different OAuth-URL env var name than this tool's convention).
      OAuthCredentialsProviderBuilder oauthBuilder = CredentialsProvider.newCredentialsProviderBuilder();
      oauthBuilder
          .clientId(Shared.envOrEmpty("CAMUNDA_CLIENT_ID"))
          .clientSecret(Shared.envOrEmpty("CAMUNDA_CLIENT_SECRET"))
          .audience(Shared.envOrDefault("CAMUNDA_TOKEN_AUDIENCE", "zeebe.camunda.io"))
          .authorizationServerUrl(
              Shared.envOrDefault("CAMUNDA_OAUTH_URL", "https://login.cloud.camunda.io/oauth/token"));
      // Verified in camunda-client-java 8.9.11 source (OAuthCredentialsProvider
      // uses its own HttpsURLConnection for the token fetch, and only trusts a
      // custom CA if truststorePath()/keystorePath() are set on THIS builder --
      // a completely separate config surface from CamundaClientBuilder's
      // caCertificatePath(), which we don't wire here). With
      // only CAMUNDA_CA_CERTIFICATE_PATH set, the token-fetch connection stays
      // on cacerts, so it rejects an intercepting proxy's cert while the main
      // REST client (which DOES get caCertificatePath) accepts the same proxy
      // fine -- surfacing as a ConnectionClosedException on every call, since
      // applyCredentials() runs before each request. This gap is in the real
      // SDK itself (even its own env-based auto-wiring has it -- verified in
      // CamundaClientBuilderImpl.createOAuthCredentialsProvider, which builds
      // the same way), not something this probe introduced -- so warn instead
      // of silently working around it.
      if (!caPath.isEmpty()) {
        System.out.println(
            Shared.fragment(
                restBase.host + " (config)",
                "WARN",
                "CONFIG_ERROR",
                "CAMUNDA_CA_CERTIFICATE_PATH is set, but the real SDK's OAuth token-fetch client does not "
                    + "inherit it -- it has its own separate trust-store config that this tool does not wire. "
                    + "The OAuth call to login.cloud.camunda.io will likely fail behind an intercepting proxy "
                    + "(watch for a ConnectionClosedException below). Use --java-truststore instead for full "
                    + "mode behind such a proxy -- it sets the trust store JVM-wide, which the OAuth client's "
                    + "default SSLContext also honors."));
      }
      builder.credentialsProvider(oauthBuilder.build());
    }

    try (CamundaClient client = builder.build()) {
      String statusTarget = restBase.host + " (sdk status)";
      try {
        client.newStatusRequest().send().join();
        System.out.println(Shared.fragment(statusTarget, "PASS", "OK", "SDK newStatusRequest() succeeded", trustLabel));
      } catch (ClientHttpException e) {
        // Mirror the Go binary's status.go classification: a completed TLS
        // handshake plus ANY clean HTTP response means transport reached the
        // cluster edge, so it is NEVER a customer-side network FAIL. 204 =
        // healthy (the try-block above); 503 = cluster unhealthy; ANY other
        // status (incl. 404 "default backend" from a paused/blipping
        // cluster) = reached-the-edge-no-route -> FAIL "our cluster, not your
        // network" (severity: blocks training right now; attribution: never
        // the customer's fault -- the Go binary's IsOurClusterProblem/
        // ExitOurClusterProblem convey that distinction, not the verdict).
        // A real 404-default-backend blip made this probe hard-FAIL while the
        // Go binary WARNed on the identical situation -- the exact
        // Go-vs-probe inconsistency this fixes. Note MalformedResponseException
        // (thrown when the 404 body isn't problem+json) extends
        // ClientHttpException and carries .code(), so it lands here too.
        if (e.code() == 503) {
          System.out.println(
              Shared.fragment(
                  statusTarget,
                  "FAIL",
                  "CLUSTER_UNHEALTHY_503",
                  "cluster reachable but unhealthy (503) -- likely our shared preflight cluster, not your network: "
                      + e,
                  trustLabel));
        } else {
          System.out.println(Shared.fragment(statusTarget, "FAIL", "CLUSTER_EDGE_404", clusterEdgeDetail(e.code()), trustLabel));
        }
        exitCode = 1;
      } catch (ClientException e) {
        String[] classified = Shared.classifyTransportError(e.getCause() != null ? e.getCause() : e);
        System.out.println(Shared.fragment(statusTarget, "FAIL", classified[0], classified[1], trustLabel));
        exitCode = 1;
      }

      String topologyTarget = restBase.host + " (sdk topology)";
      if (!isFull) {
        // Network mode: credential-free by design (matches the Go binary and
        // the Python probe) -- omit entirely, no line at all, not even SKIP.
      } else if (!hasCreds) {
        System.out.println(
            Shared.fragment(
                topologyTarget,
                "SKIP",
                "OK",
                "full mode requested but CAMUNDA_CLIENT_ID/CAMUNDA_CLIENT_SECRET are not set -- cannot run the "
                    + "authenticated newTopologyRequest() check"));
      } else {
        try {
          Topology topo = client.newTopologyRequest().send().join();
          int brokerCount = topo.getBrokers() != null ? topo.getBrokers().size() : -1;
          System.out.println(
              Shared.fragment(
                  topologyTarget,
                  "PASS",
                  "OK",
                  "SDK newTopologyRequest() succeeded, " + brokerCount + " broker(s)",
                  trustLabel));
        } catch (ClientHttpException e) {
          // 401 = a real, actionable auth failure (customer/config side) -> FAIL.
          // Any other non-200 status = reached the cluster edge, our side not
          // yours -> also FAIL (blocks training right now), but attribution
          // stays cluster-side (see IsOurClusterProblem/ExitOurClusterProblem
          // in the Go binary) -- same reasoning as the status check above.
          if (e.code() == 401) {
            System.out.println(
                Shared.fragment(
                    topologyTarget,
                    "FAIL",
                    "TOPOLOGY_AUTH_FAIL",
                    "authenticated topology request rejected (401): " + e,
                    trustLabel));
          } else {
            System.out.println(Shared.fragment(topologyTarget, "FAIL", "CLUSTER_EDGE_404", clusterEdgeDetail(e.code()), trustLabel));
          }
          exitCode = 1;
        } catch (ClientException e) {
          String[] classified = Shared.classifyTransportError(e.getCause() != null ? e.getCause() : e);
          System.out.println(Shared.fragment(topologyTarget, "FAIL", classified[0], classified[1], trustLabel));
          exitCode = 1;
        }
      }
    }

    return exitCode;
  }

  /** Builds the "reached the cluster edge, our side not yours" detail, mirroring
   * the Go binary's status.go CLUSTER_EDGE_404 message so both layers say the
   * same thing for the same situation. */
  private static String clusterEdgeDetail(int code) {
    return "reached the cluster edge (HTTP "
        + code
        + ") but got no valid cluster route -- this typically means our shared preflight cluster is paused "
        + "or in a transient edge blip, NOT a problem with your network. Re-run in ~5 minutes; if it persists, "
        + "contact the training team.";
  }

  /** Translates this tool's HTTPS_PROXY/HTTP_PROXY convention into the JVM
   * system properties Apache HttpClient5's useSystemProperties() reads
   * (https.proxyHost/https.proxyPort, http.proxyHost/http.proxyPort) -- the
   * real SDK does NOT read HTTP(S)_PROXY env vars at all (verified in
   * HttpClientFactory source). Also wires a default Authenticator for Basic
   * proxy auth if the URL carries userinfo, since JDK system properties have
   * no standard userinfo slot. */
  private static void applyProxySystemProperties(String proxyUrl) {
    URI uri = URI.create(proxyUrl);
    String host = uri.getHost();
    int port = uri.getPort() != -1 ? uri.getPort() : ("https".equals(uri.getScheme()) ? 443 : 80);
    // Apache HttpClient5's useSystemProperties() honors both http.* and
    // https.* proxy properties depending on the TARGET scheme (our target is
    // always https, but setting both is harmless and matches how most
    // real-world -D flags are set in practice).
    System.setProperty("https.proxyHost", host);
    System.setProperty("https.proxyPort", String.valueOf(port));
    System.setProperty("http.proxyHost", host);
    System.setProperty("http.proxyPort", String.valueOf(port));

    String userInfo = uri.getUserInfo();
    if (userInfo != null && !userInfo.isEmpty()) {
      int colon = userInfo.indexOf(':');
      String user = colon >= 0 ? userInfo.substring(0, colon) : userInfo;
      String pass = colon >= 0 ? userInfo.substring(colon + 1) : "";
      Authenticator.setDefault(
          new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
              if (getRequestorType() == RequestorType.PROXY) {
                return new PasswordAuthentication(user, pass.toCharArray());
              }
              return null;
            }
          });
    }
  }
}
