import java.io.IOException;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Layer 2 Java Maven dependency-resolution probe.
 *
 * Catches the corporate-mirror failure case: a Nexus/Artifactory mirror
 * (`<mirrorOf>*</mirrorOf>` in settings.xml) that can't serve the Camunda 8.9
 * training artifacts -- missing, stale-pinned, or 401. The build dies at
 * dependency resolution, independent of cluster network/TLS: curl/openssl pass,
 * the transport probes pass, the training build is still broken. No amount of
 * CA/proxy fixing helps because it's a repository problem, not a TLS one.
 *
 * Emitted as a SECOND java-stack fragment (the trust probe is the first) via
 * the multi-fragment launcher read. Distinct from SdkProbe's
 * incidental Maven fetch: THIS probe uses a THROWAWAY local repo per run so a
 * warm ~/.m2 cache can't mask a broken remote (the cache-masks-the-test trap),
 * and it compares a Central baseline against the customer's real mirror to
 * ISOLATE blame -- which SdkProbe (real ~/.m2, single leg) cannot. SdkProbe's
 * verdict and THIS probe's customer-mirror leg must agree; this probe's overall
 * verdict is driven by the customer-mirror leg (the config the real build uses),
 * never by the Central-baseline leg (that's isolation detail, not a pass).
 *
 * Resolve-only (`dependency:go-offline`, full transitive tree), no compile.
 * Maven only.
 *
 * Env vars (forwarded by the Go launcher from its flags; also settable by hand
 * for a standalone run):
 *   CAMUNDA_MAVEN_DEPCHECK       opt-in trigger (1/true/yes) -- this check does
 *       real network fetches, so it is opt-in, same reasoning as SdkProbe's
 *       CAMUNDA_SDK_AUTO_INSTALL. Also implied when any --maven-* flag is set.
 *   CAMUNDA_MAVEN_SETTINGS       path to a settings.xml to use for the customer
 *       leg (else the machine's active settings are used).
 *   CAMUNDA_MAVEN_MIRROR         explicit mirror URL -> a mirrorOf=* settings is
 *       generated and used for the customer leg (overrides the active settings).
 *       Must be an https:// URL: mirrorOf=* also routes Maven's own plugin
 *       downloads through it, and Maven executes those jars (see
 *       rejectUnsafeMirror).
 *   CAMUNDA_MAVEN_CENTRAL_ONLY   (1/true/yes) run only the Central baseline.
 *   HTTPS_PROXY / HTTP_PROXY (or lowercase), NO_PROXY  written as &lt;proxies&gt;
 *       into the generated Central-baseline settings, since Maven never reads
 *       these env vars itself. The customer leg keeps the operator's own
 *       settings -- whether THOSE reach the repositories is what it tests.
 *   CAMUNDA_CA_CERTIFICATE_PATH / CAMUNDA_MTLS_CA_PATH / CAMUNDA_JAVA_TRUSTSTORE
 *       handed to every mvn run as a trust store via MAVEN_OPTS (see
 *       Shared.prepareMavenTrust), so a TLS-intercepting proxy's CA given to
 *       this tool also reaches Maven.
 *
 * Second mode, `DepCheck --fetch-sdk <dir>`: used by run.sh/run.cmd to fetch
 * the SDK jars for SdkProbe (see fetchSdk). Not opt-in gated -- the run
 * scripts decide whether to call it.
 *
 * Redaction: a customer settings.xml / mirror URL can carry <server> passwords
 * or user:pass@host. This probe NEVER dumps raw mvn output to stdout -- only a
 * short, classified summary, funneled through Shared.scrubUrlCreds like every
 * other fragment. Not implemented: surfacing the effective mirror block
 * (`help:effective-settings` prints server passwords).
 *
 * KNOWN LIMITS:
 *   - Maven discovery covers PATH, MAVEN_HOME/M2_HOME, and a project ./mvnw
 *     wrapper. The IDE-bundled (IntelliJ/JetBrains/NetBeans), package-manager
 *     (SDKMAN/Homebrew/Chocolatey/Scoop), and bundled-wrapper-last-resort
 *     discovery methods are NOT yet implemented -- if none of the covered
 *     locations has Maven, the probe SKIPs (with guidance), it does not fail.
 *   - Per-repo x per-artifact granularity is collapsed to per-leg (one
 *     go-offline over all three coords) -- a broken mirror fails the whole leg,
 *     which is the actionable signal; per-artifact attribution is not implemented.
 */
public final class DepCheck {

  // Training coordinates -- ONE place, bump per Camunda release.
  private static final String CAMUNDA_VERSION = "8.9.15";
  private static final String[] ARTIFACTS = {
    "io.camunda:camunda-spring-boot-starter:" + CAMUNDA_VERSION, // SB4
    "io.camunda:camunda-spring-boot-3-starter:" + CAMUNDA_VERSION, // SB3.5
    "io.camunda:camunda-client-java:" + CAMUNDA_VERSION, // plain client
  };

  private static final long LEG_TIMEOUT_SECONDS = 240;

  // The SDK fetch shares the launcher's per-stack time budget with the trust
  // probe and SdkProbe itself, so both attempts together must stay well
  // inside it.
  private static final long SDK_FETCH_TIMEOUT_SECONDS = 100;
  private static final long SDK_RETRY_TIMEOUT_SECONDS = 80;

  /** Exit code of --fetch-sdk when the fetch failed AND this process already
   * emitted the fragment saying so; the run scripts then add nothing. */
  static final int FETCH_FAILED_REPORTED = 2;

  private static final String USAGE =
      "DepCheck -- Maven dependency-resolution probe.\n"
          + "Opt-in: set CAMUNDA_MAVEN_DEPCHECK=1 (or pass --maven-depcheck). Needs Maven + a JDK.\n"
          + "Env: CAMUNDA_MAVEN_SETTINGS=<path>, CAMUNDA_MAVEN_MIRROR=<url>, CAMUNDA_MAVEN_CENTRAL_ONLY=1\n"
          + "Also: DepCheck --fetch-sdk <dir>  (SDK jar fetch used by run.sh/run.cmd)";

  public static void main(String[] args) {
    for (String a : args) {
      if (a.equals("-h") || a.equals("--help")) {
        System.err.println(USAGE);
        return;
      }
    }
    try {
      if (args.length == 2 && args[0].equals("--fetch-sdk")) {
        System.exit(fetchSdk(Paths.get(args[1])));
      }
      System.exit(run(args));
    } catch (Throwable t) {
      System.out.println(Shared.crashFragment(Shared.describeThrowable(t)));
      System.exit(1);
    }
  }

  private static boolean truthy(String v) {
    v = v == null ? "" : v.trim().toLowerCase(Locale.ROOT);
    return v.equals("1") || v.equals("true") || v.equals("yes");
  }

  private static int run(String[] args) throws Exception {
    String settingsPath = Shared.envOrEmpty("CAMUNDA_MAVEN_SETTINGS");
    String mirrorUrl = Shared.envOrEmpty("CAMUNDA_MAVEN_MIRROR");
    boolean centralOnly = truthy(System.getenv("CAMUNDA_MAVEN_CENTRAL_ONLY"));

    // Opt-in: the explicit env/flag, OR any --maven-* config being present
    // (providing config implies intent to run the check).
    boolean optedIn = truthy(System.getenv("CAMUNDA_MAVEN_DEPCHECK"))
        || !settingsPath.isEmpty() || !mirrorUrl.isEmpty() || centralOnly;
    for (String a : args) {
      if (a.equals("--maven-depcheck")) optedIn = true;
    }
    if (!optedIn) {
      // Kept short deliberately -- this ends up in the customer-facing
      // result, not just an engineering log. It's opt-in because it does real
      // network fetches, which shouldn't happen on every routine run.
      System.out.println(Shared.fragment(
          "maven-dependency-resolution", "SKIP", "OK",
          "check not run -- opt in with --maven-depcheck (or CAMUNDA_MAVEN_DEPCHECK=1)"));
      return 0;
    }

    String mvn = findMvn();
    if (mvn == null) {
      System.out.println(Shared.fragment(
          "maven-dependency-resolution", "SKIP", "OK",
          "Maven not found on PATH, MAVEN_HOME/M2_HOME, or a project ./mvnw wrapper -- cannot run the "
              + "dependency-resolution check. Install Maven (or run from a project that has the Maven "
              + "wrapper) and re-run."));
      return 0;
    }

    // Confirm this mvn can actually run (a JDK is reachable). Report the chosen
    // mvn + version for the operator.
    String[] mvnVersion = runProcess(list(mvn, "-v"), null, null, 60, false);
    String verExit = mvnVersion[0];
    String verOut = mvnVersion[1];
    if (!verExit.equals("0")) {
      String detail = looksLikeNoJdk(verOut)
          ? "Maven was found at " + mvn + " but has no usable JDK to run it -- set JAVA_HOME or put java "
              + "on PATH. (This is 'Maven found, no JDK', not a repository problem.)"
          : "Maven was found at " + mvn + " but `mvn -v` failed: " + firstLine(verOut);
      System.out.println(Shared.fragment("maven-dependency-resolution", "WARN", "CONFIG_ERROR", detail));
      return 0;
    }
    System.err.println("[java depcheck] using Maven: " + mvn + " | " + firstLine(verOut));

    Shared.MavenTrust trust = null;
    Path work = null;
    try {
      trust = Shared.prepareMavenTrust();
      work = Files.createTempDirectory("c8-depcheck");
      System.err.println("[java depcheck] Maven trust store: " + trust.label);
      if (trust.problem != null) {
        System.out.println(Shared.fragment(
            "maven-dependency-resolution", "WARN", "CONFIG_ERROR", trust.problem));
      }
      Map<String, String> env = trust.env();
      String proxyUrl = Shared.getProxyUrl();
      boolean proxied = !Shared.mavenProxiesXmlFromEnv().isEmpty();
      String centralLabel = proxied
          ? "Maven Central (through the proxy " + Shared.proxyDisplay(proxyUrl) + ")"
          : "Maven Central";
      String trustNote = trustNote(trust);

      Path pom = work.resolve("pom.xml");
      Files.write(pom, pomXml().getBytes(StandardCharsets.UTF_8));

      // Target strings are kept short and fixed ("training-deps (customer)"/
      // "(baseline)") rather than embedding the variable-length (potentially
      // unbounded -- a mirror URL or settings path) customerLabel, which
      // would overflow the column and misalign against every other Layer 2
      // line. The label still appears -- in Detail, which has no
      // column-width constraint.
      if (centralOnly) {
        LegResult central = resolveLeg(mvn, "central", pom, work, centralSettingsArgs(work), env, trust);
        System.out.println(central.resolved
            ? Shared.fragment("training-deps (baseline)", "PASS", "OK",
                "all Camunda " + CAMUNDA_VERSION + " training artifacts resolve from " + centralLabel + "."
                    + trustNote)
            : Shared.fragment("training-deps (baseline)", "FAIL",
                central.errorClass,
                "cannot resolve the training artifacts from " + centralLabel + " -- " + central.detail
                    + trustNote));
        return central.resolved ? 0 : 1;
      }

      // --- Customer leg (the config their real build uses) ---
      // An explicit mirror is only usable if it is an https:// URL -- see
      // rejectUnsafeMirror. A rejected mirror stops the check here rather than
      // quietly falling back to a different config, which would report a
      // verdict for something other than what the operator asked to test.
      if (!mirrorUrl.isEmpty()) {
        String mirrorRejection = rejectUnsafeMirror(mirrorUrl);
        if (mirrorRejection != null) {
          System.out.println(Shared.fragment(
              "maven-dependency-resolution", "WARN", "CONFIG_ERROR", mirrorRejection));
          return 0;
        }
      }
      List<String> customerSettings = customerSettingsArgs(work, settingsPath, mirrorUrl);
      String customerLabel = mirrorUrl.isEmpty()
          ? (settingsPath.isEmpty() ? "your active Maven settings" : "your Maven settings " + settingsPath)
          : "your mirror " + Shared.scrubUrlCreds(mirrorUrl);
      LegResult customer = resolveLeg(mvn, "customer", pom, work, customerSettings, env, trust);

      if (customer.resolved) {
        // Kept short deliberately -- this ends up in the customer-facing
        // result, not just an engineering log. This check always does a
        // fresh fetch rather than trusting a local cache, so a PASS here
        // can't be a stale, cached false-green.
        System.out.println(Shared.fragment(
            "training-deps (customer)", "PASS", "OK",
            "all Camunda " + CAMUNDA_VERSION + " training artifacts resolve through " + customerLabel + "."
                + trustNote + ownBuildTrustNote(trust)));
        return 0;
      }

      // The customer leg runs on the operator's own settings, so the proxy
      // given to this tool never reached it -- Maven does not read
      // HTTPS_PROXY. Said explicitly whenever a proxy is configured, because
      // "the proxy works for everything else" is the natural assumption.
      String proxyNote = "";
      if (proxyUrl != null) {
        proxyNote = mirrorUrl.isEmpty()
            ? " Note: the proxy given to this tool (--proxy / HTTPS_PROXY) is NOT passed to Maven for "
                + "this check -- Maven never reads HTTPS_PROXY, it only uses a <proxies> entry in its "
                + "settings.xml (usually ~/.m2/settings.xml). If Maven must go through that proxy, add one "
                + "there."
            : " Note: this check contacts the mirror WITHOUT the proxy given to this tool (--proxy / "
                + "HTTPS_PROXY). If the mirror is only reachable through that proxy, re-run with "
                + "--maven-settings pointing at a settings.xml that has both the mirror and a <proxies> "
                + "entry.";
      }

      // Customer leg FAILED -> run the Central baseline to isolate mirror vs network.
      LegResult central = resolveLeg(mvn, "central", pom, work, centralSettingsArgs(work), env, trust);
      int rc = 1;
      if (central.resolved) {
        String cause = proxied
            ? "so the network can reach Maven repositories through that proxy, and the problem is your "
                + "Maven configuration, NOT the cluster: either it lacks a <proxies> entry for the proxy, or "
                + "your corporate Maven mirror cannot serve the artifacts. "
            : "so this is your corporate Maven mirror, NOT the network or the cluster. ";
        System.out.println(Shared.fragment(
            "training-deps (customer)", "FAIL", customer.errorClass,
            customerLabel + " could NOT resolve the Camunda training artifacts, but " + centralLabel
                + " resolves the SAME artifacts fine -- " + cause + customer.detail
                + (proxied
                    ? " The training build will fail until " + customerLabel + " can resolve io.camunda:*:"
                    : " Give your IT/Maven-admin the mirror config; the training build will fail until the "
                        + "mirror can serve io.camunda:*:")
                + CAMUNDA_VERSION + "." + proxyNote + trustNote));
        System.out.println(Shared.fragment(
            "training-deps (baseline)", "PASS", "OK",
            "isolation reference: the same artifacts resolve from " + centralLabel + "."));
      } else {
        // Neither works -> network/proxy blocks Maven repos entirely.
        System.out.println(Shared.fragment(
            "training-deps (customer)", "FAIL", customer.errorClass,
            customerLabel + " could NOT resolve the Camunda training artifacts. " + customer.detail
                + proxyNote + trustNote));
        System.out.println(Shared.fragment(
            "training-deps (baseline)", "FAIL", model(central.errorClass),
            centralLabel + " is ALSO unreachable from here -- so this is the network/proxy blocking "
                + "Maven repositories, not just your mirror. " + central.detail));
      }
      return rc;
    } finally {
      Shared.deleteTree(work);
      if (trust != null) {
        trust.cleanup();
      }
    }
  }

  /** " Maven ran with ... as its trust store." when this check handed Maven a
   * trust store of its own, else "" -- the default needs no mention. */
  private static String trustNote(Shared.MavenTrust trust) {
    return trust.isCustom() ? " Maven ran with " + trust.label + " as its trust store." : "";
  }

  /** A PASS that relied on a trust store this check handed Maven says nothing
   * about the operator's own builds, which run without it. */
  private static String ownBuildTrustNote(Shared.MavenTrust trust) {
    return trust.isCustom()
        ? " Your own Maven builds need the same CA: import it into the cacerts of the JDK Maven runs on "
            + "(keytool -importcert -cacerts), or point MAVEN_OPTS at a trust store with "
            + "-Djavax.net.ssl.trustStore."
        : "";
  }

  /** Central-leg errorClass is always a Central-unreachable flavor regardless of
   * the raw classification, since the baseline only fails when Central itself
   * can't be reached. */
  private static String model(String errorClass) {
    return "MAVEN_CENTRAL_UNREACHABLE";
  }

  private static final class LegResult {
    final boolean resolved;
    final String errorClass;
    final String detail;

    LegResult(boolean resolved, String errorClass, String detail) {
      this.resolved = resolved;
      this.errorClass = errorClass;
      this.detail = detail;
    }
  }

  private static LegResult resolveLeg(String mvn, String leg, Path pom, Path work, List<String> settingsArgs,
      Map<String, String> env, Shared.MavenTrust trust) throws Exception {
    // Throwaway local repo per leg -- the whole point: forces a real fetch
    // every run so a warm ~/.m2 cache can't mask a broken remote.
    Path repo = work.resolve("repo-" + leg);
    List<String> cmd = list(mvn, "-B", "-ntp", "-f", pom.toString(),
        "dependency:go-offline", "-Dmaven.repo.local=" + repo.toString());
    cmd.addAll(settingsArgs);

    String[] res = runProcess(cmd, null, env, LEG_TIMEOUT_SECONDS, false);
    boolean ok = res[0].equals("0");
    if (ok) {
      return new LegResult(true, "OK", "");
    }
    boolean central = leg.equals("central");
    String errorClass = classify(res[1], central);
    String reason = failureReason(res);
    return new LegResult(false, errorClass,
        (reason.isEmpty() ? "" : "First error: " + reason) + pkixHint(res[1], trust)
            + (central ? "" : Shared.mavenProxyAuthHint(res[1])));
  }

  /** Extra guidance when Maven failed on certificate trust: the JDK's PKIX
   * message alone does not say that a TLS-intercepting proxy is the usual
   * cause, nor that --trust-ca reaches Maven too. */
  static String pkixHint(String output, Shared.MavenTrust trust) {
    String t = output == null ? "" : output.toLowerCase(Locale.ROOT);
    if (!t.contains("pkix") && !t.contains("unable to find valid certification path")) {
      return "";
    }
    return trust.isCustom()
        ? " Maven did not trust a TLS certificate it was shown, even with " + trust.label
            + " -- check that this is the root CA the intercepting proxy actually signs with."
        : " Maven did not trust a TLS certificate it was shown -- typical behind a TLS-intercepting "
            + "proxy. Re-run with --trust-ca <the proxy's root CA, PEM>: this check then hands Maven that "
            + "CA in addition to the JDK's default ones.";
  }

  private static List<String> centralSettingsArgs(Path work) throws IOException {
    // Clean settings with NO mirrors, forced as BOTH user (-s) and global (-gs)
    // settings so a machine-global mirror can't sneak in -- a true Central
    // baseline. The proxy from HTTPS_PROXY/HTTP_PROXY is written in as
    // <proxies>: Maven ignores those env vars, so without this the baseline
    // would always fail on a network whose only way out is that proxy.
    Path clean = work.resolve("central-settings.xml");
    Files.write(clean, Shared.centralSettingsXml(Shared.mavenProxiesXmlFromEnv())
        .getBytes(StandardCharsets.UTF_8));
    List<String> args = list("-s", clean.toString(), "-gs", clean.toString());
    args.addAll(Shared.mavenProxyAuthTransportArgs());
    return args;
  }

  /** --fetch-sdk: copies camunda-client-java and its dependencies into
   * &lt;dir&gt;/lib for SdkProbe, from the pom.xml the run script wrote there.
   *
   * <p>First attempt: the operator's own Maven settings, as their real builds
   * resolve. If that fails and a proxy is configured (HTTPS_PROXY/HTTP_PROXY,
   * which is how the launcher forwards --proxy), one retry with plain Maven
   * Central settings plus that proxy: Maven does not read the env vars, so on
   * a network whose only way out is that proxy the first attempt cannot work
   * unless the operator's settings.xml already names it. A retry that
   * succeeds is still reported (WARN), because the operator's own builds will
   * keep failing the way the first attempt did.
   *
   * <p>Both attempts get the trust store from Shared.prepareMavenTrust.
   * Maven's output goes to stderr only. Returns 0 when the jars were fetched,
   * FETCH_FAILED_REPORTED when not (the fragment saying so is already on
   * stdout). */
  static int fetchSdk(Path sdkDir) throws Exception {
    String mvn = findMvnOnPath();
    if (mvn == null) {
      mvn = Shared.isWindows() ? "mvn.cmd" : "mvn";
    }
    String coord = "io.camunda:camunda-client-java:" + CAMUNDA_VERSION;
    Shared.MavenTrust trust = null;
    Path work = null;
    try {
      trust = Shared.prepareMavenTrust();
      System.err.println("[java sdk-probe] Maven trust store: " + trust.label);
      if (trust.problem != null) {
        System.out.println(Shared.fragment(
            "maven-dependency-resolution", "WARN", "CONFIG_ERROR", trust.problem));
      }
      Map<String, String> env = trust.env();
      List<String> base = list(mvn, "-q", "-B", "dependency:copy-dependencies", "-DoutputDirectory=lib");

      String[] first = runProcess(base, sdkDir, env, SDK_FETCH_TIMEOUT_SECONDS, true);
      if (first[0].equals("0")) {
        return 0;
      }
      String firstError = failureReason(first);
      String trustNote = trustNote(trust);
      String notMissingMaven = "Maven is installed and ran but could NOT resolve " + coord
          + " -- this is NOT a missing-Maven problem.";

      String proxyUrl = Shared.getProxyUrl();
      String proxiesXml = Shared.mavenProxiesXmlFromEnv();
      if (proxiesXml.isEmpty()) {
        String unusable = proxyUrl == null ? "" : " The proxy URL from --proxy / HTTPS_PROXY could not "
            + "be read as host:port, so no retry through it was attempted.";
        System.out.println(Shared.fragment(
            "maven-dependency-resolution", "WARN", "MAVEN_RESOLVE_FAIL",
            notMissingMaven + " Likely a corporate Maven mirror such as Nexus or Artifactory that cannot "
                + "serve the Camunda artifacts -- missing, stale, or 401 -- or a proxy blocking Maven "
                + "Central. This blocks building the training exercises regardless of cluster "
                + "connectivity." + (firstError.isEmpty() ? "" : " First error: " + firstError)
                + pkixHint(first[1], trust) + unusable + trustNote
                + " See the mvn output on stderr; run the dedicated Maven dependency-resolution check "
                + "(--maven-depcheck) to isolate Central vs mirror."));
        return FETCH_FAILED_REPORTED;
      }

      String scrubbedProxy = Shared.proxyDisplay(proxyUrl);
      work = Shared.createMavenTempDir("c8-sdk-fetch");
      Path settings = work.resolve("settings.xml");
      Files.write(settings, Shared.centralSettingsXml(proxiesXml).getBytes(StandardCharsets.UTF_8));
      System.err.println("[java sdk-probe] Maven could not resolve with your own settings; retrying once "
          + "with plain Maven Central settings through the proxy " + scrubbedProxy + "...");
      List<String> retry = new ArrayList<>(base);
      retry.addAll(list("-s", settings.toString(), "-gs", settings.toString()));
      retry.addAll(Shared.mavenProxyAuthTransportArgs());
      String[] second = runProcess(retry, sdkDir, env, SDK_RETRY_TIMEOUT_SECONDS, true);

      String withOwnSettings = (firstError.isEmpty() ? "" : " First error with your settings: " + firstError)
          + Shared.mavenProxyAuthHint(first[1]);
      if (second[0].equals("0")) {
        System.out.println(Shared.fragment(
            "maven-dependency-resolution", "WARN", "MAVEN_RESOLVE_FAIL",
            "Maven could NOT resolve " + coord + " with your own Maven settings; it only worked after this "
                + "tool gave Maven the proxy " + scrubbedProxy + " together with plain Maven Central "
                + "settings. Maven never reads --proxy or HTTPS_PROXY, so your own builds -- including the "
                + "training exercises -- will fail the same way until your settings.xml (usually "
                + "~/.m2/settings.xml) has a <proxies> entry for this proxy, or your corporate mirror is "
                + "reachable." + withOwnSettings + trustNote));
        return 0;
      }
      String secondError = failureReason(second);
      System.out.println(Shared.fragment(
          "maven-dependency-resolution", "WARN", "MAVEN_RESOLVE_FAIL",
          notMissingMaven + " It failed with your own Maven settings, AND again with plain Maven Central "
              + "settings through the proxy " + scrubbedProxy + " -- so the proxy does not let Maven reach "
              + "Maven Central either: it may block or require other credentials for "
              + "repo.maven.apache.org, or intercept TLS with a CA Maven does not trust. This blocks "
              + "building the training exercises regardless of cluster connectivity." + withOwnSettings
              + (secondError.isEmpty() ? "" : " First error through the proxy: " + secondError)
              + pkixHint(first[1] + "\n" + second[1], trust) + trustNote
              + " See the mvn output on stderr."));
      return FETCH_FAILED_REPORTED;
    } finally {
      Shared.deleteTree(work);
      if (trust != null) {
        trust.cleanup();
      }
    }
  }

  /** Rejects a CAMUNDA_MAVEN_MIRROR value that must not be pointed at.
   *
   * <p>Returns null when the value is usable, otherwise the operator-facing
   * detail explaining why it was not used.
   *
   * <p>The generated settings use mirrorOf=*, which routes ALL Maven traffic
   * through the given URL -- including Maven's own build plugins
   * (maven-dependency-plugin and its dependencies), which Maven then executes.
   * Each leg also uses a throwaway -Dmaven.repo.local, so nothing is cached and
   * every run re-downloads those plugin jars. Over plaintext http:// that is
   * executable code fetched on an unprotected connection, on exactly the kind
   * of network this tool is run on when something is wrong with it: anyone on
   * the path can substitute a modified jar. The value is also written verbatim
   * into a generated settings.xml, so a value that isn't a URL at all is
   * rejected rather than interpolated. */
  private static String rejectUnsafeMirror(String mirrorUrl) {
    URI u;
    try {
      u = new URI(mirrorUrl);
    } catch (URISyntaxException e) {
      return "the Maven mirror URL (--maven-mirror / CAMUNDA_MAVEN_MIRROR) is not a valid URL, so it was "
          + "NOT used and the mirror check did not run: " + mirrorUrl + " -- check for stray spaces, "
          + "quotes or backslashes, then re-run with the mirror's full https:// URL.";
    }
    String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase(Locale.ROOT);
    if (scheme.equals("https")) {
      if (u.getHost() == null || u.getHost().isEmpty()) {
        return "the Maven mirror URL (--maven-mirror / CAMUNDA_MAVEN_MIRROR) has no host, so it was NOT "
            + "used and the mirror check did not run: " + mirrorUrl + " -- re-run with the mirror's full "
            + "https:// URL, for example https://nexus.example.com/repository/maven-public/.";
      }
      return null;
    }
    if (scheme.equals("http")) {
      return "the Maven mirror URL (--maven-mirror / CAMUNDA_MAVEN_MIRROR) is a plaintext http:// URL, so "
          + "it was NOT used and the mirror check did not run: " + mirrorUrl + " -- testing a mirror "
          + "points Maven at it for EVERYTHING, including Maven's own build plugins, which Maven "
          + "downloads and then EXECUTES on this machine. Over http:// that download is unprotected and "
          + "anyone on the network path can replace it with modified code. Re-run with the mirror's "
          + "https:// URL. If the mirror only serves http, run --maven-settings <your settings.xml> "
          + "instead (it resolves through whatever your real build uses, without this tool pointing "
          + "every request at one plaintext host), or --maven-central-only for the Maven Central "
          + "baseline alone.";
    }
    return "the Maven mirror URL (--maven-mirror / CAMUNDA_MAVEN_MIRROR) is not an https:// URL, so it "
        + "was NOT used and the mirror check did not run: " + mirrorUrl + " -- re-run with the mirror's "
        + "full URL including the https:// scheme, for example "
        + "https://nexus.example.com/repository/maven-public/.";
  }

  private static List<String> customerSettingsArgs(Path work, String settingsPath, String mirrorUrl)
      throws IOException {
    if (!mirrorUrl.isEmpty()) {
      // Explicit mirror override: generate a mirrorOf=* settings pointing at it,
      // and force a clean global settings so only this mirror applies.
      // Callers reach here only for a mirror rejectUnsafeMirror() accepted.
      Path clean = work.resolve("clean-global.xml");
      Files.write(clean, ("<settings><mirrors></mirrors></settings>").getBytes(StandardCharsets.UTF_8));
      Path m = work.resolve("mirror-settings.xml");
      Files.write(m, mirrorSettingsXml(mirrorUrl).getBytes(StandardCharsets.UTF_8));
      return list("-s", m.toString(), "-gs", clean.toString());
    }
    if (!settingsPath.isEmpty()) {
      return list("-s", settingsPath); // no -gs: machine global still applies with the given user settings
    }
    return new ArrayList<>(); // machine's active settings (user + global) -- their real build path
  }

  /** Classify a failed leg's mvn output into a stable errorClass. Text matching
   * (not exit-code) because mvn collapses everything to exit 1; the wording is
   * what distinguishes 401 vs 404 vs unreachable. */
  private static String classify(String output, boolean central) {
    String t = output.toLowerCase(Locale.ROOT);
    if (t.contains("status code: 401") || t.contains("unauthorized")
        || t.contains("authentication failed") || t.contains("not authorized")) {
      return central ? "MAVEN_CENTRAL_UNREACHABLE" : "MAVEN_MIRROR_AUTH";
    }
    if (t.contains("could not find artifact") || t.contains("was not found")
        || t.contains("status code: 404") || t.contains("could not resolve dependencies")) {
      return "MAVEN_ARTIFACT_MISSING";
    }
    if (t.contains("could not transfer") || t.contains("connection refused")
        || t.contains("connect timed out") || t.contains("connection timed out")
        || t.contains("unknownhost") || t.contains("unknown host") || t.contains("no route to host")
        || t.contains("transfer failed") || t.contains("unable to connect")) {
      return central ? "MAVEN_CENTRAL_UNREACHABLE" : "MAVEN_MIRROR_UNREACHABLE";
    }
    return central ? "MAVEN_CENTRAL_UNREACHABLE" : "MAVEN_MIRROR_UNREACHABLE";
  }

  // ---- Maven discovery (PATH, MAVEN_HOME/M2_HOME, project ./mvnw) ----

  private static String findMvn() {
    boolean win = Shared.isWindows();
    // 1. PATH
    String onPath = findMvnOnPath();
    if (onPath != null) return onPath;
    // 2. MAVEN_HOME / M2_HOME
    for (String envName : new String[] {"MAVEN_HOME", "M2_HOME"}) {
      String home = Shared.envOrEmpty(envName);
      if (!home.isEmpty()) {
        String bin = home + "/bin/" + (win ? "mvn.cmd" : "mvn");
        if (Files.isRegularFile(Paths.get(bin)) && canRun(bin)) return bin;
      }
    }
    // 3. Project wrapper ./mvnw (most faithful: pinned Maven version)
    String wrapper = win ? "mvnw.cmd" : "./mvnw";
    Path wp = Paths.get(win ? "mvnw.cmd" : "mvnw");
    if (Files.isRegularFile(wp) && canRun(wrapper)) return wrapper;
    return null;
  }

  /** The Maven on PATH, as the run scripts' own `mvn` lookup finds it. */
  private static String findMvnOnPath() {
    String[] onPath = Shared.isWindows() ? new String[] {"mvn.cmd", "mvn.bat", "mvn"} : new String[] {"mvn"};
    for (String c : onPath) {
      if (canRun(c)) return c;
    }
    return null;
  }

  private static boolean canRun(String cmd) {
    try {
      String[] r = runProcess(list(cmd, "-v"), null, null, 60, false);
      return r[0].equals("0");
    } catch (Exception e) {
      return false;
    }
  }

  private static boolean looksLikeNoJdk(String out) {
    String t = out.toLowerCase(Locale.ROOT);
    return t.contains("java_home") || t.contains("no compiler") || t.contains("jre")
        || t.contains("cannot find") && t.contains("java");
  }

  // ---- process + fs helpers ----

  /** Runs a command, merging stderr into stdout. Returns {exitCodeAsString, output}.
   * A timeout or spawn failure returns a non-"0" exit and an explanatory output.
   *
   * <p>dir: working directory (null = inherit). env: variables to set on top
   * of the inherited environment (null/empty = none). echoToStderr: also
   * stream the output to this process's stderr as it arrives -- stdout is the
   * fragment channel, so child output must never reach it. */
  private static String[] runProcess(List<String> cmd, Path dir, Map<String, String> env, long timeoutSeconds,
      boolean echoToStderr) throws Exception {
    ProcessBuilder pb = new ProcessBuilder(cmd);
    pb.redirectErrorStream(true);
    if (dir != null) {
      pb.directory(dir.toFile());
    }
    if (env != null) {
      pb.environment().putAll(env);
    }
    Process p;
    try {
      p = pb.start();
    } catch (IOException e) {
      return new String[] {"127", "could not start process: " + e.getMessage()};
    }
    ByteArrayOutputStream buf = new ByteArrayOutputStream();
    Thread reader = new Thread(() -> {
      try (InputStream in = p.getInputStream()) {
        byte[] b = new byte[8192];
        int n;
        while ((n = in.read(b)) != -1) {
          buf.write(b, 0, n);
          if (echoToStderr) {
            System.err.write(b, 0, n);
            System.err.flush();
          }
        }
      } catch (IOException ignored) {
      }
    });
    reader.setDaemon(true);
    reader.start();
    boolean finished = p.waitFor(timeoutSeconds, TimeUnit.SECONDS);
    if (!finished) {
      // mvn is a launcher script (mvn.cmd / a shell script) that starts the
      // real JVM as a child, so killing only the direct child would leave
      // Maven itself running.
      p.descendants().forEach(ProcessHandle::destroyForcibly);
      p.destroyForcibly();
      reader.join(2000);
      return new String[] {"124", "timed out after " + timeoutSeconds + "s\n"
          + new String(buf.toByteArray(), StandardCharsets.UTF_8)};
    }
    reader.join(2000);
    return new String[] {Integer.toString(p.exitValue()),
        new String(buf.toByteArray(), StandardCharsets.UTF_8)};
  }

  private static List<String> list(String... items) {
    List<String> l = new ArrayList<>();
    for (String i : items) l.add(i);
    return l;
  }

  private static String firstLine(String s) {
    if (s == null) return "";
    int nl = s.indexOf('\n');
    return Shared.scrubUrlCreds((nl < 0 ? s : s.substring(0, nl)).trim());
  }

  /** Why a runProcess result failed, for a fragment detail: a timeout said as
   * such (a killed mvn leaves no [ERROR] line to quote), else the first mvn
   * error line. */
  private static String failureReason(String[] res) {
    if (res[0].equals("124")) {
      return firstLine(res[1]).replace("timed out", "Maven did not finish, timed out");
    }
    return firstErrorLine(res[1]);
  }

  /** First line that looks like an mvn error, scrubbed of any credentials. */
  private static String firstErrorLine(String out) {
    if (out == null) return "";
    for (String line : out.split("\n")) {
      String l = line.trim();
      String lower = l.toLowerCase(Locale.ROOT);
      if (lower.startsWith("[error]") || lower.contains("could not")
          || lower.contains("failed to") || lower.contains("transfer failed")) {
        // Trim the noisy "[ERROR] " prefix; cap length; scrub creds.
        String cleaned = l.replaceFirst("(?i)^\\[error\\]\\s*", "");
        if (cleaned.length() > 300) cleaned = cleaned.substring(0, 300) + "...";
        return Shared.scrubUrlCreds(cleaned);
      }
    }
    return "";
  }

  private static String pomXml() {
    StringBuilder sb = new StringBuilder();
    sb.append("<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n");
    sb.append("  <modelVersion>4.0.0</modelVersion>\n");
    sb.append("  <groupId>local</groupId><artifactId>c8-depcheck</artifactId><version>1.0</version>\n");
    sb.append("  <dependencies>\n");
    for (String a : ARTIFACTS) {
      String[] gav = a.split(":");
      sb.append("    <dependency><groupId>").append(gav[0]).append("</groupId>")
          .append("<artifactId>").append(gav[1]).append("</artifactId>")
          .append("<version>").append(gav[2]).append("</version></dependency>\n");
    }
    sb.append("  </dependencies>\n");
    sb.append("</project>\n");
    return sb.toString();
  }

  /** Settings for the explicit-mirror leg: a mirrorOf=* mirror at the given URL,
   * plus a repository/pluginRepository pair carrying
   * <code>&lt;checksumPolicy&gt;fail&lt;/checksumPolicy&gt;</code>.
   *
   * <p>checksumPolicy is a repository property, not a mirror property, so it has
   * to be attached to repository definitions: `central` is redefined here (for
   * both regular artifacts and plugins) with the strict policy, and the
   * mirrorOf=* mirror then serves it. Maven's default policy is `warn`, which
   * downloads and uses an artifact whose checksum does not match and only
   * prints a warning; `fail` makes the build stop instead. The URL is escaped
   * for XML by xmlEscape -- a mirror URL can legitimately contain `&amp;`. */
  private static String mirrorSettingsXml(String mirrorUrl) {
    StringBuilder sb = new StringBuilder();
    sb.append("<settings xmlns=\"http://maven.apache.org/SETTINGS/1.0.0\">");
    sb.append("<mirrors><mirror>");
    sb.append("<id>c8-explicit-mirror</id><name>c8-explicit</name>");
    sb.append("<url>").append(Shared.xmlEscape(mirrorUrl)).append("</url><mirrorOf>*</mirrorOf>");
    sb.append("</mirror></mirrors>");
    sb.append("<profiles><profile><id>c8-strict-checksums</id>");
    sb.append("<repositories>");
    sb.append(strictRepoBody("repository"));
    sb.append("</repositories>");
    sb.append("<pluginRepositories>");
    sb.append(strictRepoBody("pluginRepository"));
    sb.append("</pluginRepositories>");
    sb.append("</profile></profiles>");
    sb.append("<activeProfiles><activeProfile>c8-strict-checksums</activeProfile></activeProfiles>");
    sb.append("</settings>");
    return sb.toString();
  }

  /** One `central` (plugin)repository definition with strict checksums. The URL
   * is Central's, but every request is redirected by the mirrorOf=* mirror
   * above -- the definition exists to carry the checksum policy. */
  private static String strictRepoBody(String element) {
    return "<" + element + ">"
        + "<id>central</id><name>c8-depcheck-central</name>"
        + "<releases><enabled>true</enabled><checksumPolicy>fail</checksumPolicy></releases>"
        + "<snapshots><enabled>false</enabled><checksumPolicy>fail</checksumPolicy></snapshots>"
        + "<url>https://repo.maven.apache.org/maven2</url>"
        + "</" + element + ">";
  }

  private DepCheck() {}
}
