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
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
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

  private static final String USAGE =
      "DepCheck -- Maven dependency-resolution probe.\n"
          + "Opt-in: set CAMUNDA_MAVEN_DEPCHECK=1 (or pass --maven-depcheck). Needs Maven + a JDK.\n"
          + "Env: CAMUNDA_MAVEN_SETTINGS=<path>, CAMUNDA_MAVEN_MIRROR=<url>, CAMUNDA_MAVEN_CENTRAL_ONLY=1";

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
    String[] mvnVersion = runProcess(list(mvn, "-v"), 60);
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

    Path work = Files.createTempDirectory("c8-depcheck");
    try {
      Path pom = work.resolve("pom.xml");
      Files.write(pom, pomXml().getBytes(StandardCharsets.UTF_8));

      // Target strings are kept short and fixed ("training-deps (customer)"/
      // "(baseline)") rather than embedding the variable-length (potentially
      // unbounded -- a mirror URL or settings path) customerLabel, which
      // would overflow the column and misalign against every other Layer 2
      // line. The label still appears -- in Detail, which has no
      // column-width constraint.
      if (centralOnly) {
        LegResult central = resolveLeg(mvn, "central", pom, work, centralSettingsArgs(work));
        System.out.println(central.resolved
            ? Shared.fragment("training-deps (baseline)", "PASS", "OK",
                "all Camunda " + CAMUNDA_VERSION + " training artifacts resolve from Maven Central.")
            : Shared.fragment("training-deps (baseline)", "FAIL",
                central.errorClass,
                "cannot resolve the training artifacts from Maven Central -- " + central.detail));
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
      LegResult customer = resolveLeg(mvn, "customer", pom, work, customerSettings);

      if (customer.resolved) {
        // Kept short deliberately -- this ends up in the customer-facing
        // result, not just an engineering log. This check always does a
        // fresh fetch rather than trusting a local cache, so a PASS here
        // can't be a stale, cached false-green.
        System.out.println(Shared.fragment(
            "training-deps (customer)", "PASS", "OK",
            "all Camunda " + CAMUNDA_VERSION + " training artifacts resolve through " + customerLabel + "."));
        return 0;
      }

      // Customer leg FAILED -> run the Central baseline to isolate mirror vs network.
      LegResult central = resolveLeg(mvn, "central", pom, work, centralSettingsArgs(work));
      int rc = 1;
      if (central.resolved) {
        // Definitive corporate-mirror case: Central serves the same deps, the mirror doesn't.
        System.out.println(Shared.fragment(
            "training-deps (customer)", "FAIL", customer.errorClass,
            customerLabel + " could NOT resolve the Camunda training artifacts, but Maven CENTRAL "
                + "resolves the SAME artifacts fine -- so this is your corporate Maven mirror, NOT the "
                + "network or the cluster. " + customer.detail
                + " Give your IT/Maven-admin the mirror config; the training build will fail until the "
                + "mirror can serve io.camunda:*:" + CAMUNDA_VERSION + "."));
        System.out.println(Shared.fragment(
            "training-deps (baseline)", "PASS", "OK",
            "isolation reference: the same artifacts resolve from Maven Central."));
      } else {
        // Neither works -> network/proxy blocks Maven repos entirely.
        System.out.println(Shared.fragment(
            "training-deps (customer)", "FAIL", customer.errorClass,
            customerLabel + " could NOT resolve the Camunda training artifacts. " + customer.detail));
        System.out.println(Shared.fragment(
            "training-deps (baseline)", "FAIL", model(central.errorClass),
            "Maven Central is ALSO unreachable from here -- so this is the network/proxy blocking Maven "
                + "repositories, not just your mirror. " + central.detail));
      }
      return rc;
    } finally {
      deleteTree(work);
    }
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

  private static LegResult resolveLeg(String mvn, String leg, Path pom, Path work, List<String> settingsArgs)
      throws Exception {
    // Throwaway local repo per leg -- the whole point: forces a real fetch
    // every run so a warm ~/.m2 cache can't mask a broken remote.
    Path repo = work.resolve("repo-" + leg);
    List<String> cmd = list(mvn, "-B", "-ntp", "-f", pom.toString(),
        "dependency:go-offline", "-Dmaven.repo.local=" + repo.toString());
    cmd.addAll(settingsArgs);

    String[] res = runProcess(cmd, LEG_TIMEOUT_SECONDS);
    boolean ok = res[0].equals("0");
    if (ok) {
      return new LegResult(true, "OK", "");
    }
    boolean central = leg.equals("central");
    String errorClass = classify(res[1], central);
    String reason = firstErrorLine(res[1]);
    return new LegResult(false, errorClass, reason.isEmpty() ? "" : "First error: " + reason);
  }

  private static List<String> centralSettingsArgs(Path work) throws IOException {
    // Clean settings with NO mirrors, forced as BOTH user (-s) and global (-gs)
    // settings so a machine-global mirror can't sneak in -- a true Central baseline.
    Path clean = work.resolve("central-settings.xml");
    Files.write(clean, ("<settings xmlns=\"http://maven.apache.org/SETTINGS/1.0.0\">"
        + "<mirrors></mirrors><profiles></profiles></settings>").getBytes(StandardCharsets.UTF_8));
    return list("-s", clean.toString(), "-gs", clean.toString());
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
    boolean win = System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    // 1. PATH
    String[] onPath = win ? new String[] {"mvn.cmd", "mvn.bat", "mvn"} : new String[] {"mvn"};
    for (String c : onPath) {
      if (canRun(c)) return c;
    }
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

  private static boolean canRun(String cmd) {
    try {
      String[] r = runProcess(list(cmd, "-v"), 60);
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
   * A timeout or spawn failure returns a non-"0" exit and an explanatory output. */
  private static String[] runProcess(List<String> cmd, long timeoutSeconds) throws Exception {
    ProcessBuilder pb = new ProcessBuilder(cmd);
    pb.redirectErrorStream(true);
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
        }
      } catch (IOException ignored) {
      }
    });
    reader.setDaemon(true);
    reader.start();
    boolean finished = p.waitFor(timeoutSeconds, TimeUnit.SECONDS);
    if (!finished) {
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
    sb.append("<url>").append(xmlEscape(mirrorUrl)).append("</url><mirrorOf>*</mirrorOf>");
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

  private static String xmlEscape(String s) {
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
  }

  private static void deleteTree(Path dir) {
    if (dir == null) return;
    try {
      Files.walk(dir)
          .sorted(Comparator.reverseOrder())
          .forEach(p -> {
            try {
              Files.deleteIfExists(p);
            } catch (IOException ignored) {
            }
          });
    } catch (IOException ignored) {
    }
  }

  private DepCheck() {}
}
