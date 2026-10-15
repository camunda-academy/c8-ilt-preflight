#!/usr/bin/env node
'use strict';
/**
 * Layer 2 SDK-snippet confirmation -- TypeScript/Node.js (tier 2).
 *
 * Standalone: node preflight/layer2/typescript/probe_sdk.js
 * Requires the real Camunda TypeScript SDK, @camunda8/orchestration-cluster-api
 * -- this is the "literal SDK connects + gets topology" real confirmation,
 * catching proxy-handling/config issues the SDK-free native probe (probe.js)
 * can't. probe.js's trust check is still the mandatory tier; this is the
 * recommended, richer confirmation once the SDK is present.
 *
 * ---------------------------------------------------------------------------
 * Package/version, verified against the npm registry + the published
 * tarball, NOT assumed:
 *
 *  - The package name is correct -- @camunda8/orchestration-cluster-api
 *    really is the current Camunda 8 TypeScript/Node SDK
 *    (github.com/camunda/orchestration-cluster-api-js), confirmed via
 *    `GET https://registry.npmjs.org/@camunda8/orchestration-cluster-api`.
 *  - A version RANGE (e.g. "^9") is deliberately avoided here: this
 *    project's security policy forbids ranges for auto-install (a range lets
 *    a future compromised release in silently -- same reasoning as Python's
 *    exact SDK_VERSION pin). The registry exposes three dist-tags:
 *    "8-stable" (8.8.5), "latest" (9.1.4, the current stable release), and
 *    "alpha" (10.0.0-alpha.27, prerelease, not used). Pinned exactly to
 *    9.1.4 below.
 *  - The SDK's major version tracks the Camunda SERVER's minor version
 *    (SDK 9.y.z <-> Camunda 8.9 -- see the package's own README), so 9.1.4 is
 *    the right major for this project's target server line.
 *  - package.json declares "engines": {"node": ">=22"}, but the README says
 *    "Node 20+ (native fetch & File)" -- the two disagree. engines.node is
 *    npm's own install-time-enforced contract, so treat Node 22+ as the real
 *    requirement.
 *
 * Supply-chain note: this directory ships a package.json pinning the EXACT
 * version plus a package-lock.json with npm's integrity hashes (generated
 * once via `npm install`, committed to the repo) -- auto-install below uses
 * `npm ci`, which refuses to install anything whose resolved tarball hash
 * doesn't match the lockfile. This is
 * actually STRONGER supply-chain protection than Python's probe (which needs
 * an optional, separately-generated per-platform requirements.lock to get an
 * equivalent guarantee) -- npm's lockfile-and-integrity mechanism is
 * standard, not a bolt-on.
 *
 * Auto-install (ON by default -- same as Python's pip install and Java's Maven
 * fetch: this tier answers "can the real SDK reach the cluster", and a tier
 * that silently SKIPs answers nothing; a SKIP sitting among PASS lines reads
 * as "fine" to a participant scanning the output. The cost is an `npm ci` on
 * first run, which on a blocked network fails fast and is itself diagnostic):
 *   `npm ci` runs in this directory (using the committed lockfile) if the SDK
 *   isn't already resolvable, then this proceeds. --no-install, or
 *   CAMUNDA_SDK_AUTO_INSTALL=0, opts out for a machine where writing into
 *   node_modules is unwanted; the Go binary spells the same thing
 *   --no-sdk-install. If installation is disabled or fails, this emits a SKIP
 *   fragment with the manual install command -- the native probe's fragments
 *   (from probe.js) still cover the mandatory trust check either way.
 *
 * ---------------------------------------------------------------------------
 * Trust-store nuance, read from the SDK's own published source
 * (dist/chunk-4NRTES5E.js in the 9.1.4 tarball): every request goes through
 * `opts.fetch ?? globalThis.fetch`, i.e. Node's built-in fetch (undici), which
 * verifies against Node's default root certificates plus whatever
 * NODE_EXTRA_CA_CERTS added at process start.
 *
 * The SDK's OWN custom-CA setting does not take effect. When
 * CAMUNDA_MTLS_CA_PATH (or the sibling _CA/_CERT_PATH/_KEY_PATH vars) is set,
 * the SDK builds `new https.Agent({ca, cert, key})` and passes it to fetch as
 * `{agent}` -- but `agent` is a node:https option that Node's built-in fetch
 * does not know and silently ignores. The CA (and any client certificate) is
 * therefore never applied: behind a TLS-intercepting proxy the SDK's requests
 * fail certificate verification exactly as if CAMUNDA_MTLS_CA_PATH were unset.
 *
 * What does work for a real application is NODE_EXTRA_CA_CERTS, which Node
 * reads once at startup and APPENDS to its default root store for every TLS
 * connection, fetch included. So this check exercises that route: run.sh/
 * run.cmd start this file with NODE_EXTRA_CA_CERTS set to CAMUNDA_MTLS_CA_PATH
 * (unless the environment already carries its own NODE_EXTRA_CA_CERTS, which
 * is then left alone -- Node accepts a single file, and silently replacing the
 * user's choice would test a setup they don't have). Whenever a custom CA is
 * configured, this probe also emits a config note telling the user that
 * CAMUNDA_MTLS_CA_PATH alone does nothing for this SDK and NODE_EXTRA_CA_CERTS
 * is what their app needs. probe.js's tier-1 handshake is a separate thing: it
 * passes the CA straight to tls.connect({ca}), which does apply it.
 *
 * Proxy-support note (see installProxyDispatcher's and detectNodeEnvProxy's
 * doc comments for the details): the SDK has no proxy handling of its own --
 * it never reads HTTP(S)_PROXY. Whether its requests go through a proxy is
 * decided entirely by the fetch underneath it:
 *  - By default Node's fetch ignores HTTP(S)_PROXY and connects direct, so an
 *    unmodified app bypasses a configured --proxy. This probe mirrors that and
 *    WARNs that a PASS did not go through the proxy.
 *  - With Node's built-in proxy support switched on (NODE_USE_ENV_PROXY=1, or
 *    --use-env-proxy on the command line or in NODE_OPTIONS -- Node 22.21+ or
 *    24+), Node's fetch routes through HTTP(S)_PROXY, NO_PROXY respected, and
 *    so does the unmodified SDK. This probe then runs the SDK untouched and
 *    reports the check as having gone through the proxy.
 *  - --ts-proxy-support/CAMUNDA_TS_PROXY_SUPPORT installs undici's own
 *    `ProxyAgent` as the global dispatcher for this check -- the in-code fix
 *    an app on an older Node would apply. It takes precedence over Node's
 *    built-in proxy support when both are on.
 *
 * Auth-strategy auto-upgrade gap (the Python SDK has an equivalent gap by a
 * different mechanism, same risk): this
 * SDK's config hydration auto-upgrades CAMUNDA_AUTH_STRATEGY from its NONE
 * default to OAUTH the moment CAMUNDA_CLIENT_ID/CAMUNDA_CLIENT_SECRET are
 * present in the environment -- even if CAMUNDA_AUTH_STRATEGY was never set
 * at all (source: chunk-4NRTES5E.js's config-hydration step). A network-mode
 * run that merely leaves auth unconfigured would silently authenticate if
 * credentials happen to be in the shell (e.g. left over from an earlier
 * full-mode run). This probe defeats that by explicitly passing
 * `CAMUNDA_AUTH_STRATEGY: 'NONE'` via the `config` override in network mode
 * -- an explicit value (via env OR this override) fully
 * disables the auto-upgrade, regardless of what credentials are present.
 * ---------------------------------------------------------------------------
 */

const { execFileSync } = require('child_process');

const {
  buildTrustContext,
  classifyTransportError,
  clusterEdgeDetail,
  crashFragment,
  eprint,
  errorChain,
  fragment,
  getProxyUrl,
  hasClusterTarget,
  isVerbose,
  maskProxy,
  normalizeRestBase,
  resolveIsFull,
  tsProxySupportEnabled,
} = require('./_shared');

const SDK_NAME = '@camunda8/orchestration-cluster-api';
const SDK_VERSION = '9.1.4';
const SDK_SPEC = SDK_NAME + '@' + SDK_VERSION;
const INSTALL_TIMEOUT_MS = 90000;
const REQUEST_TIMEOUT_MS = 15000;

const USAGE = `Layer 2 SDK-snippet confirmation -- TypeScript/Node.js.
Requires ${SDK_NAME}==${SDK_VERSION} -- see run.sh/run.cmd or CAMUNDA_SDK_AUTO_INSTALL.`;

// Installing the pinned SDK is the default; opting out is explicit. A tier that
// silently SKIPs answers nothing about whether the real client reaches the
// cluster, which is the question this tier exists to settle -- and a SKIP
// sitting among PASS lines reads as "fine" to a participant scanning output.
// --no-install / CAMUNDA_SDK_AUTO_INSTALL=0 opts out when writing into the
// machine's node_modules is unwanted. --install is still accepted so existing
// muscle memory keeps working; it is now a no-op.
function autoInstallEnabled() {
  if (process.argv.slice(2).includes('--no-install')) return false;
  const v = (process.env.CAMUNDA_SDK_AUTO_INSTALL || '').trim().toLowerCase();
  return !(v === '0' || v === 'false' || v === 'no' || v === 'off');
}

function sdkResolvable() {
  try {
    require.resolve(SDK_NAME);
    return true;
  } catch (e) {
    return false;
  }
}

/**
 * Attempt `npm ci` against the committed lockfile (hash-verified, exact
 * versions -- see the module doc comment). Returns an error string, or null
 * on success.
 */
function installSdk() {
  const npmCmd = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  eprint('[typescript sdk-probe] installing ' + SDK_SPEC + " via `npm ci` against the committed, hash-verified lockfile...");
  try {
    execFileSync(npmCmd, ['ci', '--no-audit', '--no-fund'], {
      cwd: __dirname,
      timeout: INSTALL_TIMEOUT_MS,
      stdio: ['ignore', 'pipe', 'pipe'],
      // Windows: spawning "npm.cmd" directly via execFileSync can fail with
      // EINVAL in this environment -- npm.cmd is a batch
      // shim, not a native PE executable, so it needs cmd.exe to interpret
      // it. shell:true routes the spawn through cmd.exe/sh as appropriate;
      // harmless on POSIX where "npm" is a real executable.
      shell: process.platform === 'win32',
    });
    return null;
  } catch (e) {
    const tail = String((e.stderr && e.stderr.toString()) || (e.stdout && e.stdout.toString()) || e.message || e);
    return tail.length > 400 ? tail.slice(-400) : tail;
  }
}

// Node versions whose built-in fetch can route through HTTP(S)_PROXY on
// request: NODE_USE_ENV_PROXY=1 since 24.0.0 and 22.21.0, the --use-env-proxy
// flag (command line or NODE_OPTIONS) since 24.5.0 and 22.21.0. The odd-numbered
// 23.x line never got it.
const ENV_PROXY_NODE_VERSIONS = 'Node.js 22.21+ or 24+';

function nodeSupportsEnvProxy(viaFlag) {
  const [major, minor] = process.versions.node.split('.').map((n) => parseInt(n, 10));
  if (major >= 25) return true;
  if (major === 24) return !viaFlag || minor >= 5;
  if (major === 22) return minor >= 21;
  return false;
}

// The last --use-env-proxy / --no-use-env-proxy in an argument list (Node lets
// the later one win), as true/false, or null when neither appears.
function lastEnvProxyFlag(args) {
  let value = null;
  for (const a of args) {
    if (a === '--use-env-proxy') value = true;
    else if (a === '--no-use-env-proxy') value = false;
  }
  return value;
}

/**
 * Whether Node's built-in proxy support is switched on for THIS process --
 * when it is, Node's own fetch (and with it the unmodified SDK) routes through
 * HTTP(S)_PROXY, honoring NO_PROXY.
 *
 * Must run before anything replaces the global dispatcher. Two signals:
 *  - what was requested: a --use-env-proxy/--no-use-env-proxy flag (command
 *    line beats NODE_OPTIONS, and either beats the variable), else
 *    NODE_USE_ENV_PROXY, which Node honors only with the exact value "1";
 *  - what Node actually did: at startup it installs an EnvHttpProxyAgent as
 *    undici's global dispatcher (shared across undici copies through a
 *    well-known global symbol) whenever the feature is on and a proxy
 *    variable is set.
 * Either one counting as active keeps the answer right if a future Node
 * renames the class, and a version too old for the feature still reads as
 * requested-but-inactive.
 */
function detectNodeEnvProxy() {
  const fromArgv = lastEnvProxyFlag(process.execArgv);
  const fromOptions = lastEnvProxyFlag((process.env.NODE_OPTIONS || '').split(/\s+/));
  const flag = fromArgv !== null ? fromArgv : fromOptions;
  const envValue = (process.env.NODE_USE_ENV_PROXY || '').trim();

  let requested;
  let via;
  if (flag !== null) {
    requested = flag;
    via = '--use-env-proxy';
  } else {
    requested = envValue === '1';
    via = 'NODE_USE_ENV_PROXY=1';
  }

  const dispatcher = globalThis[Symbol.for('undici.globalDispatcher.1')];
  const installed = !!(dispatcher && dispatcher.constructor && dispatcher.constructor.name === 'EnvHttpProxyAgent');
  const active = installed || (requested && nodeSupportsEnvProxy(flag !== null));
  return { requested, active, via, envValue, flagDisabled: flag === false };
}

/**
 * Whether NO_PROXY/no_proxy exempts host from the proxy, using the same rules
 * as Node's built-in proxy support: comma- or space-separated entries, "*"
 * matches everything, an entry matches the host itself and its subdomains
 * (a leading "." or "*." is optional), and a ":port" suffix is ignored here
 * since every request this probe makes goes to 443.
 */
function noProxyExcludes(host) {
  const raw = process.env.no_proxy || process.env.NO_PROXY || '';
  const h = host.toLowerCase();
  for (let entry of raw.split(/[,\s]+/)) {
    entry = entry.trim().toLowerCase();
    if (!entry) continue;
    if (entry === '*') return true;
    entry = entry.replace(/:\d+$/, '').replace(/^\*?\./, '');
    if (h === entry || h.endsWith('.' + entry)) return true;
  }
  return false;
}

/**
 * Points Node's global `fetch` (and therefore the SDK's default HTTP client,
 * which just calls `globalThis.fetch` -- see the module doc comment) through
 * an HTTP(S) proxy, using undici's own official `ProxyAgent` +
 * `setGlobalDispatcher` -- NOT a hand-written HTTP client.
 *
 * WHY THIS EXISTS: the real SDK has no proxy handling, and Node's global
 * `fetch` ignores HTTP_PROXY/HTTPS_PROXY unless Node's built-in proxy support
 * is switched on (see detectNodeEnvProxy) -- which needs a recent Node. On
 * any Node without it, the SDK silently bypasses the proxy and connects
 * straight to the internet; this dispatcher is the in-code fix that works
 * regardless of Node version.
 *
 * WHY `undici`'s ProxyAgent: `undici` is the same library Node's OWN global
 * fetch is built on, and it ships an official `ProxyAgent` dispatcher for
 * exactly this use case. It tunnels the request through the proxy, follows
 * redirects, decodes chunked responses, and auto-derives Basic proxy-auth
 * from the proxy URL's userinfo (see `ProxyAgent`'s own source,
 * `lib/dispatcher/proxy-agent.js`: `username`/`password` parsed straight off
 * the proxy URL) -- none of which a hand-rolled CONNECT tunnel + minimal
 * HTTP/1.1 client would give without tight coupling to this SDK's current
 * request shape. It is also the exact fix an engineering team on an older
 * Node would apply to their own application -- three lines
 * (`setGlobalDispatcher(new ProxyAgent(...))`), no custom code -- so this
 * probe exercises the SAME real-world remediation instead of a bespoke
 * workaround.
 *
 * Returns a restore function that puts the previous global dispatcher back
 * -- this is process-global state, and probe_sdk.js should not leave it
 * mutated after `runChecks` returns.
 */
function installProxyDispatcher(proxyUrl, trust) {
  const { ProxyAgent, getGlobalDispatcher, setGlobalDispatcher } = require('undici');
  const previous = getGlobalDispatcher();
  const proxyAgentOpts = trust.ca ? { uri: proxyUrl, requestTls: { ca: trust.ca } } : proxyUrl;
  setGlobalDispatcher(new ProxyAgent(proxyAgentOpts));
  return () => setGlobalDispatcher(previous);
}

function classifySdkFailure(target, e, storeLabel, stage) {
  const name = e && e.name;
  if (name === 'HttpSdkError') {
    const status = e.status;
    if (status === 503) {
      // FAIL, not WARN: blocks training right now (severity), even though
      // it's never the customer's fault (attribution -- see the Go binary's
      // IsOurClusterProblem/ExitOurClusterProblem).
      return fragment(
        target,
        'FAIL',
        'CLUSTER_UNHEALTHY_503',
        'cluster reachable but unhealthy (503) -- likely our shared preflight cluster, not your network: ' + e.message,
        storeLabel
      );
    }
    if (stage === 'topology' && status === 401) {
      return fragment(target, 'FAIL', 'TOPOLOGY_AUTH_FAIL', 'authenticated topology request rejected (401): ' + e.message, storeLabel);
    }
    return fragment(target, 'FAIL', 'CLUSTER_EDGE_404', clusterEdgeDetail(status), storeLabel);
  }
  if (name === 'CancelSdkError') {
    return fragment(
      target,
      'FAIL',
      'CONNECT_TIMEOUT',
      'request timed out after ' + REQUEST_TIMEOUT_MS + 'ms -- port 443 likely blocked/dropped by firewall: ' + e.message,
      storeLabel
    );
  }
  // A proxy that refuses the CONNECT (through Node's built-in proxy support or
  // --ts-proxy-support's ProxyAgent) surfaces as an undici error whose message
  // carries "Proxy response (<status>)" -- no error code that the generic
  // transport classification would recognize.
  const proxyMatch = errorChain(e)
    .map((x) => (x && x.message) || '')
    .join(' | ')
    .match(/proxy response \((\d{3})\)/i);
  if (proxyMatch) {
    if (proxyMatch[1] === '407') {
      return fragment(
        target,
        'FAIL',
        'PROXY_AUTH_407',
        'authenticated corporate proxy in path rejected the request (407) -- put the proxy user name and ' +
          'password in the proxy URL (--proxy/HTTPS_PROXY) as its user-info part, with special characters such as ' +
          '@ : & URL-encoded (Basic auth only), or ask IT to exempt these hosts.',
        storeLabel
      );
    }
    return fragment(target, 'FAIL', 'CONNECT_REFUSED', 'proxy CONNECT tunnel failed: proxy answered HTTP ' + proxyMatch[1], storeLabel);
  }
  const [errorClass, detail] = classifyTransportError(e && e.cause ? e.cause : e);
  return fragment(target, 'FAIL', errorClass, detail, storeLabel);
}

/**
 * Decides how this check's requests travel when a proxy is configured, and
 * returns { route, notes, restoreDispatcher } -- route is a short phrase for
 * PASS details, notes are config fragments to emit. Installs
 * --ts-proxy-support's ProxyAgent when that path wins (restoreDispatcher then
 * puts the previous dispatcher back); Node's built-in proxy support needs
 * nothing installed, since the dispatcher Node set up at startup already
 * routes the SDK's fetch through the proxy.
 */
function resolveProxyRoute(host, proxyUrl, envProxy, trust) {
  const result = { route: '', notes: [], restoreDispatcher: null };
  if (!proxyUrl) return result;
  const nodeVersion = 'v' + process.versions.node;
  const configTarget = host + ' (config)';

  if (tsProxySupportEnabled()) {
    eprint('[typescript sdk-probe] using proxy (via undici ProxyAgent, opted in via --ts-proxy-support): ' + maskProxy(proxyUrl));
    if (envProxy.active) {
      eprint(
        "[typescript sdk-probe] Node's built-in proxy support (" + envProxy.via + ') is on as well -- ' +
          "--ts-proxy-support's ProxyAgent replaces it for this check"
      );
    }
    result.restoreDispatcher = installProxyDispatcher(proxyUrl, trust);
    result.route = "via your proxy (--ts-proxy-support's undici ProxyAgent)";
    return result;
  }

  if (envProxy.active) {
    if (noProxyExcludes(host)) {
      eprint("[typescript sdk-probe] Node's built-in proxy support is on, but NO_PROXY exempts " + host + ' -- connecting DIRECT');
      result.route = 'DIRECT (NO_PROXY exempts this host) -- your proxy was NOT used';
      result.notes.push(
        fragment(
          configTarget,
          'WARN',
          'CONFIG_ERROR',
          "Node's built-in proxy support is on (" + envProxy.via + '), but NO_PROXY/no_proxy exempts ' + host +
            ', so the real TypeScript SDK connected DIRECT -- a PASS below did NOT go through your proxy ' +
            '(--proxy/HTTPS_PROXY). Your app behaves the same way with this environment; remove the host from ' +
            'NO_PROXY if it must go through the proxy.'
        )
      );
      return result;
    }
    eprint("[typescript sdk-probe] using proxy (via Node's built-in proxy support, " + envProxy.via + '): ' + maskProxy(proxyUrl));
    result.route = "via your proxy (Node's built-in proxy support, " + envProxy.via + ')';
    return result;
  }

  eprint(
    '[typescript sdk-probe] a proxy is configured but ' +
      (envProxy.requested
        ? "Node's built-in proxy support (" + envProxy.via + ') needs ' + ENV_PROXY_NODE_VERSIONS + ', this is ' + nodeVersion
        : "neither Node's built-in proxy support nor --ts-proxy-support is on") +
      " -- this check will connect DIRECT, bypassing the proxy (matches the real SDK's own default behavior)"
  );
  result.route = 'DIRECT -- your proxy was NOT used';
  const fixes =
    'An app (and this check) goes through the proxy with either fix: set NODE_USE_ENV_PROXY=1 in the ' +
    "environment the app starts with (Node's built-in proxy support, " + ENV_PROXY_NODE_VERSIONS +
    '; this check ran on Node.js ' + nodeVersion + '), or install an undici ProxyAgent as the global ' +
    'dispatcher in the app -- pass --ts-proxy-support to have this check do the same.';
  let detail;
  if (envProxy.requested) {
    detail =
      "Node's built-in proxy support was requested (" + envProxy.via + '), but this Node.js (' + nodeVersion +
      ') predates it -- it needs ' + ENV_PROXY_NODE_VERSIONS + ' -- so Node ignores the setting and the real ' +
      'TypeScript SDK connected DIRECT, bypassing your proxy (--proxy/HTTPS_PROXY). A PASS below did NOT go ' +
      'through your proxy. Upgrade Node.js (or point this check at a newer one with --node-bin), or pass ' +
      '--ts-proxy-support to route this check through an undici ProxyAgent instead.';
  } else {
    detail =
      'A proxy is configured (--proxy/HTTPS_PROXY), but the real TypeScript SDK has no proxy support of its own: ' +
      "it uses Node's built-in fetch, which ignores HTTPS_PROXY unless Node's built-in proxy support is switched " +
      'on. This check therefore connected DIRECT, exactly as an unmodified app would -- a PASS below did NOT go ' +
      'through your proxy. ' + fixes;
    if (envProxy.flagDisabled) {
      detail += ' (--no-use-env-proxy is set, which switches the built-in support off.)';
    } else if (envProxy.envValue && envProxy.envValue !== '1') {
      detail += ' (NODE_USE_ENV_PROXY is set to "' + envProxy.envValue + '", but Node only honors the exact value 1.)';
    }
  }
  result.notes.push(fragment(configTarget, 'WARN', 'CONFIG_ERROR', detail));
  return result;
}

/**
 * The trust store the SDK's requests are actually verified against, and --
 * whenever a custom CA is configured -- a config note explaining that the
 * SDK's own CAMUNDA_MTLS_CA_PATH is not applied and what a real app must use
 * instead. See the module doc comment's trust-store nuance.
 */
function resolveSdkTrust(host, trust, viaProxyAgent) {
  const customCaPath = (process.env.CAMUNDA_MTLS_CA_PATH || '').trim();
  const extraCaPath = (process.env.NODE_EXTRA_CA_CERTS || '').trim();

  let label;
  if (viaProxyAgent && trust.ca) {
    // installProxyDispatcher hands the CA to the ProxyAgent as requestTls.ca,
    // which replaces the default store for the tunneled connection.
    label = trust.label;
  } else if (extraCaPath) {
    label = 'the default certificate store plus NODE_EXTRA_CA_CERTS (' + extraCaPath + ')';
  } else {
    label = 'the default certificate store';
  }

  // Only when the configured CA was actually readable -- an unreadable path
  // already gets its own WARN from buildTrustContext.
  if (!customCaPath || !trust.ca) return { label, note: null, info: '' };

  // The expected case -- the CA reached the SDK the way a real app has to load
  // it -- is not a problem to flag, so it rides along in the check's detail
  // instead of a separate WARN line. The other cases below stay WARNs: there
  // the CA the user passed was not, or may not have been, applied.
  if (extraCaPath === customCaPath) {
    let info =
      '(Custom CA loaded via NODE_EXTRA_CA_CERTS. The SDK does not apply its own CAMUNDA_MTLS_CA_PATH to its ' +
      'requests, so your app needs NODE_EXTRA_CA_CERTS=<CA PEM> set when node starts.';
    if (viaProxyAgent) {
      info += ' With --ts-proxy-support the CA is also passed to the ProxyAgent as requestTls.ca, trusting only that CA.';
    }
    return { label, note: null, info: info + ')' };
  }

  const why =
    'The TypeScript SDK does read CAMUNDA_MTLS_CA_PATH and builds an https.Agent from it, but it hands that agent ' +
    "to Node's built-in fetch, which ignores it -- so the CA is never applied to the SDK's requests, and behind a " +
    'TLS-intercepting proxy they fail certificate verification as if it were unset. What works in a real app is ' +
    'NODE_EXTRA_CA_CERTS=<path to the CA PEM> in the environment the node process STARTS with (Node reads it only ' +
    'at startup and adds it to its default certificate store); CAMUNDA_MTLS_CA_PATH alone has no effect.';
  let how;
  if (extraCaPath) {
    how =
      'NODE_EXTRA_CA_CERTS is already set in your environment (' + extraCaPath + '), so this check kept it and did ' +
      'NOT add your --trust-ca/CAMUNDA_MTLS_CA_PATH certificate (' + customCaPath + '): Node loads only one ' +
      'NODE_EXTRA_CA_CERTS file. If that file does not contain the CA you passed, combine both into one PEM file ' +
      'and point NODE_EXTRA_CA_CERTS at it.';
  } else {
    how =
      'This check ran WITHOUT your custom CA (--trust-ca/CAMUNDA_MTLS_CA_PATH), exactly like an app relying on ' +
      'that variable: NODE_EXTRA_CA_CERTS is not set (run.sh/run.cmd set it for this check; running probe_sdk.js ' +
      'directly does not).';
  }
  if (viaProxyAgent) {
    how +=
      " With --ts-proxy-support this check also passes the CA to its ProxyAgent as requestTls.ca, which trusts ONLY " +
      'that CA for the cluster connection -- as an app that installs its own ProxyAgent with that option would.';
  }
  return { label, note: fragment(host + ' (config)', 'WARN', 'CONFIG_ERROR', how + ' ' + why), info: '' };
}

async function runChecks(sdkModule, envProxy) {
  const { createCamundaClient } = sdkModule;
  const fragments = [];
  const trust = buildTrustContext();
  if (trust.warn) fragments.push(trust.warn);
  let storeLabel = trust.label;

  if (!hasClusterTarget()) {
    fragments.push(fragment(
      'sdk status', 'FAIL', 'CONFIG_ERROR',
      'no cluster id configured -- set CAMUNDA_CLUSTER_ID (a UUID) or CAMUNDA_REST_ADDRESS with the cluster ' +
      'id in its path before running this probe standalone. The Go binary validates this before ever invoking ' +
      'a probe; running this file directly skips that check.',
      storeLabel
    ));
    return fragments;
  }

  // Normalize the REST base the same way the Go binary and the Python/Java
  // probes do -- see _shared.js's normalizeRestBase doc comment for the
  // verified "SDK does not tolerate Console's stray :443 path segment" gap,
  // which applies to this SDK too.
  const { restBase, host, wasNormalized } = normalizeRestBase();

  // The SDK itself never reads HTTP(S)_PROXY; the route is whatever the fetch
  // underneath it does (see the module doc comment's proxy-support note). With
  // neither Node's built-in proxy support nor --ts-proxy-support on, this
  // check deliberately mirrors the unmodified SDK and connects direct -- an
  // app gets the same proxy-blind behavior out of the box -- and says so.
  const proxyUrl = getProxyUrl();
  const { route, notes: proxyNotes, restoreDispatcher } = resolveProxyRoute(host, proxyUrl, envProxy, trust);
  fragments.push(...proxyNotes);
  const routeSuffix = route ? ' ' + route : '';

  const sdkTrust = resolveSdkTrust(host, trust, restoreDispatcher !== null);
  storeLabel = sdkTrust.label;
  if (sdkTrust.note) fragments.push(sdkTrust.note);
  const withTrustInfo = (frag) => {
    if (sdkTrust.info) frag.detail += ' ' + sdkTrust.info;
    return frag;
  };

  if (wasNormalized && isVerbose()) {
    fragments.push(
      fragment(
        host + ' (config)',
        'WARN',
        'CONFIG_ERROR',
        "your CAMUNDA_REST_ADDRESS is Camunda Console's copy-paste form (stray ':443' path segment). This preflight " +
          'normalized it to ' +
          restBase +
          ' so the check is valid -- BUT the TypeScript SDK does NOT do this itself (it only appends ' +
          "'/v2' when missing; verified in its own config-hydration source) -- pasting the raw Console string straight " +
          'into your SDK config yields the same opaque \'default backend - 404\' already confirmed for the Python and ' +
          'Java SDKs. Use the canonical form ' +
          restBase +
          ' in participant SDK config.'
      )
    );
  }

  // Mode decision must mirror the Go binary exactly: network mode is
  // credential-free and does status ONLY -- never an authenticated
  // getTopology(), and never even acquires a token.
  const hasCreds = !!((process.env.CAMUNDA_CLIENT_ID || '').trim() && (process.env.CAMUNDA_CLIENT_SECRET || '').trim());
  const isFull = resolveIsFull(process.env.CAMUNDA_PREFLIGHT_MODE || '', hasCreds);

  // Build the client config explicitly rather than relying purely on the
  // SDK's own env auto-detection -- see the module doc comment's "auth-
  // strategy auto-upgrade gap" note for why CAMUNDA_AUTH_STRATEGY: 'NONE'
  // must be forced in network mode.
  const config = { CAMUNDA_REST_ADDRESS: restBase };
  if (!isFull) {
    config.CAMUNDA_AUTH_STRATEGY = 'NONE';
  } else if (hasCreds) {
    config.CAMUNDA_AUTH_STRATEGY = 'OAUTH';
  }

  // installProxyDispatcher (if it ran above) mutated process-global undici
  // state -- must always be restored before returning, success or failure,
  // so this probe never leaves the process's global fetch dispatcher pointed
  // at a proxy that only this one check opted into. createCamundaClient
  // itself is inside this try (not just the calls below), since a throw
  // during client construction would otherwise skip the restore.
  try {
    const client = createCamundaClient({
      config,
      // NullLogger equivalent -- REQUIRED, not optional. At
      // 'debug' level, this SDK's own config.hydrated event logs
      // CAMUNDA_CLIENT_ID COMPLETELY UNMASKED (only
      // CAMUNDA_CLIENT_SECRET gets redacted) -- the same class of leak Python's
      // probe_sdk.py addresses with an explicit NullLogger().
      // Unlike the Python SDK (where CAMUNDA_SDK_LOG_LEVEL=silent does NOT
      // suppress the leak, requiring logger=NullLogger() specifically), this
      // SDK's log.level:'silent' does fully suppress every transport call,
      // including config.hydrated. Passed
      // programmatically here (belt-and-suspenders) rather than relying only on
      // the CAMUNDA_SDK_LOG_LEVEL=silent env var, so it can never be skipped by
      // an unset/overridden env var.
      log: { level: 'silent' },
    });

    const statusTarget = host + ' (sdk status)';
    try {
      await client.getStatus({ signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
      fragments.push(withTrustInfo(fragment(statusTarget, 'PASS', 'OK', 'SDK getStatus() succeeded' + routeSuffix, storeLabel)));
    } catch (e) {
      fragments.push(withTrustInfo(classifySdkFailure(statusTarget, e, storeLabel, 'status')));
    }

    // getTopology() is the authenticated, FULL-MODE-ONLY analog. In network
    // mode emit NO fragment at all -- matching the Go binary and the Python/
    // Java probes, which simply omit their topology stage in network mode.
    const topologyTarget = host + ' (sdk topology)';
    if (!isFull) {
      // network mode: credential-free, topology omitted (no line), like Go.
      return fragments;
    }

    if (!hasCreds) {
      fragments.push(
        fragment(
          topologyTarget,
          'SKIP',
          'OK',
          'full mode requested but CAMUNDA_CLIENT_ID/CAMUNDA_CLIENT_SECRET are not set -- cannot run the authenticated getTopology() check'
        )
      );
    } else {
      try {
        const topo = await client.getTopology({ signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
        const brokerCount = topo && Array.isArray(topo.brokers) ? topo.brokers.length : '?';
        fragments.push(
          fragment(topologyTarget, 'PASS', 'OK', 'SDK getTopology() succeeded, ' + brokerCount + ' broker(s)' + routeSuffix, storeLabel)
        );
      } catch (e) {
        fragments.push(classifySdkFailure(topologyTarget, e, storeLabel, 'topology'));
      }
    }
  } finally {
    if (restoreDispatcher) restoreDispatcher();
  }

  return fragments;
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes('-h') || args.includes('--help')) {
    eprint(USAGE);
    return 0;
  }

  // Read before anything else can touch undici's global dispatcher -- see
  // detectNodeEnvProxy.
  const envProxy = detectNodeEnvProxy();

  if (!sdkResolvable()) {
    if (!autoInstallEnabled()) {
      console.log(
        JSON.stringify(
          fragment(
            'sdk',
            'SKIP',
            'OK',
            SDK_NAME +
              ' not installed, so the real TypeScript SDK was not exercised (the native trust probe in ' +
              'probe.js already covers the mandatory check). The automatic install is disabled by ' +
              '--no-sdk-install, or CAMUNDA_SDK_AUTO_INSTALL=0 -- re-run without it, or install manually: ' +
              'cd "' +
              __dirname +
              '" && npm ci'
          )
        )
      );
      return 0;
    }

    const installErr = installSdk();
    if (installErr) {
      console.log(
        JSON.stringify(
          fragment(
            'sdk',
            'SKIP',
            'OK',
            'auto-install of the Camunda TypeScript SDK failed -- ' +
              installErr +
              '. Install manually: (cd "' +
              __dirname +
              '" && npm ci)'
          )
        )
      );
      return 0;
    }
    if (!sdkResolvable()) {
      console.log(JSON.stringify(fragment('sdk', 'SKIP', 'OK', 'npm reported a successful install but the SDK still failed to resolve')));
      return 0;
    }
    eprint('[typescript sdk-probe] installed ' + SDK_SPEC);
  }

  // Defense-in-depth (mirrors probe_sdk.py's contextlib.redirect_stdout
  // guard): this probe's stdout is a line-delimited JSON channel the launcher
  // parses, so redirect stdout to stderr while requiring the SDK, in case a
  // transitive dependency ever prints a banner at import time. This specific
  // SDK version prints nothing at require() time; kept anyway
  // as a cheap guard against a future version regressing this.
  const realWrite = process.stdout.write.bind(process.stdout);
  let sdkModule;
  try {
    process.stdout.write = process.stderr.write.bind(process.stderr);
    sdkModule = require(SDK_NAME);
  } finally {
    process.stdout.write = realWrite;
  }

  const fragments = await runChecks(sdkModule, envProxy);
  let exitCode = 0;
  for (const frag of fragments) {
    console.log(JSON.stringify(frag));
    if (!['PASS', 'WARN', 'SKIP'].includes(frag.verdict)) exitCode = 1;
  }
  return exitCode;
}

main()
  .then((code) => process.exit(code))
  .catch((e) => {
    // Last-resort: never let an unhandled exception produce a bare stack
    // trace on stdout that the launcher can't parse -- emit a proper
    // probe-error fragment instead (matches the cross-runtime fragment
    // contract shared by every language's Layer 2 probe).
    console.log(JSON.stringify(crashFragment((e && (e.stack || e.message)) || String(e))));
    process.exit(1);
  });
