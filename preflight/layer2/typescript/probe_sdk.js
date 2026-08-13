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
 *    "8-stable" (8.8.4), "latest" (9.1.2, the current stable release), and
 *    "alpha" (10.0.0-alpha.15, prerelease, not used). Pinned exactly to
 *    9.1.2 below.
 *  - The SDK's major version tracks the Camunda SERVER's minor version
 *    (SDK 9.y.z <-> Camunda 8.9 -- see the package's own README), so 9.1.2 is
 *    the right major for this project's target server line.
 *  - package.json declares "engines": {"node": ">=22"}, but the README says
 *    "Node 20+ (native fetch & File)" -- the two disagree. engines.node is
 *    npm's own install-time-enforced contract, so treat Node 22+ as the real
 *    requirement (this machine's Node is v22.14.0, satisfying both anyway).
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
 * Auto-install (off by default -- same reasoning as Python's pip auto-install
 * and Java's Maven fetch: a corporate-proxy/no-internet environment is
 * exactly the case this whole tool exists to catch, and silently spending
 * time on `npm ci` during every automated preflight run would be bad UX in
 * precisely that scenario):
 *   CAMUNDA_SDK_AUTO_INSTALL=1   or   --install   runs `npm ci` in this
 *   directory (using the committed lockfile) if the SDK isn't already
 *   resolvable, then proceeds. If installation isn't enabled/fails, this
 *   emits a SKIP fragment with the manual install command -- the native
 *   probe's fragments (from probe.js) still cover the mandatory trust check
 *   either way.
 *
 * ---------------------------------------------------------------------------
 * Trust-store nuance, verified against the SDK's own published source
 * (dist/chunk-WSCXETVI.js in the 9.1.2 tarball), NOT assumed: with no custom
 * CA/mTLS material configured, the SDK calls Node's global `fetch` (undici)
 * with no custom Agent at all -- i.e. Node's own built-in root certificates,
 * the SAME default probe.js's tier-1 check uses. Once CAMUNDA_MTLS_CA_PATH
 * (or the sibling _CA/_CERT_PATH/_KEY_PATH vars) are set, the SDK builds
 * `new https.Agent({ca: ...})` and attaches it to every outbound call
 * (including OAuth token fetches) -- REPLACING the default root store, not
 * appending (see probe.js's module doc comment for the full verified
 * reasoning, including a live empirical test). This SDK's real custom-CA
 * behavior matches Java's real client, not Go/Python's.
 *
 * Env-var-name note: unlike Java (whose real client reads a DIFFERENT name,
 * CAMUNDA_CA_CERTIFICATE_PATH, than this tool's own CAMUNDA_MTLS_CA_PATH
 * convention -- needing its own cross-name mismatch WARN), the real
 * TypeScript SDK reads CAMUNDA_MTLS_CA_PATH directly. No name-mismatch WARN
 * is needed for this language.
 *
 * Proxy-support note (see installProxyDispatcher's own doc comment for the
 * full story): the SDK has ZERO built-in HTTP(S)_PROXY handling -- absent
 * from its source, and observably so: pointing HTTPS_PROXY at a dead port,
 * both raw fetch() and this SDK's own getStatus() still succeed with a real
 * response instead of a connection error. By DEFAULT this probe mirrors that exactly -- a configured --proxy
 * is silently bypassed, same as an unmodified real application using this
 * SDK would experience. --ts-proxy-support/CAMUNDA_TS_PROXY_SUPPORT opts
 * into routing through the proxy instead, via undici's own official
 * `ProxyAgent` + `setGlobalDispatcher` (the same fix a real customer
 * engineering team should apply to their own application -- three lines of
 * setup, no custom HTTP client needed).
 *
 * Auth-strategy auto-upgrade gap (mirrors Python's known gap
 * #1, a different mechanism, same risk): this
 * SDK's config hydration auto-upgrades CAMUNDA_AUTH_STRATEGY from its NONE
 * default to OAUTH the moment CAMUNDA_CLIENT_ID/CAMUNDA_CLIENT_SECRET are
 * present in the environment -- even if CAMUNDA_AUTH_STRATEGY was never set
 * at all (source: chunk-WSCXETVI.js's config-hydration step). A network-mode
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
  crashFragment,
  eprint,
  fragment,
  getProxyUrl,
  isVerbose,
  maskProxy,
  normalizeRestBase,
  resolveIsFull,
  tsProxySupportEnabled,
} = require('./_shared');

const SDK_NAME = '@camunda8/orchestration-cluster-api';
const SDK_VERSION = '9.1.2';
const SDK_SPEC = SDK_NAME + '@' + SDK_VERSION;
const INSTALL_TIMEOUT_MS = 90000;
const REQUEST_TIMEOUT_MS = 15000;

const USAGE = `Layer 2 SDK-snippet confirmation -- TypeScript/Node.js.
Requires ${SDK_NAME}==${SDK_VERSION} -- see run.sh/run.cmd or CAMUNDA_SDK_AUTO_INSTALL.`;

function autoInstallEnabled() {
  if (process.argv.slice(2).includes('--install')) return true;
  const v = (process.env.CAMUNDA_SDK_AUTO_INSTALL || '').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes';
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

/**
 * Points Node's global `fetch` (and therefore the SDK's default HTTP client,
 * which just calls `globalThis.fetch` -- see the module doc comment) through
 * an HTTP(S) proxy, using undici's own official `ProxyAgent` +
 * `setGlobalDispatcher` -- NOT a hand-written HTTP client.
 *
 * WHY THIS EXISTS: the real SDK's own HTTP client (Node's global
 * `fetch`/undici) does NOT honor HTTP_PROXY/HTTPS_PROXY at all -- absent
 * from its source, and observably so: pointing HTTPS_PROXY at a dead port
 * that nothing listens on, both raw fetch() and the SDK's own getStatus()
 * still succeed with a real response instead of a connection error -- so
 * when `--proxy` is set, this probe's own tier-1
 * native check correctly tunnels through it while tier 2 silently bypassed
 * the proxy entirely and connected straight to the real internet.
 *
 * EARLIER VERSION of this fix (superseded here) hand-wrote a hand-rolled
 * HTTP/1.1 client + manual CONNECT tunnel as a custom `fetch` override. That
 * worked, but carried real downsides verified against `undici`'s ProxyAgent
 * instead: no redirect-following, a minimal chunked-decoder, and tight
 * coupling to this SDK's exact today's request shape. `undici` (the same
 * library Node's OWN global fetch is built on) ships an official `ProxyAgent`
 * dispatcher for exactly this use case: it (a) correctly
 * tunnels a real request through a local test proxy and (b) auto-derives
 * Basic proxy-auth from the proxy URL's userinfo, same as this probe's own
 * hand-rolled tunnel did (verified against `ProxyAgent`'s own source,
 * `lib/dispatcher/proxy-agent.js`: `username`/`password` parsed straight off
 * the proxy URL). This is also the exact fix a real customer engineering
 * team would apply to their own application -- three lines
 * (`setGlobalDispatcher(new ProxyAgent(...))`), no custom code -- so this
 * probe now tests the SAME real-world remediation instead of a bespoke
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
    return fragment(target, 'FAIL', 'UNEXPECTED_HTTP_STATUS', 'unexpected HTTP status ' + status + ': ' + e.message, storeLabel);
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
  const [errorClass, detail] = classifyTransportError(e && e.cause ? e.cause : e);
  return fragment(target, 'FAIL', errorClass, detail, storeLabel);
}

async function runChecks(sdkModule) {
  const { createCamundaClient } = sdkModule;
  const fragments = [];
  const trust = buildTrustContext();
  const storeLabel = trust.label;
  if (trust.warn) fragments.push(trust.warn);

  // Normalize the REST base the same way the Go binary and the Python/Java
  // probes do -- see _shared.js's normalizeRestBase doc comment for the
  // verified "SDK does not tolerate Console's stray :443 path segment" gap,
  // which applies to this SDK too.
  const { restBase, host, wasNormalized } = normalizeRestBase();

  // See installProxyDispatcher's doc comment: the real SDK's own fetch
  // ignores HTTP_PROXY/HTTPS_PROXY entirely, so without it a configured
  // --proxy is silently bypassed here while tier 1 correctly tunnels through
  // it -- not a bug, the DEFAULT here deliberately mirrors the real,
  // unmodified SDK exactly (a training group's own job-worker code gets the same
  // proxy-blind behavior out of the box, unless THEY also apply this same
  // fix). --ts-proxy-support/CAMUNDA_TS_PROXY_SUPPORT opts into the tunneled
  // check instead, at the cost of no longer testing the real SDK's own
  // (nonexistent) proxy handling.
  const proxyUrl = getProxyUrl();
  const proxySupportEnabled = tsProxySupportEnabled();
  let restoreDispatcher = null;
  if (proxyUrl && proxySupportEnabled) {
    eprint('[typescript sdk-probe] using proxy (via undici ProxyAgent, opted in via --ts-proxy-support): ' + maskProxy(proxyUrl));
    restoreDispatcher = installProxyDispatcher(proxyUrl, trust);
  } else if (proxyUrl) {
    eprint('[typescript sdk-probe] a proxy is configured but --ts-proxy-support is not set -- this check will connect DIRECT, bypassing the proxy (matches the real SDK\'s own default behavior)');
    fragments.push(
      fragment(
        host + ' (config)',
        'WARN',
        'CONFIG_ERROR',
        'A proxy is configured (--proxy/HTTPS_PROXY) but --ts-proxy-support/CAMUNDA_TS_PROXY_SUPPORT is not set. The ' +
          "real TypeScript SDK's own fetch has no proxy support at all (confirmed from source) and connects direct -- " +
          'this check mirrors that default exactly, so a PASS below did NOT go through your proxy. Pass ' +
          '--ts-proxy-support to route this check through the proxy instead.'
      )
    );
  }

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
      // probe_sdk.py found and fixed with an explicit NullLogger(). GOOD NEWS:
      // unlike Python (where CAMUNDA_SDK_LOG_LEVEL=silent
      // was confirmed NOT to suppress the leak, requiring logger=NullLogger()
      // specifically), this SDK's log.level:'silent' DOES fully suppress every
      // transport call, including config.hydrated -- confirmed by wiring a
      // transport spy and observing zero invocations with 'silent' set. Passed
      // programmatically here (belt-and-suspenders) rather than relying only on
      // the CAMUNDA_SDK_LOG_LEVEL=silent env var, so it can never be skipped by
      // an unset/overridden env var.
      log: { level: 'silent' },
    });

    const statusTarget = host + ' (sdk status)';
    try {
      await client.getStatus({ signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
      fragments.push(fragment(statusTarget, 'PASS', 'OK', 'SDK getStatus() succeeded', storeLabel));
    } catch (e) {
      fragments.push(classifySdkFailure(statusTarget, e, storeLabel, 'status'));
    }

    // getTopology() is the authenticated, FULL-MODE-ONLY analog. In network
    // mode emit NO fragment at all -- matching the Go binary and the Python/
    // Java probes, which simply omit their topology stage in network mode.
    const topologyTarget = host + ' (sdk topology)';
    if (!isFull) {
      // network mode: credential-free, topology omitted (no line), like Go.
    } else if (!hasCreds) {
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
          fragment(topologyTarget, 'PASS', 'OK', 'SDK getTopology() succeeded, ' + brokerCount + ' broker(s)', storeLabel)
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

  if (!sdkResolvable()) {
    if (!autoInstallEnabled()) {
      console.log(
        JSON.stringify(
          fragment(
            'sdk',
            'SKIP',
            'OK',
            SDK_NAME +
              ' not installed (native trust probe in probe.js already covers the mandatory check) -- install manually: ' +
              '(cd "' +
              __dirname +
              '" && npm ci), or set CAMUNDA_SDK_AUTO_INSTALL=1 (or pass --install) to install it automatically next run'
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

  const fragments = await runChecks(sdkModule);
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
