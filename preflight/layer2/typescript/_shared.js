'use strict';
/**
 * Shared helpers for the TypeScript/Node.js Layer 2 probes (probe.js +
 * probe_sdk.js). Mirrors preflight/layer2/python/_shared.py's structure and
 * division of labor -- centralized so probes never carry two independently-
 * drifting copies of the same fragment-emission / classification /
 * redaction logic (one shared vocabulary across every language).
 *
 * Plain CommonJS, zero dependencies, zero build step -- `require('./_shared')`
 * works with nothing beyond the `node` binary itself, matching every other
 * tier-1 probe's "no build step" ethos in this project. (Tier 2's SDK usage
 * needs its own npm install, same precedent as Java's tier-2 needing its own
 * `javac`/Maven step -- see probe_sdk.js.)
 */

const fs = require('fs');
const net = require('net');
const tls = require('tls');
const { URL } = require('url');

const RUNTIME = 'typescript';
const CONNECT_TIMEOUT_MS = 10000;

// Matches inline URL credentials (scheme://user:pass@host) so they can be
// masked out of any text before it's emitted (credentials embedded in a URL
// must never reach output; mirrored from _shared.py's scrub_url_creds).
const URL_CREDS_RE = /(\w+:\/\/)[^/@\s:]+:[^/@\s]+@/g;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function scrubUrlCreds(text) {
  if (!text) return text;
  return String(text).replace(URL_CREDS_RE, '$1****:****@');
}

function eprint(...args) {
  // eslint-disable-next-line no-console
  console.error(...args);
}

function fragment(target, verdict, errorClass, detail, storeLabel) {
  // Scrub URL credentials from the detail as a universal backstop -- every
  // emitted fragment funnels through here, so a proxy password embedded in an
  // exception string can't leak to stdout regardless of which code path
  // built the detail (mirrors probe.py's fragment()).
  return {
    runtime: RUNTIME,
    trustStoreExercised: storeLabel || '',
    target: target || '',
    verdict,
    errorClass,
    detail: scrubUrlCreds(detail),
  };
}

function crashFragment(detail) {
  return fragment('', 'probe-error', 'PROBE_CRASHED', 'probe crashed: ' + detail);
}

/**
 * Whether to surface extra diagnostic fragments hidden by default (e.g. the
 * Console-URL normalization notice) -- useful to the operator/trainer, but
 * confusing noise for participants. Set by the launcher via
 * CAMUNDA_PREFLIGHT_VERBOSE (from the Go binary's --verbose), or by passing
 * --verbose when running a probe standalone.
 */
function isVerbose() {
  if (process.argv.slice(2).includes('--verbose')) return true;
  const v = (process.env.CAMUNDA_PREFLIGHT_VERBOSE || '').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes';
}

/**
 * Opt-in switch for probe_sdk.js's proxy-tunneling `fetch` override (see
 * tunneledFetch in probe_sdk.js). OFF by default -- the real SDK's own
 * `fetch` has zero proxy handling and silently connects direct, which is
 * exactly what this tool's default behavior mirrors on purpose (matching
 * what a cohort's own unmodified job-worker code would do). Set
 * CAMUNDA_TS_PROXY_SUPPORT=1 (forwarded from the Go binary's
 * --ts-proxy-support) or pass --ts-proxy-support standalone to opt into the
 * tunneled check instead -- see RUNBOOK's TypeScript section for what that
 * does and does not prove.
 */
function tsProxySupportEnabled() {
  if (process.argv.slice(2).includes('--ts-proxy-support')) return true;
  const v = (process.env.CAMUNDA_TS_PROXY_SUPPORT || '').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes';
}

/**
 * Mirrors the Go binary's network-vs-full decision so probes never diverge
 * from it (network mode must be credential-free -- status only, no
 * authenticated topology, no token). An explicit
 * mode (passed by the launcher via CAMUNDA_PREFLIGHT_MODE) wins; when unset
 * (probe run standalone by hand) fall back to creds-presence auto-detect,
 * the same default the Go binary uses.
 */
function resolveIsFull(mode, hasCreds) {
  const m = (mode || '').trim().toLowerCase();
  if (m === 'network') return false;
  if (m === 'full') return true;
  return hasCreds;
}

function getProxyUrl() {
  for (const name of ['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy']) {
    const v = process.env[name];
    if (v) return v;
  }
  return null;
}

function maskProxy(proxyUrl) {
  if (!proxyUrl) return '';
  let u;
  try {
    u = new URL(proxyUrl);
  } catch (e) {
    return proxyUrl;
  }
  if (u.username || u.password) {
    u.username = '****';
    u.password = '****';
    return u.toString();
  }
  return proxyUrl;
}

/**
 * Same config-source precedence as the Go binary: an explicit
 * CAMUNDA_REST_ADDRESS host wins over CAMUNDA_REGION.
 */
function resolveApiHost() {
  const restAddress = (process.env.CAMUNDA_REST_ADDRESS || '').trim();
  const region = (process.env.CAMUNDA_REGION || '').trim() || 'bru-2';

  if (restAddress) {
    const candidate = restAddress.includes('://') ? restAddress : 'https://' + restAddress;
    try {
      const u = new URL(candidate);
      if (u.hostname) return u.hostname;
    } catch (e) {
      // fall through to the region-derived default
    }
  }
  return region + '.api.camunda.io';
}

/**
 * Rebuild a canonical https://<host>/<clusterId> REST base, mirroring the Go
 * binary's hostset.parseExplicitHost tolerance (UUID-anywhere-in-path +
 * authority-port stripping) and Python's _shared.normalize_rest_base /
 * Java's Shared.normalizeRestBase.
 *
 * This exists because the real Camunda TypeScript SDK does NOT tolerate the
 * exact string Camunda Console tells users to copy either -- verified live
 * against the SDK's own config-hydration source (dist/chunk-WSCXETVI.js): it
 * only appends '/v2' when the path doesn't already end in it, with no UUID
 * extraction or stray-segment stripping.
 * Console's copy-paste form embeds a stray ':443' path segment
 * (https://<host>/:443/<clusterId>/v2/); passed straight through, the SDK
 * would hit /:443/<clusterId>/v2/status -> Cloudflare 'default backend - 404'
 * -- the SAME known gap already confirmed for the Python and Java SDKs.
 *
 * Returns { restBase, host, wasNormalized }. wasNormalized is true when the
 * raw input carried stray path segments (the exact case a hand-configuring
 * participant would trip over), so the caller can WARN about it.
 */
function normalizeRestBase() {
  const raw = (process.env.CAMUNDA_REST_ADDRESS || '').trim();
  const region = (process.env.CAMUNDA_REGION || '').trim() || 'bru-2';
  const clusterIdEnv = (process.env.CAMUNDA_CLUSTER_ID || '').trim();

  if (!raw) {
    const host = region + '.api.camunda.io';
    if (clusterIdEnv) {
      return { restBase: 'https://' + host + '/' + clusterIdEnv, host, wasNormalized: false };
    }
    return { restBase: 'https://' + host, host, wasNormalized: false };
  }

  const candidate = raw.includes('://') ? raw : 'https://' + raw;
  let parsed;
  try {
    parsed = new URL(candidate);
  } catch (e) {
    return { restBase: candidate, host: region + '.api.camunda.io', wasNormalized: false };
  }
  const host = parsed.hostname || region + '.api.camunda.io';

  const segments = parsed.pathname.split('/').filter(Boolean);
  let clusterId = segments.find((s) => UUID_RE.test(s));
  if (!clusterId) clusterId = clusterIdEnv;

  if (!clusterId) {
    // No UUID anywhere -- return the input untouched rather than guessing;
    // the SDK will surface its own error and the native probe still runs.
    return { restBase: candidate, host, wasNormalized: false };
  }

  const canonical = 'https://' + host + '/' + clusterId;
  // Non-canonical if the raw path carried anything beyond the clusterId and
  // an optional trailing "v2" (e.g. a stray ":443"/"443" Console segment), or
  // if the authority carried an explicit port.
  const straySegments = segments.filter((s) => s !== clusterId && s !== 'v2');
  const wasNormalized = straySegments.length > 0 || parsed.port !== '';
  return { restBase: canonical, host, wasNormalized };
}

// error.code values mirror the Go binary's classifyDialError (httpclient.go)
// and probe.py/Shared.java's classification -- same DNS/refused/timeout/cert
// distinctions, expressed via Node's actual documented error.code values
// (verified live: net.createConnection against a non-existent hostname threw
// code ENOTFOUND; against a closed port threw
// ECONNREFUSED; a certificate-trust failure threw
// UNABLE_TO_GET_ISSUER_CERT_LOCALLY). ETIMEDOUT/ABORT_ERR are set by this
// project's own timeout wrappers (Node's raw net/tls sockets don't
// self-assign a `.code` on a bare 'timeout' event; AbortSignal.timeout()
// used by probe_sdk.js does set `.code = 'ABORT_ERR'`).
const DNS_CODES = new Set(['ENOTFOUND', 'EAI_AGAIN', 'ENODATA']);
const REFUSED_CODES = new Set(['ECONNREFUSED', 'ECONNABORTED', 'EACCES', 'EHOSTUNREACH', 'ENETUNREACH']);
const TIMEOUT_CODES = new Set(['ETIMEDOUT', 'ABORT_ERR', 'UND_ERR_CONNECT_TIMEOUT']);
const CERT_CODES = new Set([
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'UNABLE_TO_GET_ISSUER_CERT',
  'CERT_HAS_EXPIRED',
  'CERT_NOT_YET_VALID',
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'SELF_SIGNED_CERT_IN_CHAIN',
  'ERR_TLS_CERT_ALTNAME_INVALID',
  'CERT_UNTRUSTED',
  'ERR_OSSL_X509_KEY_VALUES_MISMATCH',
]);

/**
 * Walks err.cause (Node's fetch/undici TypeError chaining -- e.g. the SDK's
 * NetworkSdkError sets `.cause` to the original error) the same way
 * _shared.py walks __cause__/__context__ and Shared.java walks getCause().
 * Also descends into AggregateError.errors[0] (Node's Happy-Eyeballs
 * dual-stack connect can throw an AggregateError wrapping multiple per-
 * address failures), so classification still works for that shape.
 */
function errorChain(err) {
  const chain = [];
  const seen = new Set();
  let cur = err;
  while (cur && typeof cur === 'object' && !seen.has(cur)) {
    seen.add(cur);
    chain.push(cur);
    if (Array.isArray(cur.errors) && cur.errors.length) {
      cur = cur.errors[0];
      continue;
    }
    cur = cur.cause;
  }
  if (chain.length === 0) chain.push(err);
  return chain;
}

/**
 * Classify a connection/TLS error into [errorClass, detail]. Structural
 * (error.code) checks first, then substring matching on the chained error
 * text for wrapped/opaque cases -- the same layered approach used across
 * every language in this project.
 */
function classifyTransportError(err) {
  const chain = errorChain(err);

  for (const e of chain) {
    const code = e && e.code;
    if (!code) continue;
    if (DNS_CODES.has(code)) {
      return ['DNS_FAIL', 'hostname did not resolve: ' + (e.message || e)];
    }
    if (REFUSED_CODES.has(code)) {
      return ['CONNECT_REFUSED', 'connection refused -- port 443 likely blocked by firewall: ' + (e.message || e)];
    }
    if (TIMEOUT_CODES.has(code)) {
      return ['CONNECT_TIMEOUT', 'connection timed out -- port 443 likely blocked/dropped by firewall: ' + (e.message || e)];
    }
    if (CERT_CODES.has(code)) {
      return ['TLS_HANDSHAKE_FAIL', 'certificate not trusted: ' + (e.message || e)];
    }
  }

  const text = chain
    .map((e) => (e && (e.message || e.toString())) || '')
    .join(' | ')
    .toLowerCase();
  if (/timed out|timeout/.test(text)) {
    return ['CONNECT_TIMEOUT', 'connection timed out -- port 443 likely blocked/dropped by firewall: ' + chain[0]];
  }
  if (/refused|forbidden by its access permissions/.test(text)) {
    return ['CONNECT_REFUSED', 'connection refused -- port 443 likely blocked by firewall: ' + chain[0]];
  }
  if (/getaddrinfo|nodename nor servname|name or service not known|dns/.test(text)) {
    return ['DNS_FAIL', 'hostname did not resolve: ' + chain[0]];
  }
  if (/cert|ssl|tls|handshake/.test(text)) {
    return ['TLS_HANDSHAKE_FAIL', 'TLS handshake failed: ' + chain[0]];
  }
  return ['CONNECT_REFUSED', 'connection failed: ' + chain[0]];
}

/**
 * Raw plain-TCP connect with a manual timeout (net.Socket has no built-in
 * connect timeout for a 'connect' event that never fires). Shared by both
 * probe.js's own tier-1 checks AND probe_sdk.js's proxy-aware fetch override
 * (see connectViaProxy/tlsHandshake below) -- moved here rather than kept
 * private to probe.js so the two probes never carry two independently-
 * drifting copies of the exact same socket/tunnel/trust logic.
 */
function connectPlain(host, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    const sock = net.createConnection({ host, port });
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      sock.destroy();
      const e = new Error('connection timed out after ' + timeoutMs + 'ms');
      e.code = 'ETIMEDOUT';
      reject(e);
    }, timeoutMs);
    sock.once('connect', () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(sock);
    });
    sock.once('error', (e) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(e);
    });
  });
}

class ProxyError extends Error {
  constructor(statusLine) {
    super(statusLine || 'no response from proxy');
    this.statusLine = statusLine || '';
  }
}

/**
 * Opens an HTTP CONNECT tunnel through proxyUrl to host:port -- raw socket,
 * manual CONNECT handshake, Basic proxy-auth from the URL's userinfo,
 * upgrading to TLS only after the tunnel is established. Confirmed live
 * (probe.js's original research): Node's tls.connect()/https/global fetch do
 * NOT auto-tunnel through HTTPS_PROXY/HTTP_PROXY, and the real SDK itself has
 * ZERO proxy-env-var handling of its own -- this manual tunnel is the only
 * way this project's proxy support works for Node at all, for either tier
 * (probe_sdk.js's proxy-aware fetch override reuses this exact function so
 * tier 2 stops silently bypassing --proxy the way global fetch does).
 */
function connectViaProxy(proxyUrl, host, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    let proxy;
    try {
      proxy = new URL(proxyUrl);
    } catch (e) {
      reject(e);
      return;
    }
    const proxyPort = proxy.port ? Number(proxy.port) : proxy.protocol === 'https:' ? 443 : 80;

    connectPlain(proxy.hostname, proxyPort, timeoutMs)
      .then((rawSock) => {
        const sock = proxy.protocol === 'https:' ? tls.connect({ socket: rawSock, servername: proxy.hostname }) : rawSock;

        const lines = ['CONNECT ' + host + ':' + port + ' HTTP/1.1', 'Host: ' + host + ':' + port];
        if (proxy.username) {
          const user = decodeURIComponent(proxy.username);
          const pass = decodeURIComponent(proxy.password || '');
          const cred = Buffer.from(user + ':' + pass).toString('base64');
          lines.push('Proxy-Authorization: Basic ' + cred);
        }

        let buf = Buffer.alloc(0);
        let settled = false;

        const timer = setTimeout(() => {
          if (settled) return;
          settled = true;
          sock.destroy();
          const e = new Error('proxy CONNECT tunnel timed out after ' + timeoutMs + 'ms');
          e.code = 'ETIMEDOUT';
          reject(e);
        }, timeoutMs);

        const onData = (chunk) => {
          buf = Buffer.concat([buf, chunk]);
          const idx = buf.indexOf('\r\n\r\n');
          if (idx === -1 || settled) return;
          settled = true;
          clearTimeout(timer);
          sock.removeListener('data', onData);
          sock.removeListener('error', onError);
          const statusLine = buf.slice(0, buf.indexOf('\r\n')).toString('latin1').trim();
          if (!/ 200(\s|$)/.test(statusLine)) {
            sock.destroy();
            reject(new ProxyError(statusLine));
            return;
          }
          resolve(sock);
        };
        const onError = (e) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          reject(e);
        };
        sock.on('data', onData);
        sock.on('error', onError);
        sock.write(lines.join('\r\n') + '\r\n\r\n');
      })
      .catch(reject);
  });
}

function tlsHandshake(rawSocket, host, trust, timeoutMs) {
  return new Promise((resolve, reject) => {
    const tlsSock = tls.connect({
      socket: rawSocket,
      servername: host,
      ca: trust.ca,
      rejectUnauthorized: true,
    });
    const timer = setTimeout(() => {
      tlsSock.destroy();
      const e = new Error('TLS handshake timed out after ' + timeoutMs + 'ms');
      e.code = 'ETIMEDOUT';
      reject(e);
    }, timeoutMs);
    tlsSock.once('secureConnect', () => {
      clearTimeout(timer);
      resolve(tlsSock);
    });
    tlsSock.once('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}

/**
 * Bundles the trust material (`ca: undefined` means Node's own default
 * store) with a human-readable label, plus an optional pre-formed WARN
 * fragment (e.g. an unreadable custom-CA file). Shared by probe.js's tier-1
 * checks and probe_sdk.js's proxy-aware fetch override -- both tiers must
 * make the IDENTICAL trust decision for the same CAMUNDA_MTLS_CA_PATH value,
 * or Layer 2 re-introduces the exact false-green this whole probe exists to
 * prevent. REPLACE, not append -- verified against the real SDK's own
 * published source (see probe.js's original module doc comment for the full
 * verified reasoning, including a live empirical test): once a custom CA is
 * set, ONLY that CA is trusted, not "OS store + custom CA".
 */
function buildTrustContext() {
  const customCaPath = (process.env.CAMUNDA_MTLS_CA_PATH || '').trim();
  if (!customCaPath) {
    return {
      ca: undefined,
      label: 'the default certificate store',
      warn: null,
    };
  }

  let pem;
  try {
    pem = fs.readFileSync(customCaPath, 'utf8');
  } catch (e) {
    return {
      ca: undefined,
      label: 'the default certificate store (your custom certificate path is unreadable -- NOT applied)',
      warn: fragment(
        resolveApiHost() + ' (config)',
        'WARN',
        'CONFIG_ERROR',
        'CAMUNDA_MTLS_CA_PATH is set to ' + customCaPath + ', but that file could not be read (' + e.message + ') -- proceeding WITHOUT the custom CA.'
      ),
    };
  }

  return {
    ca: pem,
    label: 'your custom certificate (' + customCaPath + ')',
    warn: null,
  };
}

module.exports = {
  RUNTIME,
  CONNECT_TIMEOUT_MS,
  scrubUrlCreds,
  eprint,
  fragment,
  crashFragment,
  isVerbose,
  tsProxySupportEnabled,
  resolveIsFull,
  getProxyUrl,
  maskProxy,
  resolveApiHost,
  normalizeRestBase,
  classifyTransportError,
  errorChain,
  connectPlain,
  ProxyError,
  connectViaProxy,
  tlsHandshake,
  buildTrustContext,
};
