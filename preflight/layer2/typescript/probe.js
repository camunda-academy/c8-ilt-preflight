#!/usr/bin/env node
'use strict';
/**
 * Layer 2 native trust probe -- TypeScript/Node.js (tier 1).
 *
 * Standalone: node preflight/layer2/typescript/probe.js
 * (no Camunda SDK required -- Node's built-in tls/net modules only)
 *
 * Env vars:
 *   CAMUNDA_REST_ADDRESS   full cluster REST URL (wins over CAMUNDA_REGION)
 *   CAMUNDA_REGION         region slug, default bru-2
 *   CAMUNDA_MTLS_CA_PATH   extra CA PEM -- the SAME env var name the real
 *       @camunda8/orchestration-cluster-api SDK itself reads (verified in its
 *       own README + source). Unlike Java (whose real client reads a
 *       DIFFERENT name, CAMUNDA_CA_CERTIFICATE_PATH, and needed its own
 *       cross-name mismatch WARN), there is no name trap here.
 *   HTTPS_PROXY / HTTP_PROXY (or lowercase)   explicit proxy, CONNECT-tunneled
 *
 * Emits one JSON fragment per line on stdout, per target, per the
 * cross-runtime probe contract shared by every language's Layer 2 probe:
 *   {runtime, trustStoreExercised, target, verdict, errorClass, detail}
 *
 * ---------------------------------------------------------------------------
 * CRITICAL, verified (not assumed) -- both from the real SDK's published
 * source AND empirically against a live Node process: when
 * CAMUNDA_MTLS_CA_PATH is set, this probe's custom-CA trust context REPLACES
 * Node's default root store; it does NOT append to it.
 *
 * Why: @camunda8/orchestration-cluster-api 9.1.2's own mTLS handling (its
 * published dist/chunk-WSCXETVI.js) builds `new https.Agent({ca: <PEM>})`
 * whenever CAMUNDA_MTLS_CA_PATH/_CA/_CERT_PATH/_KEY_PATH are set -- it does
 * NOT spread Node's own `tls.rootCertificates` into that `ca` value first.
 * Empirically verified live in this environment: an https.Agent constructed
 * with ONLY a (dummy) custom `ca` failed to verify a real public-CA-signed
 * host (login.cloud.camunda.io) with UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
 * confirming Node's documented tls.createSecureContext() behavior that
 * supplying `ca` REPLACES the well-known Mozilla-curated default list rather
 * than extending it. (Spreading `[...tls.rootCertificates, customCa]`
 * instead DOES append correctly -- also verified live -- but that is not
 * what the real SDK does, so this probe does not do it either.)
 *
 * This means the TypeScript SDK's real custom-CA behavior matches JAVA's
 * (replace), not Go/Python's (append). An initial assumption of append,
 * mirroring Go/Python, would have been WRONG for this runtime -- corrected
 * here after verification, since custom-CA semantics must always be verified
 * from source rather than guessed. Faithfully mirroring the real SDK's
 * REPLACE behavior is required by this tier's whole
 * purpose: exercising the SAME trust store the real SDK uses. A probe that
 * merely appended (like Go/Python do for their own SDKs) would risk a false
 * PASS in exactly the scenario where the real client, having discarded the
 * public CAs, fails to trust the OTHER target (e.g. the OAuth host, if it
 * isn't behind the same TLS-intercepting proxy as the cluster host).
 * ---------------------------------------------------------------------------
 */

const {
  CONNECT_TIMEOUT_MS,
  ProxyError,
  buildTrustContext,
  classifyTransportError,
  connectPlain,
  connectViaProxy,
  crashFragment,
  eprint,
  fragment,
  getProxyUrl,
  maskProxy,
  resolveApiHost,
  tlsHandshake,
} = require('./_shared');

const OAUTH_HOST = 'login.cloud.camunda.io';

const USAGE = `Layer 2 native trust probe -- TypeScript/Node.js.
Standalone: node preflight/layer2/typescript/probe.js
See the RUNBOOK's TypeScript section for env vars.`;

function resolveTargets() {
  return [
    [resolveApiHost(), 443],
    [OAUTH_HOST, 443],
  ];
}

async function probeTarget(host, port, trust, proxyUrl) {
  const target = host + ':' + port;
  const start = Date.now();

  let rawSocket;
  try {
    rawSocket = proxyUrl ? await connectViaProxy(proxyUrl, host, port, CONNECT_TIMEOUT_MS) : await connectPlain(host, port, CONNECT_TIMEOUT_MS);
  } catch (e) {
    if (e instanceof ProxyError) {
      if (e.statusLine.includes('407')) {
        return fragment(
          target,
          'FAIL',
          'PROXY_AUTH_407',
          'authenticated corporate proxy in path -- supply credentials in the proxy URL ' +
            '(Basic auth only; export HTTPS_PROXY=http://user:pass@<proxy>:<port>) ' +
            'or ask IT to exempt these hosts. Proxy response: ' +
            e.statusLine
        );
      }
      return fragment(target, 'FAIL', 'CONNECT_REFUSED', 'proxy CONNECT tunnel failed: ' + e.statusLine);
    }
    const [errorClass, detail] = classifyTransportError(e);
    return fragment(target, 'FAIL', errorClass, detail);
  }

  try {
    const tlsSock = await tlsHandshake(rawSocket, host, trust, CONNECT_TIMEOUT_MS);
    const elapsedMs = Date.now() - start;
    tlsSock.destroy();
    return fragment(target, 'PASS', 'OK', 'TLS handshake succeeded (' + elapsedMs + 'ms)', trust.label);
  } catch (e) {
    const [errorClass, detail] = classifyTransportError(e);
    if (errorClass === 'TLS_HANDSHAKE_FAIL') {
      return fragment(
        target,
        'FAIL',
        'TLS_HANDSHAKE_FAIL',
        'certificate not trusted by ' + trust.label + ': ' + (e.message || e) + ' -- likely a TLS-intercepting proxy; import its root CA via CAMUNDA_MTLS_CA_PATH (see RUNBOOK)',
        trust.label
      );
    }
    return fragment(target, 'FAIL', errorClass, detail, trust.label);
  } finally {
    try {
      rawSocket.destroy();
    } catch (_) {
      // already closed
    }
  }
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes('-h') || args.includes('--help')) {
    eprint(USAGE);
    return 0;
  }

  const trust = buildTrustContext();
  if (trust.warn) {
    console.log(JSON.stringify(trust.warn));
  }

  const proxyUrl = getProxyUrl();
  if (proxyUrl) {
    eprint('[typescript probe] using proxy: ' + maskProxy(proxyUrl));
  }
  eprint('[typescript probe] trust store: ' + trust.label);

  let exitCode = 0;
  for (const [host, port] of resolveTargets()) {
    const frag = await probeTarget(host, port, trust, proxyUrl);
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
