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
 *   CAMUNDA_MTLS_CA_PATH   extra CA PEM (this tool's --trust-ca). The real
 *       @camunda8/orchestration-cluster-api SDK reads the same name but never
 *       applies it to its requests -- see probe_sdk.js's module doc comment;
 *       a real app needs NODE_EXTRA_CA_CERTS, which tier 2 exercises.
 *   HTTPS_PROXY / HTTP_PROXY (or lowercase)   explicit proxy, CONNECT-tunneled
 *
 * Emits one JSON fragment per line on stdout, per target, per the
 * cross-runtime probe contract shared by every language's Layer 2 probe:
 *   {runtime, trustStoreExercised, target, verdict, errorClass, detail}
 *
 * ---------------------------------------------------------------------------
 * Custom-CA semantics: when CAMUNDA_MTLS_CA_PATH is set, this probe passes the
 * PEM to tls.connect() as `ca`, which per Node's documented
 * tls.createSecureContext() behavior REPLACES the default root store rather
 * than extending it -- each target is checked against that CA alone. A PASS
 * therefore proves the CA by itself vouches for the chain this network
 * presents, the strict question for a TLS-intercepting proxy.
 *
 * This is NOT how the real SDK picks up a CA. The SDK reads
 * CAMUNDA_MTLS_CA_PATH and builds an https.Agent from it, but Node's built-in
 * fetch ignores that agent, so the CA never reaches its requests; a real app
 * needs NODE_EXTRA_CA_CERTS, which appends to the default store. Tier 2
 * (probe_sdk.js) exercises that route -- see its module doc comment.
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
Supported env vars are listed in this probe's source header.`;

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
        'certificate not trusted by ' + trust.label + ': ' + (e.message || e) + ' -- likely a TLS-intercepting proxy; import its root CA via CAMUNDA_MTLS_CA_PATH',
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
