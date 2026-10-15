# Camunda 8 ILT Connectivity Preflight

A small, self-contained tool that checks — before a Camunda 8 training
session — whether a machine can actually reach the cluster and run the
training exercises. It exists because "the network is fine" and "the
training exercises will work" are different questions: a corporate proxy,
firewall, or TLS-intercepting appliance can let general internet traffic
through while still blocking (or silently breaking) the specific path a
given language's SDK needs.

**Looking to run the check yourself?** See
[`preflight/README.md`](preflight/README.md) — that's the participant-facing
guide: download, run, read the result.

This document is for anyone building, auditing, or extending the tool itself.

---

## How it checks

Two layers, run together by a single command:

- **Layer 1** — a self-contained Go binary (standard library only, no
  external modules, no CGO) that checks DNS, TCP, TLS, ALPN, OAuth
  reachability, and cluster health against the training cluster and its web
  components.
- **Layer 2** — a small native probe per training language (Java, Python,
  TypeScript/Node.js, C#/.NET), because a trust store belongs to a runtime
  *installation*, not to the operating system. A corporate CA or intercepting
  proxy can be trusted by the OS and still be untrusted by a given language's
  runtime, so Layer 1 passing is not sufficient — each Layer 2 probe confirms
  the actual runtime a training group will use can complete a TLS handshake and, for
  the languages that ship one, exercises a snippet of the real Camunda SDK.

Every check reports one of `PASS` / `WARN` / `FAIL` / `SKIP`, and the tool
writes both a human-readable summary and a machine-readable JSON result.

### Behind a proxy

When a proxy is configured (`--proxy`, or `HTTPS_PROXY`/`HTTP_PROXY` with
`NO_PROXY` respected), Layer 1's TCP, TLS and ALPN stages run through the
proxy's `CONNECT` tunnel, and the HTTP stages use the same proxy. A proxy
resolves the target name itself, so a host the local resolver cannot resolve
is not a dead end there: the `dns` stage becomes a `WARN`
(`DNS_VIA_PROXY_WARN`) and the remaining stages continue through the proxy.
If the proxy cannot reach or resolve the host either, that shows up at the
`tcp` stage (for example a `CONNECT` answered with `502`). Without a proxy, a
failed lookup is still a `FAIL` that skips the rest.

Layer 2 hands the same proxy and the same custom CA (`--trust-ca`) to each
runtime in the form that runtime actually reads, because none of them reads
all of the same settings:

- **Maven** ignores `HTTPS_PROXY` and the JDK's trust settings are separate
  from the OS store. The Java probe writes a temporary `settings.xml` with
  `<proxies>` entries for its own Maven runs (credentials are never printed),
  and gives every `mvn` call a temporary trust store — the JDK's default CAs
  plus the `--trust-ca` certificate, or the `--java-truststore` file —
  through `MAVEN_OPTS`. When the proxy URL carries credentials, those runs
  also use `-Dmaven.resolver.transport=wagon`: with Maven 3.9's default HTTP
  transport, an authenticating proxy is sent credentials only on the first
  `CONNECT` tunnel, and the later tunnels a dependency download opens fail
  with `407`.
- **The TypeScript SDK** has no proxy handling of its own; it uses Node's
  built-in `fetch`, which goes through `HTTPS_PROXY` only when Node's
  built-in proxy support is switched on (`NODE_USE_ENV_PROXY=1`, Node 24+ or
  22.21+). The probe reports which route the SDK check took. The SDK also
  does not apply its own `CAMUNDA_MTLS_CA_PATH` to its requests, so the SDK
  check runs with `NODE_EXTRA_CA_CERTS` set to the `--trust-ca` file — the
  setting a real application needs as well.

## Repository layout

```
preflight/
  README.md              participant-facing usage guide
  layer1/                 the Go binary
    cmd/preflight/         entrypoint
    internal/               checks, config, launcher, report, redact, model
    build.sh / build.ps1    cross-compile all 4 release binaries
  layer2/                 one directory per training language
    java/
    python/
    typescript/
    csharp/
    <language>/run.sh, run.cmd   the per-OS entrypoint Layer 1 invokes
```

Each `layer2/<language>` probe is also runnable standalone (see that
language's `run.sh`/`run.cmd`) — useful for debugging a probe in isolation
without going through the Go binary.

## Building from source

Requires Go 1.22+. From `preflight/layer1`:

```bash
bash build.sh          # Linux/macOS — or on Windows: pwsh ./build.ps1
```

Cross-compiles all four release targets (`windows/amd64`, `darwin/amd64`,
`darwin/arm64`, `linux/amd64`) plus a `SHA256SUMS.txt`, into
`preflight/releases/` (not checked into this repo).

Each `layer2/<language>` directory documents its own build/runtime
requirements in its `run.sh`/`run.cmd`.

## Command-line flags

The most commonly used flags:

| Flag | Purpose |
|---|---|
| `--host` | full cluster REST base URL |
| `--stacks` | comma-separated training languages to check (`java,python,...`) |
| `--auto` | auto-detect installed languages instead of naming them |
| `--mode` | `network` (credential-free, default) or `full` (authenticated) |
| `--java-home`, `--python-bin`, `--node-bin`, `--dotnet-bin` | pin a specific runtime installation, for machines with more than one |
| `--proxy` | explicit proxy URL (`http://user:pass@host:port`, credentials URL-encoded); default: `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY` |
| `--trust-ca` | PEM file of an additional CA to trust (e.g. a TLS-intercepting proxy's root), passed on to every runtime |
| `--java-truststore` | Java only: a JKS/PKCS12 trust store to use instead of the JDK's `cacerts` |
| `--maven-depcheck` | Java only: check that the training's Maven dependencies resolve (real downloads, slower) |
| `--ts-proxy-support` | TypeScript only: route the SDK check through the proxy with an undici `ProxyAgent`, as an app on an older Node would |
| `--verbose` | show additional diagnostic detail |
| `--out` | where to write the result JSON |

Run `--help` for the complete, current list — flags are added as new checks
are, and this table is not guaranteed to stay exhaustive.

## Design notes for contributors

- **Layer 1 has zero external dependencies by design** — standard library
  only, so the binary can be audited and rebuilt from source without trusting
  a dependency tree.
- **Network mode is credential-free by construction**, not just by
  convention: credential environment variables are stripped from every Layer
  2 subprocess unless `--mode full` is explicitly set.
- **The result file is designed to be shared with a third party** (a
  training contact, for troubleshooting), so output is deliberately
  conservative about what it includes: secrets are refused outright rather
  than masked, a client ID is masked, and local file paths / a detected
  proxy's hostname or IP are masked by default (`--unmasked-hostnames` opts
  back in when someone is actively diagnosing a proxy issue).
- **A probe that checks the real SDK checks it unmodified.** Where an SDK
  ignores a proxy or a CA setting, the probe does not quietly fix that for
  itself: it runs the SDK the way an unmodified application would, and says
  in the result which route and which trust store were actually used, and
  what an application needs to change.
- **A missing runtime piece is a finding, not a crash.** For example, a Java
  runtime (JRE) without `javac` is reported as `FAIL` / `RUNTIME_ABSENT`
  asking for a JDK (17 or later recommended; the Camunda Spring Boot Starter
  requires 17), rather than as a crashed probe.
