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
