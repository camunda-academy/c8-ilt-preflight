# Camunda 8 Training Connectivity Preflight

A small, self-contained tool that checks — **before training day** — whether
your machine can reach the Camunda 8 cluster used for the training exercises.
Run it once, fix anything it flags to ensure training readiness.

- No installation, no admin rights required.
- One download per operating system: unzip it and run the program inside.
- **This check by default never needs any cluster data or login credentials.** It only confirms
  *network connectivity*, not your credentials.
- Nothing is sent anywhere automatically. The tool only talks to Camunda's
  own training infrastructure and your own configured proxy (if any) —
  results stay on your machine until you choose to share them.

---

## 1. Download and unzip

Download the archive for your operating system:

| Operating system | Archive | Program inside |
|---|---|---|
| Windows | preflight-windows-amd64.zip | preflight-windows-amd64.exe |
| macOS (Intel) | preflight-darwin-amd64.zip | preflight-darwin-amd64 |
| macOS (Apple Silicon) | preflight-darwin-arm64.zip | preflight-darwin-arm64 |
| Linux | preflight-linux-amd64.zip | preflight-linux-amd64 |

Unzip it. You get one folder containing the program, this README, and a
`layer2` folder. **Keep them together** — the program looks for `layer2`
next to itself when it checks your programming-language setup. Moved on its
own, it still checks network connectivity, but reports the language checks
as skipped.

The tool isn't code-signed yet, so your operating system will likely warn you
the first time you run it. This is expected and safe to bypass — see below.

**Windows — "Windows protected your PC":** click **More info**, then
**Run anyway**.

**macOS — "cannot be opened because the developer cannot be verified":**
right-click (Control-click) the program → **Open** → **Open** again in the
dialog. If that option doesn't appear, open Terminal in the unzipped folder
and run this once:
```bash
xattr -dr com.apple.quarantine .
chmod +x ./preflight-darwin-amd64   # or preflight-darwin-arm64
```

**Linux:**
```bash
chmod +x ./preflight-linux-amd64
```

**"An unauthorized application was blocked" (or similar, from your company's endpoint security software):** this is your organization's own policy, not a bug in this tool — some companies block any program or script without a recognized publisher, and this tool isn't code-signed yet. Try running from a local drive (e.g. your Desktop) rather than a network drive first; if it's still blocked, ask your IT/security team to allow it. They can verify exactly which file they're allowing against the checksums (`SHA256SUMS.txt`) published alongside the download — this covers both the program itself and the `layer2/*/run.sh` / `run.cmd` scripts, since those run directly too and can be blocked the same way.

---

## 2. Run the check

Open a terminal (macOS/Linux) or PowerShell (Windows) **in the unzipped
folder**, and run:

**Windows (PowerShell):**
```powershell
.\preflight-windows-amd64.exe --host <PROVIDED-BY-YOUR-TRAINING-CONTACT> --stacks <your-languages>
```

**macOS / Linux:**
```bash
./preflight-darwin-amd64 --host <PROVIDED-BY-YOUR-TRAINING-CONTACT> --stacks <your-languages>
```

Replace:
- **`<PROVIDED-BY-YOUR-TRAINING-CONTACT>`** with the cluster address your training contact
  gave you.
- **`<your-languages>`** with the programming languages you're training with (comma-separated):

| Training language | Value to use |
|---|---|
| Java | `java` |
| Python | `python` |
| TypeScript / Node.js | `typescript` |
| C# / .NET | `csharp` |

**Training in Java?** Also add `--maven-depcheck` — this additionally
confirms your machine can download the training's Java dependencies (a
separate, common blocker, unrelated to general network connectivity). It
does real downloads, so it takes a bit longer than the other checks:

```bash
./preflight-darwin-amd64 --host <PROVIDED-BY-YOUR-TRAINING-CONTACT> --stacks java --maven-depcheck
```

That's it — one command checks everything you need.

---

## 3. Reading the result

The tool prints one line per check:

| Result | Meaning |
|---|---|
| `PASS` | Working correctly — nothing to do. |
| `WARN` | Works, but worth knowing about (e.g. a non-default certificate in the path). Doesn't block training. |
| `FAIL` | Blocks training — needs to be fixed before the session. |
| `SKIP` | Not checked (e.g. a language runtime isn't installed on this machine). |

At the end you'll see either:
- **`All checks passed.`** — you're ready for training, or
- **`FAILED at stage: ...`**, followed by a **Troubleshooting notes**
  section explaining, in plain language, what's wrong and what to try next.

## 4. If something fails

1. Read the **Troubleshooting notes** at the end of the output first — most
   issues (a corporate proxy, a firewall rule, a missing language runtime)
   come with a specific suggested fix right there.
2. The tool also writes a result file
   (`c8-preflight-result-<timestamp>.json`) next to it. **Send this file to
   your training contact** if you can't resolve the issue yourself — it has
   everything they need to help.
3. If you're on a corporate network with a proxy or a security appliance
   that inspects HTTPS traffic, your training contact can give you one or two extra
   flags to work around it — share the result file first so they know
   what's actually happening.

---

## Good to know

- This check is **credential-free** — it by default never asks for or uses real cluster credentials, only confirms the network path is open.
- Run this on the **actual machine and network you'll use for training**,
  ideally a few days beforehand. Corporate network access changes can take
  time to arrange, and checking from a different machine or network won't
  catch the same issues.

---

Questions? Contact your training contact.
