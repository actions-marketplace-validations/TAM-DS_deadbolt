# DeadBolt

## Find leaked keys. Review agent authority.

**An offline scanner for leaked secrets and over-privileged AI agents.**

DeadBolt finds leaked credentials and risky MCP and agent configurations in source trees, git history and container images. It estimates potential authority from credential types, configuration and unverified token claims, then writes a remediation proposal for human review. **Effective access remains unknown.** Core scanning makes **no network calls**. Python 3.11+ uses the standard library; Python 3.10 installs `tomli` for TOML parsing. An optional local model adds explanations over loopback HTTP. Remediation is performed by the operator.

## See it in action

![DeadBolt 0.1.0 running in Mac Terminal, showing critical findings, redacted credentials, estimated authority and zero attempted network calls](docs/images/deadbolt-demo-macos.png)

*Synthetic demo—all credentials are fake. Screenshot from a Mac Terminal run; timings vary by machine.*

## Use as a GitHub Action
### Add these steps to your workflow’s `steps` section.

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
- uses: TAM-DS/deadbolt@v0.1.0
```

## Quick start — macOS and Linux

Run these commands in **Mac Terminal** or a Linux terminal using bash or zsh. You need **Python 3.10–3.13**, Git and Python's `venv` support installed. Installation requires internet access; the core scanner and demo run offline afterward. **No local AI model, API key or Docker daemon is required.**

```bash
python3 --version
git --version
python3 -m venv ~/deadbolt-venv
source ~/deadbolt-venv/bin/activate
python -m pip install git+https://github.com/TAM-DS/deadbolt
deadbolt demo
```

The demo creates a temporary synthetic repository with fake credentials. Expect **30 findings and exit code 1**: the scanner found the planted problems. Exit code 2 indicates a usage or runtime error.

In a new terminal session, activate the same environment before running DeadBolt:

```bash
source ~/deadbolt-venv/bin/activate
deadbolt demo
```

To update an existing installation, run this inside the activated environment:

```bash
python -m pip install --upgrade --force-reinstall git+https://github.com/TAM-DS/deadbolt
```

Run `deactivate` when you are finished.

[![ci](https://github.com/TAM-DS/deadbolt/actions/workflows/ci.yml/badge.svg)](https://github.com/TAM-DS/deadbolt/actions/workflows/ci.yml)
· Apache-2.0 · Python 3.10–3.13 · Linux-first · macOS CLI · CI tested on Linux

---

## Why another secret scanner?

A leaked API key is rarely the whole problem. The real damage is what the key is **allowed to do**. That can mean a cloud bill in the thousands of dollars by morning, or a firmware-signing key that makes every release suspect.

AI agents add new places where credentials and authority leak. DeadBolt checks these surfaces and adds configuration-specific findings:

| Surface | What goes wrong | DeadBolt coverage |
|---|---|---|
| MCP server configs (`mcp.json`, `claude_desktop_config.json`, Cursor, VS Code, Cline, Codex TOML) | standing tokens in `env`, auto-approved shell tools, `/` filesystem roots, unpinned `npx` servers, `docker.sock` mounts | checked |
| Agent / tool manifests | `scopes: ["*"]`, org-wide OAuth scopes such as `cloud-platform` | checked |
| Agent context caches & memory | the model echoes a key into an unencrypted conversation-history file | checked |
| Prompt files | a key embedded in a prompt is sent to the model provider on **every call** | checked |
| Git history | the "I deleted the file" fix: the key is still in every clone | checked |
| Container image layers | a token baked into `layer.tar` of a `docker save` / OCI tarball | checked |
| CI logs | `npm publish` echoes `NPM_TOKEN` | checked |

DeadBolt treats each finding as an **authority** problem, not just a pattern match.

## What it does

```
              ┌──────────── sources (all local) ────────────┐
 worktree ─┐  │ files · git index (--staged) · git history  │
 tarballs ─┼─▶│ docker-save / OCI layers · build archives   │
 git repo ─┘  └──────────────────────┬──────────────────────┘
                                     ▼
          ┌──────────────────────────┴───────────────────────────┐
          │ detectors                                             │
          │  • 21 provider rules (keyword prefilter → regex →     │
          │    placeholder + entropy filters)                     │
          │  • MCP auditor (8 rules) · agent-manifest auditor     │
          │  • exposure tagging: prompt / context-cache / CI log  │
          └──────────────────────────┬───────────────────────────┘
                                     ▼
          ┌──────────────────────────┴───────────────────────────┐
          │ deterministic blast radius (0–100)                    │
          │  authority (read < write < deploy < admin)            │
          │  + billable? + where it has travelled                 │
          │  + decoded JWT claims (role, scope, exp)              │
          └──────────────────────────┬───────────────────────────┘
                                     ▼
   text / JSON / SARIF 2.1.0      revocation proposals (sha256)   ──▶ human approves
   (secrets always redacted)      nothing executes                    into a hash-chained ledger
```

### 1. Detection

- **21 credential rules.** They cover AWS, GCP service accounts, Google/Gemini API keys, Azure storage, Anthropic, OpenAI, Hugging Face, GitHub, GitLab, npm, PyPI, Docker Hub, Stripe, Slack, SendGrid, private keys (SSH / TLS / **code and firmware signing**), database URLs, JWTs, plus a generic high-entropy rule.
- **False-positive discipline.** Documentation examples (`AKIAIOSFODNN7EXAMPLE`), `${VAR}`, `{{ secrets.X }}`, `<your-key>`, low-entropy values and `# deadbolt:allow` lines are all ignored. When a provider rule already matched a value, the generic rule stays quiet about it.

### 2. MCP and agent-authority auditing

| Rule | Finding |
|---|---|
| `DB-MCP-001` | Literal credential in a server's `env` or `headers`. Every agent session inherits it |
| `DB-MCP-002` | Credential passed in `args`, where it shows up in `ps`, shell history and crash dumps |
| `DB-MCP-003` | Filesystem server rooted at `/`, `~`, `/home`, `C:\` … |
| `DB-MCP-004` | Unpinned `npx` / `uvx` / `pipx` package or container image that isn't digest-pinned |
| `DB-MCP-005` | Remote MCP endpoint over plaintext `http://` (loopback excepted) |
| `DB-MCP-006` | `autoApprove` / `alwaysAllow` / `trust` covering side-effecting tools |
| `DB-MCP-007` | Shell or command-execution server exposed to the model, which turns prompt injection into RCE |
| `DB-MCP-008` | `--privileged`, `docker.sock`, host networking or a `/` mount on an MCP container |
| `DB-AGT-001` | Wildcard / admin scopes or org-wide OAuth scopes granted to an agent |

### 3. Deterministic blast-radius triage

Every rule declares an estimated potential authority (`read`, `write`, `deploy` or `admin`), whether it can **spend money**, and its revocation runbook. The score then adds up the places the secret has travelled:

```
blast = 18 × authority  + 10 if billable
      + git-history 8 · docker-layer 8 · ci-log 6 · agent-context-cache 6 · llm-prompt 6 · mcp-config 5 · IaC 4
```

JWTs are decoded as **unverified claims**. A `service_role` claim contributes an estimated **admin** classification. Signature validity, actual grants, revocation and issuer enforcement remain unknown. An unverified expiry claim never reduces severity. Scores are review priorities, with time-dependent expiry notes, and are not probabilities of compromise or verified access.

**Optional local LLM notes** (`--llm-triage`) use an Ollama-compatible endpoint. The client accepts numeric loopback addresses or `localhost`, pins the connection to a numeric loopback address, bypasses proxies, refuses redirects, and sends sanitized metadata. The model can add an explanation while authority, score and severity remain deterministic. The report counts attempted local requests. A connection failure, missing model or invalid response returns exit code 2 with the deterministic scan report preserved. Actual inference with a real local model remains unverified; HTTP integration is tested with a local synthetic server.

### 4. Bounded authority: proposals, not actions

```bash
deadbolt audit . --proposals deadbolt-proposals.json
deadbolt approve 431bc213 --by "Tracy Manning" --reason "rotated in Stripe dashboard"
deadbolt ledger            # ✔ ledger intact (1 entries)
```

- Each proposal is **content-addressed**. Its `proposal_id` is the SHA-256 of its canonical body. Editing a step without updating that ID invalidates the proposal. Review the complete content and compare the ID with your trusted copy. Hashes establish content identity; they do not authenticate an author.
- Decisions are appended under a file lock to a **hash-chained** JSONL ledger. Ordinary edits break verification. To detect recomputed hashes or truncation, compare with an independently retained head using `deadbolt ledger --expected-head <trusted-sha256>`. A local chain alone cannot establish authenticity or completeness. Approver names are operator-supplied labels.
- `executes_automatically: false` is hard-coded. DeadBolt never revokes keys, rewrites history or opens PRs.

### Safe demo and ledger checks

`deadbolt demo` creates a new temporary directory. `--out PATH` requires a destination that does not exist. To repeat a demo with a saved path, choose a new destination.

An approval prints the complete ledger head. Save that hash independently if you need to check for later rewriting or truncation. `--expected-head` compares the entire current ledger to that checkpoint; after a legitimate append, retain the new head. For a tamper demonstration, edit a **copy** of the ledger and verify that copy with `--ledger PATH`.

## Demo output (synthetic, all credentials fake)

`deadbolt demo` generates an edge-diagnostics repo where an "AI maintenance copilot" is wired into fleet telemetry through MCP. It plants 20+ fake credentials across `.env`, an MCP config, a firmware-signing key, a GCP service account, an agent cache, a prompt file, a CI log, a two-layer container image and a commit that was "fixed" by deleting the file.

```text
DeadBolt 0.1.0  ·  /tmp/dirty  ·  sources: worktree, git-history
16 files · 0.01 MB · 10 ms · 0 attempted network calls

 CRITICAL  DB-STRIPE-001  Stripe live secret key
           config/settings.py:1 @ 283aab0096  worktree
           Stripe live secret key detected (sk_l********54qs)
           blast radius  90/100 · estimated authority=admin · exposure=git-history
             – billable — an attacker can run up charges until the key is revoked
             – Committed to git history — deleting the file does not remove it; every clone has it

 CRITICAL  DB-MCP-007  Arbitrary command execution exposed to the model
           .cursor/mcp.json:21 @ 283aab0096  worktree
           [shell] server exposes shell/command execution — prompt injection becomes remote code execution
           blast radius  85/100 · estimated authority=admin · exposure=mcp-config,git-history

 CRITICAL  DB-MCP-001  Standing credential in MCP server config
           .cursor/mcp.json:33 @ 283aab0096  worktree
           [fleet-telemetry] headers.Authorization holds a literal JSON Web Token — every agent session inherits it
           blast radius  85/100 · estimated authority=admin · exposure=mcp-config,git-history
             – unverified claims suggest elevated role (service_role); effective access unknown
             – unverified expiry is more than a year out — potentially long-lived credential

 HIGH      DB-DOCKER-001  Docker Hub personal access token
           artifacts/edge-gateway.image.tar!/app/config/registry.yaml:3 [layer a71e0c9d55b2]  docker-layer
           blast radius  62/100 · estimated authority=deploy · exposure=docker-layer

 HIGH      DB-GL-001  GitLab personal access token
           config/legacy-ci.yaml:3 @ …  git-history          ← file was deleted; key lives on in history
 …
30 findings: 14 critical · 13 high · 3 medium
```

The fixture is **generated, not committed**. Every fake token is assembled at runtime from split prefixes, so this repository contains no scannable secret, and CI checks that by scanning DeadBolt's own worktree and full history.

## Usage

```bash
deadbolt audit [PATH]                       # directory, single file, .tar/.tgz, or `docker save` image
deadbolt audit . --history                  # + every added line in git history
deadbolt audit --staged                     # pre-commit mode: only what's in the index
deadbolt audit image.tar                    # container layers, no Docker daemon needed
deadbolt audit . -f sarif -o deadbolt.sarif # GitHub code scanning
deadbolt audit . -f json  --fail-on critical --min-severity medium
deadbolt baseline . -o .deadbolt-baseline.json && deadbolt audit . --baseline .deadbolt-baseline.json
deadbolt rules                              # list every rule with its authority level
```

Exit codes: `0` nothing at or above `--fail-on` (default `high`) · `1` findings · `2` usage or runtime error.
Skip paths with `.deadboltignore` (glob per line) or `--exclude`. Staged scans use `.deadboltignore` from the Git index, so unstaged edits do not alter the staged scan policy. Ignore rules and baselines are reviewable policy inputs.

Unreadable/corrupt archives, files exceeding the 2 MiB text limit, archives over 512 MiB, excessive archive nesting, malformed supported configs and history beyond `--max-commits` return **2 (incomplete scan)**. Increase the commit limit explicitly for longer histories. Known binary extensions, dependency/build directories and symlinks encountered during a tree walk are excluded by design. History scanning inspects added text plus complete changed JSON/TOML configs. Scope and exclusions still require review.

**pre-commit**

```yaml
repos:
  - repo: https://github.com/TAM-DS/deadbolt
    rev: main
    hooks: [{ id: deadbolt }]
```

**GitHub Actions**

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- uses: TAM-DS/deadbolt@main
  with: { fail-on: high }
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: { sarif_file: deadbolt.sarif }
```

## Engineering notes

- **Offline core.** A unit test fails the build if any core module imports `socket`, `urllib.request`, `http.client`, `requests`, `httpx` or `aiohttp`. The only network-capable module is the opt-in, loopback-only LLM client.
- **Throughput.** Each rule's regex runs only when one of its keywords appears in the lowercased file. The generic rule finds its anchors with `str.find` and runs a short anchored regex at those offsets. Files are spread across a process pool. The original pre-hardening benchmark reported **10,000 Python files / 94 MB in 1.7 s on a 2-vCPU Linux sandbox**. That timing has not been revalidated for this revision.
- **Redaction.** Findings carry `prefix****last4` and a truncated SHA-256 fingerprint. Known detected values are removed from report metadata, URL query strings and userinfo are sanitized, and model notes are filtered. Regression cases cover endpoint URLs, server names and all report/proposal formats. Detection and redaction have finite rule coverage.
- **Stable identities.** Finding IDs are derived from the rule and the secret's fingerprint, not the line number, so baselines survive refactors. A secret found in both the worktree and history is reported once, tagged `git-history`.
- **Tested.** 60 `unittest` cases cover every rule and MCP check, false positives, redaction, SARIF shape, baselines, exit codes, staged mode, proposal tampering and ledger tampering. CI runs them on Python 3.10 through 3.13.

## Part of an end-to-end governed-agent lifecycle

| Stage | Repo | Question it answers |
|---|---|---|
| **Before commit / build** | **DeadBolt** | Did a credential or an over-broad agent grant leak into code, config, history or an image, and how bad is it? |
| Before a prompt ships | [guardrails-mcp](https://github.com/TAM-DS/guardrails-mcp) | Did the prompt change actually make things better? (baseline vs. candidate on labeled cases, human release decision) |
| Before and at deployment | [agent-foundry](https://github.com/TAM-DS/agent-foundry) | Was this agent validated, evaluated and explicitly approved, and what bounded runtime grant does it get? |
| Runtime detection & response | [penumbra](https://github.com/TAM-DS/penumbra) | Is an insider, a spy or a hijacked agent active right now, and what containment should a human approve? |

They share one principle, the same one Agent Foundry states as *capability is not authority*: **the model proposes, the system decides what is authorized, and a human decides what happens.**

## Roadmap

- Rust scanning core behind the same CLI (via PyO3) for multi-GB monorepos
- Offline format checks for tokens with built-in checksums
- SBOM / SLSA provenance cross-check for MCP server packages
- Edge targets: firmware images (squashfs / ext4) and embedded-Linux rootfs tarballs

 ## How it was built

I architected DeadBolt and directed Claude as my build agent. I set the design, the security
boundaries, and the review standard, then reviewed and hardened the code myself, including
redaction, approval integrity, and scan coverage. It's the same pattern DeadBolt enforces:
the model proposes, a human decides.


## License

Apache-2.0 © Tracy Anne Griffin Manning. Built for defenders: DeadBolt never validates a credential against a live service and never uses a credential it finds.
