# Security Investigation Agent (TypeScript) — Updated

A multi-agent security auditor built on the [Claude Agent SDK](https://platform.claude.com/docs/en/agent-sdk/overview). Point it at a codebase or a GitHub PR, get back a report with vulnerability chains, CVE-confirmed dependency findings, evidence, and concrete suggested fixes.

Upgraded sibling of the [original take-home (v1)](https://github.com/ashwinmudaliar/claude-agent-sdk-security-investigator-TS), itself a TypeScript port of the [Python implementation](https://github.com/ashwinmudaliar/claude-agent-sdk-security-investigator). v1 mirrors the Python sibling's architecture (orchestrator + two parallel subagents + hooks); this version extends it — see [What's new](#whats-new-in-this-version) below.

SDK features used: multi-agent orchestration, subagent delegation (two parallel auditors + one serial remediation subagent), extended thinking, hooks, in-process MCP servers, and skills.

## What's New In This Version

Four additions on top of v1 — three leveraging Agent SDK primitives directly, one integration pattern built around the SDK.

### SDK primitives leveraged

| | Primitive (SDK API) | What it adds | Where |
|---|---|---|---|
| **1** | `AgentDefinition` + `agents` field on `Options` | Third subagent — `remediation` — drafts a diff-style patch for every finding the two auditor subagents produce | [`agent.ts`](agent.ts) — `remediation` block |
| **2** | `createSdkMcpServer` + `tool` | In-process MCP server giving the deps-and-config subagent GitHub Advisory lookups — real CVE/GHSA IDs, CVSS, and fixed-version data lands in findings | [`agent.ts`](agent.ts) — `githubMcpServer` |
| **3** | `AgentDefinition.skills` + `settingSources: ["project"]` | Six Flask-specific vulnerability patterns auto-loaded into the `code-analysis` subagent's context. Skill bundle (with `name` + `description` frontmatter) lives at the standard discovery path; the SDK handles loading | [`.claude/skills/flask-vulnerabilities/SKILL.md`](.claude/skills/flask-vulnerabilities/SKILL.md); `skills: ["flask-vulnerabilities"]` declaration in [`agent.ts`](agent.ts) |

### Integration pattern built on top

| | Pattern | What it adds | Where |
|---|---|---|---|
| **4** | Subprocess wrapper as a webhook target | Hono webhook server exposes the agent as a GitHub PR-review service. `child_process.spawn` invokes the CLI per webhook; a custom `INVESTIGATION_SCOPE` env-var contract scopes each audit to the PR's changed files | [`webhook-server/`](webhook-server/) |

**How they compose at runtime:** the orchestrator runs recon, then kicks off `code-analysis` (skill auto-loaded by the SDK into its context) and `deps-and-config` (MCP server attached) in parallel, merges their findings, hands the merged list to `remediation` for fixes, and synthesizes with extended thinking. The chain reasoning crosses sources — a skill-flagged hardcoded `SECRET_KEY` plus an MCP-confirmed Werkzeug CVE end up in the same vulnerability chain even though they came from separate subagents.

The CLI (`agent.ts <repo>`) is for ad-hoc audits. The webhook server (`webhook-server/server.ts`) wraps the same agent for GitHub PR review — webhook in, scoped audit, comment out.

## Quick Start

```bash
git clone https://github.com/ashwinmudaliar/claude-agent-sdk-security-investigator-TS-UPDATED.git
cd claude-agent-sdk-security-investigator-TS-UPDATED
npm install
cp .env.example .env   # add ANTHROPIC_API_KEY (required for both modes)

# CLI mode — one-off audit of a local directory
npx tsx agent.ts test-app/
```

The report writes to `security-report.md`. The audit trail writes to `investigation-log.json`.

For the webhook server (per-PR review), see [`webhook-server/README.md`](webhook-server/README.md) — it covers `GITHUB_TOKEN`, `GITHUB_WEBHOOK_SECRET`, smee.io setup, and a sample-payload curl recipe. After one-time setup, day-to-day use is a single command:

```bash
npm run dev   # boots webhook server + smee tunnel in one terminal
```

## Example Output

The `example-output/` directory contains a complete run against the included test app (a deliberately vulnerable Flask application — yes, Python: the agent's host language and the target's language are independent).

The agent found 9 Critical, 8 High, 3 Medium, and 1 Low findings, with four vulnerability chains and 18 suggested fixes. Here's one:

> **Chain A — Unauthenticated Full Credential Dump in One Request**
>
> 1. `GET /search?q=%25' UNION SELECT password_hash,username FROM users WHERE '1'='1` → extracts every password hash without authentication
> 2. Unsalted MD5 hashes reverse to plaintext in seconds via free online rainbow tables
> 3. The admin hash (`md5("admin123")`) resolves instantly
>
> Result: every user's plaintext password in under a minute, zero credentials required.

The SQL injection on `/search`, the unsalted MD5 hashing, and the hardcoded admin hash are three separate findings. The orchestrator's extended-thinking step connected them into one attack path, and the remediation subagent attached a concrete patch to each.

[Full report →](example-output/security-report.md) · [Investigation log →](example-output/investigation-log.json)

## How It Works

The investigation follows a five-phase workflow:

**Reconnaissance.** The orchestrator (Sonnet) maps the repo: languages, frameworks, entry points, dependency manifests.

**Parallel investigation.** Two auditor subagents (Haiku), each with a focused mandate, constrained tool set, and stack-specific augmentation:

```typescript
const SUBAGENTS: Record<string, AgentDefinition> = {
  "code-analysis": {
    description: "Reads source code to find logic-level vulnerabilities...",
    prompt: `You are a senior application security engineer auditing source code...`,
    tools: ["Read", "Grep", "Glob"],
    skills: ["flask-vulnerabilities"],   // SDK auto-loads SKILL.md
    model: "haiku",
  },
  "deps-and-config": {
    description: "Reads dependency manifests, lockfiles, and configuration files...",
    prompt: `You are a senior application security engineer auditing the
non-code surface of a project...`,
    tools: [
      "Read", "Grep", "Glob", "Bash",
      "mcp__github__list_global_security_advisories",
      "mcp__github__get_global_security_advisory",
    ],
    model: "haiku",
  },
  remediation: {
    description: "Drafts a concrete fix for every finding the auditors produce.",
    prompt: `Receives merged findings, returns a keyed array of suggested fixes...`,
    tools: ["Read", "Grep", "Glob"],
    model: "haiku",
  },
};
```

Code-analysis gets the Flask skill auto-loaded into its context via the SDK's `skills` primitive. Deps-and-config gets in-process MCP tools (defined alongside `SUBAGENTS`) for confirming CVEs against GitHub's Advisory Database — real CVE/GHSA IDs and fixed-version data in findings, not pattern matches.

**Remediation.** After both auditors return, the orchestrator hands the merged findings list to a third Haiku subagent. It re-reads context as needed and emits a diff-style patch for each finding, keyed by id.

**Synthesis.** The orchestrator uses extended thinking (10,000 token budget) to deduplicate findings, filter for exploitability, identify vulnerability chains, and attach the right fix to each finding by id. Extended thinking is what turns "SQL injection + missing admin auth + MD5 hashing" into "full credential harvest without a login."

**Report.** A structured Markdown document with findings grouped by severity, each with location, evidence, exploitability analysis, the auditor's one-line remediation note, and the diff-style suggested fix from the remediation subagent. Written to disk and printed to stdout.

### Hooks

Two hooks enforce execution safety and auditability:

```typescript
hooks: {
  PreToolUse: [
    { matcher: "Bash", hooks: [makePreToolHook(target)] },
  ],
  PostToolUse: [
    {
      matcher: "Read|Grep|Glob|Bash",
      hooks: [makePostToolHook(auditLog)],
    },
  ],
},
```

The **PreToolUse hook** intercepts every Bash command before execution. Known interpreters and runtimes (`python`, `node`, `flask run`, etc.) are blocked when their arguments point into the target repo. Inspection and audit commands (`pip audit`, `grep`, `ls`, `git log`) are explicitly allowed.

The **PostToolUse hook** writes an audit trail. Every Read, Grep, Glob, and Bash call is logged with timestamp, agent type, input, and a human-readable summary. The investigation log lets you verify the report against what the agent actually read.

## Architecture

```
                  ┌─────────────────────────────┐
                  │  Orchestrator (Sonnet)       │
                  │  recon · merge · synthesize  │
                  │  extended thinking: 10k      │
                  └──────┬───────────┬───────────┘
                  parallel│           │parallel
                          ▼           ▼
            ┌──────────────────┐  ┌──────────────────┐
            │  code-analysis   │  │  deps-and-config │
            │  (Haiku)         │  │  (Haiku)         │
            │  Read,Grep,Glob  │  │  Read,Grep,Glob, │
            │  + flask SKILL   │  │  Bash + MCP tools│
            │   (auto-loaded)  │  │   (CVE lookups)  │
            └────────┬─────────┘  └────────┬─────────┘
                     │   findings (ids)    │
                     └──────────┬──────────┘
                                ▼
                     ┌──────────────────┐
                     │   remediation    │   ← serial after auditors
                     │   (Haiku)        │
                     │   Read,Grep,Glob │
                     │   → fixes by id  │
                     └────────┬─────────┘
                              │
                              ▼
                     security-report.md
```

Sonnet handles cross-domain reasoning: recon, delegation briefs, deduplication, vulnerability chain analysis, attaching fixes to findings. Haiku does the focused per-domain work: reading source with the skill loaded, running CVE lookups via MCP, drafting concrete patches.

**Optional deployment surface.** [`webhook-server/server.ts`](webhook-server/server.ts) wraps the agent as a GitHub PR-review service: clone the PR head → spawn `agent.ts` with `INVESTIGATION_SCOPE` set to the changed files → post the report as a PR comment.

**Model choices.** Both models are set as `ORCHESTRATOR_MODEL` and `SUBAGENT_MODEL` constants at the top of `agent.ts`. The defaults — Sonnet 4.6 + Haiku 4.5 — are tuned for a fast, cheap demo on small-to-medium repos. Swap the orchestrator to Opus 4.7 when synthesis gets harder (large codebases, more findings to deduplicate, deeper chain reasoning). Drop both to Haiku for the leanest run. Per-subagent overrides also work — set `model:` on a specific `AgentDefinition` if one investigation needs a different tier than the others.

## Limitations

The agent reads code but doesn't execute it — the PreToolUse hook blocks any attempt to run interpreters against the target repo. The tradeoff: runtime-only vulnerabilities (race conditions, timing attacks, environment-specific behavior) won't show up. If you need those, pair this with a DAST scanner.

Context window size bounds the repos this can handle. The test app is 3 files. On a real codebase, the orchestrator's recon phase matters more because the subagents can't read everything. Larger repos need a file-prioritization step before delegation.

## Adapt This Pattern

The architecture generalizes to any problem where independent experts investigate and an orchestrator reasons across their findings:

- **Compliance audit.** Swap the prompts to check against SOC 2 controls or HIPAA requirements. The tool set stays the same.
- **Code review.** Split into correctness vs. maintainability. The orchestrator is where you weigh "this is technically wrong" against "this is technically fine but no one will be able to maintain it."
- **Due diligence.** Point it at an acquisition target's repo. The report structure already maps to what a technical reviewer needs before a deal closes.

The subagent definitions are data at the top of `agent.ts`. Change the prompts, adjust the tools, add another subagent if the domain calls for it.

## Where This Could Go

- **DAST subagent.** Spin up the target in a container, make HTTP requests, confirm the static findings at runtime. A natural fourth subagent.
- **Git history analysis.** `git log` and `git blame` can surface recently-changed security-critical code, reverted fixes, and secrets that were committed then removed. A natural fifth subagent.
- **Diff-aware mode for the webhook.** The webhook server already passes `INVESTIGATION_SCOPE` with the changed-file list. Push this further — the orchestrator could read the actual diff and constrain even the recon phase to changed code paths, dropping per-PR audits to seconds and pennies.
- **Multi-repo scanning.** The orchestrator prompt doesn't assume a single repo. Wrap it in a loop.
- **More skills.** The Flask skill is one of many possible. Drop a `django-vulnerabilities/SKILL.md` in `.claude/skills/`, add `"django-vulnerabilities"` to the code-analysis subagent's `skills` field — no other code change needed.

## References

- [Claude Agent SDK documentation](https://platform.claude.com/docs/en/agent-sdk/overview)
- [Building effective agents](https://www.anthropic.com/engineering/building-effective-agents)
- [Python sibling implementation](https://github.com/ashwinmudaliar/claude-agent-sdk-security-investigator)
