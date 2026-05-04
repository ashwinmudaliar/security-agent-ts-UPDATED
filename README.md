# Security Investigation Agent (TypeScript) — Updated

A multi-agent security auditor built on the [Claude Agent SDK](https://platform.claude.com/docs/en/agent-sdk/overview). Point it at a codebase or a GitHub PR, get back a report with vulnerability chains, CVE-confirmed dependency findings, evidence, and concrete suggested fixes.

Upgraded sibling of the [original take-home (v1)](https://github.com/ashwinmudaliar/claude-agent-sdk-security-investigator-TS), itself a TypeScript port of the [Python implementation](https://github.com/ashwinmudaliar/claude-agent-sdk-security-investigator). v1 mirrors the Python sibling's architecture (orchestrator + two parallel subagents + hooks); this version extends it — see [What's new](#whats-new-in-this-version) below.

SDK features used: multi-agent orchestration, subagent delegation (two parallel auditors + one serial remediation subagent), extended thinking, hooks, in-process MCP servers, and Markdown skills.

## What's New In This Version

Four additions on top of v1, each leveraging a different Agent SDK primitive:

| | SDK primitive | What it adds | Where |
|---|---|---|---|
| **1** | Subagent definition | A third subagent — `remediation` — drafts a diff-style patch for every finding the two auditor subagents produce | [`upgraded/agent.ts`](upgraded/agent.ts) — `remediation` block |
| **2** | In-process MCP server (`createSdkMcpServer` + `tool`) | GitHub Advisory CVE/GHSA lookups for the deps-and-config subagent — real version-range and fixed-version data lands in findings | [`upgraded/agent.ts`](upgraded/agent.ts) — `githubMcpServer` |
| **3** | Skill (Markdown knowledge plugin) | Six Flask-specific vulnerability patterns prepended to the code-analysis subagent's prompt — concrete grep recipes and severity guidance | [`upgraded/skills/flask-vulnerabilities/SKILL.md`](upgraded/skills/flask-vulnerabilities/SKILL.md) |
| **4** | Subprocess wrapper + new `INVESTIGATION_SCOPE` env contract | Hono webhook server — the agent as a GitHub PR-review service. Per-PR audits scoped to changed files, posted as PR comments | [`webhook-server/`](webhook-server/) |

**How they compose:** the orchestrator runs recon, then kicks off `code-analysis` (skill loaded) and `deps-and-config` (MCP enabled) in parallel, merges their findings, hands the merged list to `remediation` for fixes, and synthesizes everything with extended thinking. The synthesis chain reasoning crosses sources — a skill-flagged hardcoded `SECRET_KEY` plus an MCP-confirmed Werkzeug CVE end up in the same vulnerability chain in the report, even though they came from separate subagents.

The CLI (`upgraded/agent.ts <repo>`) is for ad-hoc audits. The webhook server (`webhook-server/server.ts`) wraps the same agent for GitHub PR review — webhook in, scoped audit, comment out.

## Quick Start

```bash
git clone https://github.com/ashwinmudaliar/claude-agent-sdk-security-investigator-TS-UPDATED.git
cd claude-agent-sdk-security-investigator-TS-UPDATED
npm install
cp .env.example .env   # add ANTHROPIC_API_KEY (required for both modes)

# CLI mode — one-off audit of a local directory
npx tsx upgraded/agent.ts test-app/
```

The report writes to `security-report.md`. The audit trail writes to `investigation-log.json`.

For the webhook server (per-PR review), see [`webhook-server/README.md`](webhook-server/README.md) — it covers `GITHUB_TOKEN`, `GITHUB_WEBHOOK_SECRET`, smee.io setup, and a sample-payload curl recipe.

## Example Output

The `example-output/` directory contains a complete run against the included test app (a deliberately vulnerable Flask application — yes, Python: the agent's host language and the target's language are independent).

The agent found 6 Critical, 5 High, 2 Medium, and 1 Low findings, plus three vulnerability chains. Here's one:

> **Chain B — Full Credential Harvest Without a Login**
>
> 1. `GET /admin/users` → returns all usernames, IDs, and roles (no auth required)
> 2. `GET /search?q=x%' UNION SELECT password_hash,role FROM users WHERE '1'='1` → dumps all MD5 hashes
> 3. `hashcat -m 0 hashes.txt rockyou.txt` → cracks all hashes in seconds given MD5's speed and the lack of salting
>
> Result: plaintext passwords for every account, with no authentication ever attempted.

The missing auth on `/admin/*`, the SQL injection on `/search`, and the weak hashing are three separate findings. The agent connected them into one attack path.

[Full report →](example-output/security-report.md) · [Investigation log →](example-output/investigation-log.json)

## How It Works

The investigation follows a four-phase workflow:

**Reconnaissance.** The orchestrator (Sonnet) maps the repo: languages, frameworks, entry points, dependency manifests.

**Parallel investigation.** Two subagents (Haiku), each with a focused mandate and a constrained tool set:

```typescript
const SUBAGENTS: Record<string, AgentDefinition> = {
  "code-analysis": {
    description: "Reads source code to find logic-level vulnerabilities...",
    prompt: `You are a senior application security engineer auditing source code.
Your mandate is logic-level vulnerabilities in the application code itself —
NOT dependencies and NOT configuration. The other subagent owns those.
...`,
    tools: ["Read", "Grep", "Glob"],
    model: "haiku",
  },
  "deps-and-config": {
    description: "Reads dependency manifests, lockfiles, and configuration files...",
    prompt: `You are a senior application security engineer auditing the
non-code surface of a project — dependencies, config, secrets.
...`,
    tools: ["Read", "Grep", "Glob", "Bash"],
    model: "haiku",
  },
};
```

Each entry is an object with a description, prompt, tools, and model. Code-analysis gets read-only tools. Deps-and-config gets Bash too, for running `pip audit` and `npm audit`.

**Synthesis.** The orchestrator uses extended thinking (10,000 token budget) to deduplicate findings across subagents, filter for exploitability, and identify vulnerability chains. Extended thinking is what turns "SQL injection + missing admin auth + MD5 hashing" into "full credential harvest without a login."

**Report.** A structured Markdown document with findings grouped by severity, each with location, evidence, exploitability analysis, and remediation. Written to disk and printed to stdout.

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
                 ┌─────────────────────────┐
                 │  Orchestrator (Sonnet)   │
                 │  Extended thinking: 10k  │
                 └────────┬────────────────┘
                          │
              ┌───────────┴───────────┐
              ▼                       ▼
   ┌──────────────────┐   ┌──────────────────┐
   │  code-analysis   │   │  deps-and-config  │
   │  (Haiku)         │   │  (Haiku)          │
   │  Read,Grep,Glob  │   │  Read,Grep,Glob,  │
   │                  │   │  Bash             │
   └──────────────────┘   └───────────────────┘
```

Sonnet handles cross-domain reasoning: recon, delegation briefs, deduplication, vulnerability chain analysis. Haiku does the thorough file-by-file work: reading source, grepping for patterns, running audit tools.

**Model choices.** Both models are set as `ORCHESTRATOR_MODEL` and `SUBAGENT_MODEL` constants at the top of `agent.ts`. The defaults — Sonnet 4.6 + Haiku 4.5 — are tuned for a fast, cheap demo on small-to-medium repos. Swap the orchestrator to Opus 4.7 when synthesis gets harder (large codebases, more findings to deduplicate, deeper chain reasoning). Drop both to Haiku for the leanest run. Per-subagent overrides also work — set `model:` on a specific `AgentDefinition` if one investigation needs a different tier than the others.

## Limitations

The agent reads code but doesn't execute it — the PreToolUse hook blocks any attempt to run interpreters against the target repo. The tradeoff: runtime-only vulnerabilities (race conditions, timing attacks, environment-specific behavior) won't show up. If you need those, pair this with a DAST scanner.

Context window size bounds the repos this can handle. The test app is 3 files. On a real codebase, the orchestrator's recon phase matters more because the subagents can't read everything. Larger repos need a file-prioritization step before delegation.

## Adapt This Pattern

The architecture generalizes to any problem where independent experts investigate and an orchestrator reasons across their findings:

- **Compliance audit.** Swap the prompts to check against SOC 2 controls or HIPAA requirements. The tool set stays the same.
- **Code review.** Split into correctness vs. maintainability. The orchestrator is where you weigh "this is technically wrong" against "this is technically fine but no one will be able to maintain it."
- **Due diligence.** Point it at an acquisition target's repo. The report structure already maps to what a technical reviewer needs before a deal closes.

The subagent definitions are data at the top of `agent.ts`. Change the prompts, adjust the tools, add a third subagent if the domain calls for it.

## Where This Could Go

- **DAST subagent.** Spin up the target in a container, make HTTP requests, confirm the static findings at runtime.
- **Git history analysis.** `git log` and `git blame` can surface recently-changed security-critical code, reverted fixes, and secrets that were committed then removed. That's a natural third subagent.
- **CI integration.** Run it on every PR. The Markdown output already works as a GitHub comment, and the investigation log gives reviewers a record of what was checked.
- **Multi-repo scanning.** The orchestrator prompt doesn't assume a single repo. Wrap it in a loop.
- **Organization-specific rules.** Banned functions, required headers, internal API patterns. Feed them into the subagent prompts via a config file.

## References

- [Claude Agent SDK documentation](https://platform.claude.com/docs/en/agent-sdk/overview)
- [Building effective agents](https://www.anthropic.com/engineering/building-effective-agents)
- [Python sibling implementation](https://github.com/ashwinmudaliar/claude-agent-sdk-security-investigator)
