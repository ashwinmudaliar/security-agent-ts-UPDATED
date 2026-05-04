/**
 * Security Investigation Agent — Claude Agent SDK (TypeScript).
 *
 * Point it at a codebase, get back a reasoned security audit:
 *
 *     npx tsx agent.ts /path/to/repo
 *
 * The orchestrator (Sonnet 4.6) does reconnaissance, delegates to two focused
 * subagents (Haiku 4.5) — one for code, one for config/dependencies — collects
 * their findings, then hands the merged set to a third subagent (remediation,
 * Haiku 4.5) which drafts fixes. The orchestrator synthesizes everything with
 * extended thinking. Two hooks: a PreToolUse guardrail that blocks code
 * execution from the target repo, and a PostToolUse hook that writes an audit
 * trail of every Read/Grep/Glob/Bash call.
 *
 * Subagent definitions and prompts live at the top of this file. To repurpose
 * this agent (compliance audit, code review, due diligence), edit those.
 */

import { writeFile, stat } from "node:fs/promises";
import { resolve as resolvePath, basename } from "node:path";
import { performance } from "node:perf_hooks";
import process from "node:process";

import {
  createSdkMcpServer,
  query,
  tool,
  type AgentDefinition,
  type Options,
  type PreToolUseHookInput,
  type PostToolUseHookInput,
  type HookCallback,
  type HookJSONOutput,
} from "@anthropic-ai/claude-agent-sdk";
import { z } from "zod";

import "dotenv/config";

// ----------------------------------------------------------------------------
// Configuration — the bits worth changing live here.
// ----------------------------------------------------------------------------

const ORCHESTRATOR_MODEL = "claude-sonnet-4-6";
const SUBAGENT_MODEL: AgentDefinition["model"] = "haiku"; // Haiku 4.5

const REPORT_PATH = "security-report.md";
const AUDIT_LOG_PATH = "investigation-log.json";

const SUBAGENTS: Record<string, AgentDefinition> = {
  "code-analysis": {
    description:
      "Reads source code to find logic-level vulnerabilities: data flow " +
      "from user input to dangerous sinks, missing auth, dangerous " +
      "function usage, weak crypto, error handling that leaks PII or " +
      "stack traces.",
    prompt: `You are a senior application security engineer auditing source code.

Your mandate is logic-level vulnerabilities in the application code itself —
NOT dependencies and NOT configuration. The other subagent owns those.

Investigate, in priority order:

1. Data flow from untrusted input (HTTP params, headers, body, files, env)
   through to dangerous sinks: SQL queries, shell/subprocess, eval/exec,
   filesystem paths, deserialization, template rendering, redirects.
2. Authentication and authorization: missing middleware, decorators, or
   guards on sensitive routes; privilege-escalation paths; broken object-
   level authorization.
3. Dangerous function usage: eval, exec, child_process with shell=true,
   pickle.loads on untrusted data, yaml.load (unsafe), os.system, etc.
4. Cryptography: weak hashes (MD5, SHA1) for passwords, ECB mode, hardcoded
   keys/IVs, missing constant-time comparison.
5. Error handling: stack traces returned to clients, sensitive data in logs.

Reason about EXPLOITABILITY, not just pattern matches. An eval() over a
hardcoded constant is LOW. An eval() over a query parameter is CRITICAL.
Trace the input path before assigning severity.

Use Read, Grep, and Glob to navigate the codebase. Read the entry points
first (route definitions, main files), then follow data flows.

Return findings as a JSON array. Each finding MUST have these fields:

    {
      "id":            "CA-1", "CA-2", ... (unique within this subagent),
      "title":         "Short imperative description",
      "severity":      "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
      "category":      "injection" | "auth" | "crypto" | "deserialization" |
                       "dangerous-function" | "info-disclosure" | "other",
      "location":      "relative/path:LINE" or "relative/path:START-END",
      "description":   "What the issue is, in plain language.",
      "evidence":      "The actual code snippet or pattern observed.",
      "exploitability":"How an attacker would reach this — the input path.",
      "remediation":   "Concrete fix, ideally with a code suggestion."
    }

Also note things the codebase does WELL (parameterized queries elsewhere,
proper auth on most routes, etc.) under a "positive_observations" key.

Final output format:

    {
      "findings": [ ... ],
      "positive_observations": [ "...", "..." ],
      "files_reviewed": [ "path/to/file", ... ]
    }

Output ONLY the JSON. No prose around it.`,
    tools: ["Read", "Grep", "Glob"],
    skills: ["flask-vulnerabilities"],
    model: SUBAGENT_MODEL,
  },
  "deps-and-config": {
    description:
      "Reads dependency manifests, lockfiles, and configuration files. " +
      "Hunts for hardcoded secrets, vulnerable dependency versions, " +
      "and insecure defaults (debug mode, permissive CORS, exposed " +
      "ports, missing security headers).",
    prompt: `You are a senior application security engineer auditing the
non-code surface of a project — dependencies, config, secrets.

Your mandate (the code-analysis subagent owns application logic):

1. Dependency manifests: requirements.txt, package.json, Cargo.toml, go.mod,
   Gemfile, pom.xml, build.gradle. Flag pinned versions known to be
   vulnerable. Flag unpinned ranges that pull in vulnerable transitive deps.

   For EVERY dependency you suspect is vulnerable, confirm against GitHub's
   security advisory database using the GitHub MCP tools:
     • \`mcp__github__list_global_security_advisories\` — search by ecosystem
       (\`pip\`, \`npm\`, \`maven\`, \`rubygems\`, \`go\`, \`rust\`, etc.) and
       package name to enumerate published advisories.
     • \`mcp__github__get_global_security_advisory\` — fetch the full record
       (CVE ID, GHSA ID, CVSS score, affected ranges, patched versions) for
       a specific GHSA ID.
   When a finding is backed by a confirmed advisory, include in its
   \`description\` and \`evidence\` fields: the CVE ID (e.g. CVE-2023-12345),
   the GHSA ID, the CVSS severity, the affected version range, and the
   first fixed version. Put the upgrade target into \`remediation\`. If no
   advisory matches, say so explicitly so the orchestrator can downgrade.
2. Hardcoded secrets: API keys, tokens, private keys, DB passwords, JWT
   secrets in .env files, config files, source files (yes, source — secrets
   are config-shaped wherever they live).
3. Insecure defaults: DEBUG=True in production-style configs, permissive
   CORS (origins='*' especially with credentials), bind to 0.0.0.0,
   missing security headers (CSP, HSTS), exposed admin interfaces,
   default credentials.
4. Run dependency audit tools where available — try \`pip audit\`, \`npm audit
   --json\`, etc. Use Bash for these. If they aren't installed, note that
   and skip rather than failing.

Use Read, Grep, Glob, Bash, and the GitHub advisory MCP tools
(\`mcp__github__list_global_security_advisories\`,
\`mcp__github__get_global_security_advisory\`). NEVER execute application code
itself (don't run \`python app.py\`, \`node index.js\`, etc.) — only run audit
tools and inspection commands. The PreToolUse hook will block execution
attempts anyway, but don't try.

Return findings as a JSON array using the same schema as the code-analysis
subagent (use \`id\` prefix "DC-" — DC-1, DC-2, ...):

    {
      "id", "title", "severity", "category", "location",
      "description", "evidence", "exploitability", "remediation"
    }

Categories you'll commonly use here: "secrets", "vulnerable-dependency",
"insecure-config", "cors", "debug-mode", "exposure".

Final output:

    {
      "findings": [ ... ],
      "positive_observations": [ ... ],
      "files_reviewed": [ ... ]
    }

Output ONLY the JSON. No prose around it.`,
    tools: [
      "Read",
      "Grep",
      "Glob",
      "Bash",
      "mcp__github__list_global_security_advisories",
      "mcp__github__get_global_security_advisory",
    ],
    model: SUBAGENT_MODEL,
  },
  remediation: {
    description:
      "Receives the merged findings from code-analysis and deps-and-config " +
      "and drafts a concrete suggested fix for each one. Read-only — never " +
      "modifies files in the target repo. Output is text (code snippet, " +
      "config change, or process change) that lands in the final report.",
    prompt: `You are a senior application security engineer drafting fixes
for a set of findings produced by two upstream auditors (code-analysis and
deps-and-config). Your job is REMEDIATION ONLY — you do not re-audit, do not
add new findings, and do not modify any files. Fixes are text the report
will display under each finding.

You will receive a JSON payload that contains the merged findings list:

    {
      "findings": [
        { "id", "title", "severity", "category", "location",
          "description", "evidence", "exploitability", "remediation" },
        ...
      ]
    }

The upstream \`remediation\` field is a one-liner. Your job is to upgrade it
into a concrete, actionable fix a developer can apply in an afternoon.

For each finding:

1. Use Read, Grep, and Glob to gather just enough context — the function
   around the vulnerable line, the framework idioms in use, the existing
   code style. Do not re-derive the vulnerability; trust the finding.
2. Draft a "suggested_fix" with two parts:
   a. \`summary\` — one or two sentences describing the change.
   b. \`patch\` — the concrete change. Prefer a unified-diff-style snippet
      (\`- old\` / \`+ new\`) when the fix is code. For config or process
      changes, use the closest equivalent (\`# before\` / \`# after\`,
      or a short numbered procedure).
3. Match the codebase: same language, same framework conventions, same
   style. If a parameterized-query helper already exists, use it. If the
   project uses a specific crypto library, use that one.
4. If a finding genuinely cannot be fixed without a larger refactor, say
   so explicitly in \`summary\` and outline the smallest safe step.

DO NOT:
  - Modify any files. You have Read/Grep/Glob only — use them.
  - Invent APIs. If you're unsure a function exists, grep for it.
  - Re-rank severities or merge findings — the orchestrator owns that.
  - Output prose around the JSON.

Return EXACTLY this JSON shape:

    {
      "fixes": [
        {
          "id":             "CA-1" | "DC-3" | ...  (must match an input id),
          "summary":        "One or two sentences.",
          "patch":          "Multi-line string. Diff-style preferred.",
          "confidence":     "high" | "medium" | "low",
          "notes":          "Optional caveats — empty string if none."
        },
        ...
      ]
    }

Every finding in the input MUST have a corresponding entry in \`fixes\`,
keyed by \`id\`. Output ONLY the JSON.`,
    tools: ["Read", "Grep", "Glob"],
    model: SUBAGENT_MODEL,
  },
};

const ORCHESTRATOR_PROMPT = (reportPath: string) => `You are the lead security
investigator orchestrating an audit of an unfamiliar codebase. Your job is to
produce a reasoned, prioritized security report — not a flat list of pattern
matches.

You have three subagents available via the Task tool:

  • code-analysis    — reads application source for logic vulns
  • deps-and-config  — reads manifests, configs, env files; runs audit tools
  • remediation      — drafts a concrete fix for each finding (read-only)

WORKFLOW (follow in order):

1. RECONNAISSANCE. Use Glob and Read to map the repo:
   - Languages and frameworks
   - Entry points (main files, route definitions)
   - Dependency manifests
   - Overall size and structure
   Keep this light — you're orienting, not auditing yet.

2. DELEGATE (audit). Launch BOTH \`code-analysis\` and \`deps-and-config\`
   in parallel using the Task tool. Give each one a brief that summarizes
   what you found in recon: language(s), framework, key files to focus on.
   Do not duplicate their work.

3. MERGE FINDINGS. When both return their JSON, merge their findings into
   a single list. Preserve every \`id\` (CA-* and DC-*) — the remediation
   subagent will reference them. Do not deduplicate yet; that happens in
   synthesis after fixes are in hand.

4. DELEGATE (remediation). Launch the \`remediation\` subagent with a single
   message containing the merged findings list as JSON:

       { "findings": [ ...all findings from steps above... ] }

   Wait for it to return its \`fixes\` array. Each fix is keyed by the
   finding \`id\`.

5. SYNTHESIZE. With findings AND fixes in hand, reason carefully (extended
   thinking is enabled — use it):

   a. DEDUPLICATION. The two audit subagents may flag the same root cause
      from different angles (e.g. a hardcoded secret that's also a weak-
      crypto issue). Merge — keep the higher severity, combine evidence,
      and pick the more thorough suggested fix from the matched ids.

   b. EXPLOITABILITY FILTER. For each finding, ask: is this actually
      reachable by an attacker given the input path? Downgrade or drop
      false positives. A pattern is not a vulnerability — a reachable
      pattern is.

   c. VULNERABILITY CHAINS. Look for combinations that are worse than
      the sum of their parts. Examples: missing auth on /admin + SQL
      injection in /admin = critical full-DB compromise. Surface these
      in their own section.

   d. PRIORITIZED REMEDIATION. Order findings by severity, then by
      remediation cost (cheap wins first within a tier).

6. WRITE THE REPORT. Produce a single Markdown document in EXACTLY this
   structure (no extra top-level sections, no preamble):

\`\`\`
# Security Investigation Report

**Target:** {target path}
**Date:** {YYYY-MM-DD}
**Agent:** Claude Security Investigator (TypeScript) v1.1
**Files analyzed:** {count}

## Executive Summary

{2-3 sentences: overall posture, count by severity, top concerns.}

## Critical Findings

### [CRITICAL] {Title}
**Location:** \`{file:line}\`
**Description:** ...
**Evidence:**
\`\`\`
{code snippet}
\`\`\`
**Exploitability:** ...
**Remediation:** {short one-liner from the auditor}

**Suggested Fix:** {summary from the remediation subagent}
\`\`\`
{patch / diff / config change from the remediation subagent}
\`\`\`
{If confidence is "low" or notes are non-empty, surface them here as a one-line caveat.}

## High Findings
{same structure, [HIGH] prefix}

## Medium Findings
{same structure}

## Low Findings
{same structure}

## Vulnerability Chains

{Where multiple findings combine. If none, write "None identified.".}

## Positive Observations

{What the codebase does well. Bullet list.}

## Recommendations

{Prioritized next steps. Numbered list.}
\`\`\`

7. SAVE THE REPORT. Use the Write tool to save the markdown to
   \`${reportPath}\` (in the agent's working directory, not the target repo).
   Then print the markdown to stdout so the user sees it in the terminal.

Be specific. Cite real file paths and line numbers. Quote the actual code.
A security engineer should be able to act on this report in an afternoon.`;

// ----------------------------------------------------------------------------
// MCP server — in-process tools the deps-and-config subagent calls to look
// up CVEs in GitHub's public advisory database. No subprocess, no Docker, no
// auth required (the /advisories endpoint is public). If GITHUB_TOKEN is set
// in the env we'll use it for a higher rate limit, but it's not required.
// ----------------------------------------------------------------------------

const GITHUB_API_BASE = "https://api.github.com";

async function callGitHubAdvisoryAPI(
  path: string,
): Promise<{ status: number; body: unknown }> {
  const url = `${GITHUB_API_BASE}/${path.replace(/^\//, "")}`;
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "claude-security-investigator-ts/1.1",
  };
  if (process.env.GITHUB_TOKEN) {
    headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  }
  const res = await fetch(url, { headers });
  const text = await res.text();
  let body: unknown = text;
  try {
    body = JSON.parse(text);
  } catch {
    /* leave as raw text */
  }
  return { status: res.status, body };
}

function asToolResult(payload: unknown) {
  return {
    content: [
      {
        type: "text" as const,
        text:
          typeof payload === "string"
            ? payload
            : JSON.stringify(payload, null, 2),
      },
    ],
  };
}

const githubMcpServer = createSdkMcpServer({
  name: "github",
  version: "1.0.0",
  tools: [
    tool(
      "list_global_security_advisories",
      "Search GitHub's global security advisory database for confirmed CVEs " +
        "affecting a specific package. Returns a list of advisories with " +
        "GHSA ID, CVE ID, summary, severity, and affected/patched version " +
        "ranges. Call this first to enumerate advisories for a package, " +
        "then use get_global_security_advisory for the full record on a " +
        "specific match.",
      {
        ecosystem: z
          .enum([
            "pip",
            "npm",
            "maven",
            "rubygems",
            "nuget",
            "go",
            "rust",
            "composer",
            "actions",
            "pub",
            "swift",
            "erlang",
            "other",
          ])
          .describe("Package ecosystem the dependency belongs to."),
          package: z
          .string()
          .describe("Package name as it appears in the manifest, e.g. 'flask'."),
        severity: z
          .enum(["unknown", "low", "medium", "high", "critical"])
          .optional()
          .describe("Optional CVSS severity filter."),
        per_page: z
          .number()
          .int()
          .min(1)
          .max(100)
          .optional()
          .describe("Max results (default 30, max 100)."),
      },
      async ({ ecosystem, package: pkg, severity, per_page }) => {
        const params = new URLSearchParams({ ecosystem, affects: pkg });
        if (severity) params.set("severity", severity);
        if (per_page) params.set("per_page", String(per_page));
        const { status, body } = await callGitHubAdvisoryAPI(
          `advisories?${params.toString()}`,
        );
        if (status !== 200) {
          return asToolResult(
            `GitHub API ${status}: ${
              typeof body === "string" ? body : JSON.stringify(body)
            }`,
          );
        }
        return asToolResult(body);
      },
    ),
    tool(
      "get_global_security_advisory",
      "Fetch the complete record for a single GitHub security advisory by " +
        "its GHSA ID. Returns CVE ID, CVSS score and vector, full " +
        "description, vulnerable version ranges, first patched versions, " +
        "references, and source repository. Call this after " +
        "list_global_security_advisories on a candidate match.",
      {
        ghsa_id: z
          .string()
          .regex(/^GHSA-[\w-]+$/i)
          .describe("GitHub Security Advisory ID, e.g. 'GHSA-68rp-wp8r-4726'."),
      },
      async ({ ghsa_id }) => {
        const { status, body } = await callGitHubAdvisoryAPI(
          `advisories/${ghsa_id}`,
        );
        if (status !== 200) {
          return asToolResult(
            `GitHub API ${status}: ${
              typeof body === "string" ? body : JSON.stringify(body)
            }`,
          );
        }
        return asToolResult(body);
      },
    ),
  ],
});

// ----------------------------------------------------------------------------
// Hooks — safety guardrail + audit trail.
// ----------------------------------------------------------------------------

// Tokens that indicate "execute application code" rather than "inspect it".
const EXECUTORS = new Set([
  "python", "python2", "python3", "py",
  "node", "nodejs", "ts-node", "tsx", "deno", "bun",
  "ruby", "rb", "perl", "php", "lua",
  "go", "cargo", "rustc",
  "java", "javac", "scala", "kotlin", "kotlinc",
  "sh", "bash", "zsh", "fish",
  "flask", "uvicorn", "gunicorn", "hypercorn", "fastapi",
  "rails", "puma", "unicorn",
  "make", "ninja",
  "docker", "docker-compose", "podman",
  "pytest", "unittest", "jest", "mocha", "vitest",
]);

// Audit/inspection tools that are explicitly allowed even though they're Bash.
const ALLOWED_AUDIT_PREFIXES = [
  "pip ", "pip3 ", "pip-audit", "pip_audit",
  "npm audit", "npm ls", "npm list", "npm view", "npm outdated",
  "yarn audit",
  "pnpm audit",
  "cargo audit", "cargo tree",
  "bundle audit", "bundler-audit",
  "safety check", "safety scan",
  "grep ", "egrep ", "fgrep ", "rg ",
  "find ", "ls", "wc ", "head ", "tail ", "cat ",
  "file ", "stat ", "du ", "tree",
  "git ", "jq ",
  "echo ",
];

/** Tokenize a shell command, naively. Good enough for the heuristic. */
function shellTokens(cmd: string): string[] {
  // Split on whitespace, handling quoted segments minimally. For deeper
  // parsing we'd reach for a shell parser, but the heuristic only needs
  // to identify the executable + obvious arg paths.
  const tokens: string[] = [];
  let buf = "";
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i]!;
    if (c === "'" && !inDouble) {
      inSingle = !inSingle;
      continue;
    }
    if (c === '"' && !inSingle) {
      inDouble = !inDouble;
      continue;
    }
    if (c === "\\" && i + 1 < cmd.length) {
      buf += cmd[i + 1]!;
      i++;
      continue;
    }
    if (/\s/.test(c) && !inSingle && !inDouble) {
      if (buf) {
        tokens.push(buf);
        buf = "";
      }
      continue;
    }
    buf += c;
  }
  if (buf) tokens.push(buf);
  return tokens;
}

function isExecutionCommand(
  cmd: string,
  targetRoot: string,
): { block: boolean; reason: string } {
  const stripped = cmd.trim();
  if (!stripped) return { block: false, reason: "" };

  const lowered = stripped.toLowerCase();
  for (const prefix of ALLOWED_AUDIT_PREFIXES) {
    if (lowered.startsWith(prefix)) return { block: false, reason: "" };
  }

  const tokens = shellTokens(stripped);
  if (tokens.length === 0) return { block: false, reason: "" };

  const head = basename(tokens[0]!).toLowerCase();

  if (EXECUTORS.has(head)) {
    const targetAbs = resolvePath(targetRoot);
    for (const arg of tokens.slice(1)) {
      if (arg.startsWith("-")) continue;
      let argAbs: string;
      try {
        argAbs = resolvePath(arg);
      } catch {
        continue;
      }
      if (
        argAbs.startsWith(targetAbs) ||
        arg === targetRoot ||
        arg === targetAbs
      ) {
        return {
          block: true,
          reason:
            `Blocked: \`${head}\` would execute code from the target ` +
            `repo (${arg}). The investigator must read and analyze ` +
            `code, not run it.`,
        };
      }
    }
  }

  // Catch-all: install commands can run setup scripts. Block.
  const installSignatures = [
    "pip install", "pip3 install",
    "npm install", "yarn install", "pnpm install",
  ];
  if (installSignatures.some((sig) => lowered.includes(sig))) {
    return {
      block: true,
      reason:
        "Blocked: install commands can execute arbitrary code via " +
        "setup scripts. Use audit subcommands instead " +
        "(pip audit, npm audit, etc.).",
    };
  }

  return { block: false, reason: "" };
}

function makePreToolHook(targetRoot: string): HookCallback {
  return async (input): Promise<HookJSONOutput> => {
    const hook = input as PreToolUseHookInput;
    if (hook.tool_name !== "Bash") return {};
    const cmd = (hook.tool_input as { command?: string })?.command ?? "";
    const { block, reason } = isExecutionCommand(cmd, targetRoot);
    if (block) {
      return {
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: "deny",
          permissionDecisionReason: reason,
        },
        systemMessage: reason,
      };
    }
    return {};
  };
}

interface AuditEntry {
  timestamp: string;
  tool: string;
  agent_type?: string;
  input: unknown;
  summary: string;
}

function makePostToolHook(auditLog: AuditEntry[]): HookCallback {
  return async (input): Promise<HookJSONOutput> => {
    const hook = input as PostToolUseHookInput;
    const tool = hook.tool_name;
    const toolInput = (hook.tool_input ?? {}) as Record<string, unknown>;

    let summary: string;
    switch (tool) {
      case "Read":
        summary = `read ${toolInput.file_path ?? ""}`;
        break;
      case "Grep":
        summary =
          `grep ${JSON.stringify(toolInput.pattern ?? "")} ` +
          `path=${toolInput.path ?? "."} glob=${toolInput.glob ?? "*"}`;
        break;
      case "Glob":
        summary =
          `glob ${toolInput.pattern ?? ""} path=${toolInput.path ?? "."}`;
        break;
      case "Bash":
        summary = `bash: ${toolInput.command ?? ""}`;
        break;
      default:
        summary = tool;
    }

    auditLog.push({
      timestamp: new Date().toISOString(),
      tool,
      agent_type: (hook as { agent_type?: string }).agent_type,
      input: toolInput,
      summary,
    });
    return {};
  };
}

// ----------------------------------------------------------------------------
// Runner.
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// Progress streamer — tag every line with the subagent that emitted it.
// ----------------------------------------------------------------------------
//
// Every message streamed by query() carries `parent_tool_use_id`. When the
// orchestrator delegates via a Task/Agent tool call, we record that tool's
// `id` against its `subagent_type`. Subsequent messages from the subagent
// arrive with `parent_tool_use_id` matching that id — which lets us tag every
// downstream tool_use / thinking line with the right subagent.

const SUBAGENT_LABEL: Record<string, string> = {
  orchestrator: "orch",
  "code-analysis": "code",
  "deps-and-config": "deps",
  remediation: "remed",
};

const SUBAGENT_COLOR: Record<string, string> = {
  orchestrator: "\x1b[36m", // cyan
  "code-analysis": "\x1b[34m", // blue
  "deps-and-config": "\x1b[35m", // magenta
  remediation: "\x1b[32m", // green
};
const COLOR_RESET = "\x1b[0m";

function tagFor(subagent: string): string {
  const label = (SUBAGENT_LABEL[subagent] ?? "??").padEnd(5);
  const color = SUBAGENT_COLOR[subagent] ?? SUBAGENT_COLOR.orchestrator!;
  return `${color}[${label}]${COLOR_RESET}`;
}

function formatToolUse(name: string, inp: Record<string, unknown>): string {
  if (name === "Read") return `· read ${inp.file_path ?? ""}`;
  if (name === "Glob") return `· glob ${inp.pattern ?? ""}`;
  if (name === "Grep") return `· grep ${JSON.stringify(inp.pattern ?? "")}`;
  if (name === "Bash") {
    const cmd = String(inp.command ?? "");
    return `· bash ${cmd.slice(0, 70)}`;
  }
  if (name === "Write") return `· write ${inp.file_path ?? ""}`;
  return `· ${name}`;
}

async function pathExists(p: string): Promise<boolean> {
  try {
    await stat(p);
    return true;
  } catch {
    return false;
  }
}

async function runInvestigation(targetArg: string): Promise<number> {
  const target = resolvePath(targetArg);
  const targetStat = await stat(target).catch(() => null);
  if (!targetStat || !targetStat.isDirectory()) {
    process.stderr.write(`error: ${target} is not a directory\n`);
    return 2;
  }

  const auditLog: AuditEntry[] = [];

  // Optional scope override. When INVESTIGATION_SCOPE is set (newline-separated
  // relative paths), the orchestrator runs a partial audit focused on those
  // files plus their immediate dependencies. Used by the webhook server to
  // run cheap per-PR audits over only the changed files.
  const scopeRaw = process.env.INVESTIGATION_SCOPE?.trim();
  const scopePaths = scopeRaw
    ? scopeRaw.split(/\r?\n/).map((p) => p.trim()).filter(Boolean)
    : [];
  const scopeBlock =
    scopePaths.length > 0
      ? `\nSCOPE OVERRIDE — partial PR audit, NOT a full-repo investigation.\n` +
        `Focus your analysis on these changed files (relative to the target):\n` +
        scopePaths.map((p) => `  - ${p}`).join("\n") +
        `\n\nRead these files and any code paths they import or that import\n` +
        `them. Do not audit unrelated parts of the repo. The remediation phase\n` +
        `still applies to the findings produced from this scope.\n`
      : "";

  const today = new Date().toISOString().slice(0, 10);
  const userPrompt =
    `Investigate the codebase at: ${target}\n\n` +
    `Today's date is ${today}.\n\n` +
    `Follow your workflow: reconnaissance, parallel audit-subagent ` +
    `delegation (code-analysis + deps-and-config), then remediation ` +
    `subagent on the merged findings, then synthesis with extended ` +
    `thinking. Write the final report to ` +
    `\`${resolvePath(REPORT_PATH)}\` and print it to stdout.` +
    scopeBlock;

  const options: Options = {
    model: ORCHESTRATOR_MODEL,
    systemPrompt: ORCHESTRATOR_PROMPT(REPORT_PATH),
    agents: SUBAGENTS,
    mcpServers: {
      github: githubMcpServer,
    },
    allowedTools: [
      "Read",
      "Grep",
      "Glob",
      "Bash",
      "Task",
      "Write",
      "mcp__github__list_global_security_advisories",
      "mcp__github__get_global_security_advisory",
    ],
    permissionMode: "bypassPermissions",
    allowDangerouslySkipPermissions: true,
    persistSession: false,
    // Load project-level settings so the SDK discovers skills under
    // `.claude/skills/` (the `code-analysis` subagent declares it via
    // `skills: ['flask-vulnerabilities']`).
    settingSources: ["project"],
    additionalDirectories: [target],
    maxThinkingTokens: 10000,
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
      PostToolUseFailure: [
        {
          matcher: "Read|Grep|Glob|Bash",
          hooks: [makePostToolHook(auditLog)],
        },
      ],
    },
    maxTurns: 80,
    stderr: (data: string) => process.stderr.write(`[cli] ${data}`),
  };

  process.stdout.write(`▸ Investigating ${target}\n`);
  process.stdout.write(
    `▸ Orchestrator: ${ORCHESTRATOR_MODEL}  |  Subagents: ${SUBAGENT_MODEL}\n\n`,
  );

  const started = performance.now();
  const finalTextParts: string[] = [];
  let totalCost: number | null = null;

  let sawResult = false;
  // Maps a Task/Agent tool_use id → the subagent_type it delegated to. Filled
  // when we observe the orchestrator's delegation; consumed when downstream
  // messages from that subagent arrive carrying parent_tool_use_id.
  const subagentByToolUseId = new Map<string, string>();

  try {
    for await (const msg of query({ prompt: userPrompt, options })) {
      const m = msg as {
        type?: string;
        parent_tool_use_id?: string | null;
        message?: {
          content?: Array<{
            type?: string;
            name?: string;
            id?: string;
            text?: string;
            input?: Record<string, unknown>;
          }>;
        };
      };

      if (m.type === "result") {
        sawResult = true;
        totalCost = (msg as { total_cost_usd?: number }).total_cost_usd ?? null;
        continue;
      }

      if (m.type !== "assistant" || !m.message?.content) continue;

      const subagent = m.parent_tool_use_id
        ? subagentByToolUseId.get(m.parent_tool_use_id) ?? "orchestrator"
        : "orchestrator";
      const tag = tagFor(subagent);

      for (const block of m.message.content) {
        if (block.type === "text" && typeof block.text === "string") {
          finalTextParts.push(block.text);
          continue;
        }
        if (block.type === "thinking") {
          process.stdout.write(`${tag} … thinking\n`);
          continue;
        }
        if (block.type === "tool_use") {
          const name = block.name ?? "";
          const inp = (block.input ?? {}) as Record<string, unknown>;
          const id = block.id ?? "";

          // Record subagent delegation so later messages are attributed.
          if ((name === "Task" || name === "Agent") && inp.subagent_type && id) {
            subagentByToolUseId.set(id, String(inp.subagent_type));
            process.stdout.write(
              `${tag} → delegating to ${inp.subagent_type}\n`,
            );
            continue;
          }

          process.stdout.write(`${tag} ${formatToolUse(name, inp)}\n`);
        }
      }
    }
  } catch (err) {
    // The bundled Claude Code CLI sometimes exits with code 1 on shutdown
    // after the result message. If we already received a result, treat
    // the run as successful and continue to finalization.
    const msg = (err as Error)?.message ?? String(err);
    if (sawResult && /exited with code/i.test(msg)) {
      // Quiet swallow — investigation completed.
    } else {
      throw err;
    }
  } finally {
    const elapsed = (performance.now() - started) / 1000;

    // Persist the audit log regardless of how the run ended.
    await writeFile(
      AUDIT_LOG_PATH,
      JSON.stringify(
        {
          target,
          started_at: new Date(Date.now() - elapsed * 1000).toISOString(),
          duration_seconds: Number(elapsed.toFixed(2)),
          tool_calls: auditLog,
        },
        null,
        2,
      ),
    );

    // Fallback: if the orchestrator forgot to use Write, write the streamed text.
    if (!(await pathExists(REPORT_PATH)) && finalTextParts.length > 0) {
      await writeFile(REPORT_PATH, finalTextParts.join(""));
    }

    process.stdout.write(`\n✓ Done in ${elapsed.toFixed(1)}s\n`);
    if (totalCost != null) {
      process.stdout.write(`  cost: $${totalCost.toFixed(4)}\n`);
    }
    process.stdout.write(`  report:    ${resolvePath(REPORT_PATH)}\n`);
    process.stdout.write(
      `  audit log: ${resolvePath(AUDIT_LOG_PATH)}  (${auditLog.length} tool calls)\n`,
    );
  }

  return 0;
}

async function main(): Promise<number> {
  const args = process.argv.slice(2);
  if (args.length !== 1) {
    process.stderr.write("usage: npx tsx agent.ts <path-to-repo>\n");
    return 2;
  }
  return runInvestigation(args[0]!);
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    process.stderr.write(`fatal: ${err?.stack ?? err}\n`);
    process.exit(1);
  });
