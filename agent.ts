/**
 * Security Investigation Agent — Claude Agent SDK (TypeScript).
 *
 * Point it at a codebase, get back a reasoned security audit:
 *
 *     npx tsx agent.ts /path/to/repo
 *
 * The orchestrator (Sonnet 4.6) does reconnaissance, delegates to two focused
 * subagents (Haiku 4.5) — one for code, one for config/dependencies — and
 * synthesizes their findings with extended thinking. Two hooks: a PreToolUse
 * guardrail that blocks code execution from the target repo, and a PostToolUse
 * hook that writes an audit trail of every Read/Grep/Glob/Bash call.
 *
 * Subagent definitions and prompts live at the top of this file. To repurpose
 * this agent (compliance audit, code review, due diligence), edit those.
 */

import { writeFile, stat } from "node:fs/promises";
import { resolve as resolvePath, basename } from "node:path";
import { performance } from "node:perf_hooks";
import process from "node:process";

import {
  query,
  type AgentDefinition,
  type Options,
  type PreToolUseHookInput,
  type PostToolUseHookInput,
  type HookCallback,
  type HookJSONOutput,
} from "@anthropic-ai/claude-agent-sdk";

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

Use Read, Grep, Glob, and Bash. NEVER execute application code itself
(don't run \`python app.py\`, \`node index.js\`, etc.) — only run audit tools
and inspection commands. The PreToolUse hook will block execution attempts
anyway, but don't try.

Return findings as a JSON array using the same schema as the code-analysis
subagent:

    {
      "title", "severity", "category", "location",
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
    tools: ["Read", "Grep", "Glob", "Bash"],
    model: SUBAGENT_MODEL,
  },
};

const ORCHESTRATOR_PROMPT = (reportPath: string) => `You are the lead security
investigator orchestrating an audit of an unfamiliar codebase. Your job is to
produce a reasoned, prioritized security report — not a flat list of pattern
matches.

You have two subagents available via the Task tool:

  • code-analysis    — reads application source for logic vulns
  • deps-and-config  — reads manifests, configs, env files; runs audit tools

WORKFLOW (follow in order):

1. RECONNAISSANCE. Use Glob and Read to map the repo:
   - Languages and frameworks
   - Entry points (main files, route definitions)
   - Dependency manifests
   - Overall size and structure
   Keep this light — you're orienting, not auditing yet.

2. DELEGATE. Launch BOTH subagents in parallel using the Task tool. Give
   each one a brief that summarizes what you found in recon: language(s),
   framework, key files to focus on. Do not duplicate their work.

3. SYNTHESIZE. After both return their JSON findings, reason carefully
   (extended thinking is enabled — use it):

   a. DEDUPLICATION. The two subagents may flag the same root cause from
      different angles (e.g. a hardcoded secret that's also a weak-crypto
      issue). Merge.

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

4. WRITE THE REPORT. Produce a single Markdown document in EXACTLY this
   structure (no extra top-level sections, no preamble):

\`\`\`
# Security Investigation Report

**Target:** {target path}
**Date:** {YYYY-MM-DD}
**Agent:** Claude Security Investigator (TypeScript) v1.0
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
**Remediation:** ...

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

5. SAVE THE REPORT. Use the Write tool to save the markdown to
   \`${reportPath}\` (in the agent's working directory, not the target repo).
   Then print the markdown to stdout so the user sees it in the terminal.

Be specific. Cite real file paths and line numbers. Quote the actual code.
A security engineer should be able to act on this report in an afternoon.`;

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

/** Surface a short progress line for an assistant message, if interesting. */
function formatProgress(message: unknown): string | null {
  const m = message as {
    type?: string;
    message?: { content?: Array<{ type?: string; name?: string; input?: Record<string, unknown> }> };
  };
  if (m.type !== "assistant" || !m.message?.content) return null;
  for (const block of m.message.content) {
    if (block.type === "tool_use") {
      const name = block.name ?? "";
      const inp = (block.input ?? {}) as Record<string, unknown>;
      if (name === "Task") {
        return `  → delegating to ${inp.subagent_type ?? "?"} subagent`;
      }
      if (name === "Read") return `  · read ${inp.file_path ?? ""}`;
      if (name === "Glob") return `  · glob ${inp.pattern ?? ""}`;
      if (name === "Grep") return `  · grep ${JSON.stringify(inp.pattern ?? "")}`;
      if (name === "Bash") {
        const cmd = String(inp.command ?? "");
        return `  · bash ${cmd.slice(0, 80)}`;
      }
      if (name === "Write") return `  · write ${inp.file_path ?? ""}`;
      return `  · ${name}`;
    }
    if (block.type === "thinking") return "  … thinking";
  }
  return null;
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

  const today = new Date().toISOString().slice(0, 10);
  const userPrompt =
    `Investigate the codebase at: ${target}\n\n` +
    `Today's date is ${today}.\n\n` +
    `Follow your workflow: reconnaissance, parallel subagent delegation, ` +
    `synthesis with extended thinking, then write the final report to ` +
    `\`${resolvePath(REPORT_PATH)}\` and print it to stdout.`;

  const options: Options = {
    model: ORCHESTRATOR_MODEL,
    systemPrompt: ORCHESTRATOR_PROMPT(REPORT_PATH),
    agents: SUBAGENTS,
    allowedTools: ["Read", "Grep", "Glob", "Bash", "Task", "Write"],
    permissionMode: "bypassPermissions",
    allowDangerouslySkipPermissions: true,
    persistSession: false,
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
    maxTurns: 60,
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
  try {
    for await (const msg of query({ prompt: userPrompt, options })) {
      const line = formatProgress(msg);
      if (line) process.stdout.write(line + "\n");

      if (msg.type === "assistant" && msg.message?.content) {
        for (const block of msg.message.content as Array<{
          type?: string;
          text?: string;
        }>) {
          if (block.type === "text" && typeof block.text === "string") {
            finalTextParts.push(block.text);
          }
        }
      }
      if (msg.type === "result") {
        sawResult = true;
        totalCost = (msg as { total_cost_usd?: number }).total_cost_usd ?? null;
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
