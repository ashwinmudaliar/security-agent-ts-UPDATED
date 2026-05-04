/**
 * GitHub PR-review webhook server. Wraps the upgraded security investigator
 * (../agent.ts) and runs it against the changed files of every PR
 * that GitHub posts to /webhook.
 *
 * Flow per PR:
 *   1. POST /webhook receives the GitHub pull_request payload.
 *   2. Verify the X-Hub-Signature-256 HMAC against GITHUB_WEBHOOK_SECRET.
 *   3. Filter for action ∈ {opened, synchronize}.
 *   4. Respond 202 immediately (GitHub's hook timeout is ~10s; the audit takes
 *      minutes), then process in the background.
 *   5. List changed files via the GitHub API.
 *   6. Clone the base repo and check out `pull/<N>/head` (works for fork PRs).
 *   7. Spawn `npx tsx agent.ts <repo>` with INVESTIGATION_SCOPE set
 *      to the changed-file list — the agent runs a focused audit.
 *   8. Read security-report.md, post it as a PR comment via the issues API.
 *   9. Clean up the temp work dir.
 *
 * Env (loaded via dotenv):
 *   ANTHROPIC_API_KEY        - passed through to the agent
 *   GITHUB_TOKEN             - clones private repos, posts the PR comment
 *   GITHUB_WEBHOOK_SECRET    - HMAC secret configured on the GitHub webhook
 *   PORT                     - default 3000
 */

import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { spawn } from "node:child_process";
import { createHmac, timingSafeEqual } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import {
  dirname,
  join as joinPath,
  resolve as resolvePath,
} from "node:path";
import { fileURLToPath } from "node:url";
import process from "node:process";

import "dotenv/config";

// ----------------------------------------------------------------------------
// Config
// ----------------------------------------------------------------------------

const PORT = Number(process.env.PORT ?? 3000);
const SECRET = requireEnv("GITHUB_WEBHOOK_SECRET");
const GH_TOKEN = requireEnv("GITHUB_TOKEN");
const ANTHROPIC_API_KEY = requireEnv("ANTHROPIC_API_KEY");

const SERVER_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolvePath(SERVER_DIR, "..");
const AGENT_PATH = joinPath(REPO_ROOT, "agent.ts");

const AGENT_TIMEOUT_MS = 15 * 60 * 1000; // 15 min hard cap per PR
const COMMENT_BODY_LIMIT = 60_000; // GitHub's hard limit is 65,536

// ----------------------------------------------------------------------------
// Server
// ----------------------------------------------------------------------------

const app = new Hono();

app.get("/health", (c) => c.text("ok"));

app.post("/webhook", async (c) => {
  const sig = c.req.header("X-Hub-Signature-256") ?? "";
  const event = c.req.header("X-GitHub-Event") ?? "";
  const delivery = c.req.header("X-GitHub-Delivery") ?? "?";
  const body = await c.req.text(); // raw text — must not re-encode for HMAC

  if (!verifySignature(body, sig, SECRET)) {
    log(delivery, "rejected: invalid signature");
    return c.text("invalid signature", 401);
  }

  if (event === "ping") {
    log(delivery, "ping ok");
    return c.json({ ok: true, message: "pong" });
  }

  if (event !== "pull_request") {
    log(delivery, `ignored event=${event}`);
    return c.text(`ignored: event=${event}`, 202);
  }

  let payload: PullRequestPayload;
  try {
    payload = JSON.parse(body);
  } catch {
    return c.text("invalid json", 400);
  }

  const action = payload.action;
  if (action !== "opened" && action !== "synchronize") {
    log(delivery, `ignored action=${action}`);
    return c.text(`ignored: action=${action}`, 202);
  }

  const job = {
    delivery,
    owner: payload.repository.owner.login,
    repo: payload.repository.name,
    prNumber: payload.pull_request.number,
    headSha: payload.pull_request.head.sha,
    cloneUrl: payload.repository.clone_url,
  };

  log(delivery, `accepted ${job.owner}/${job.repo}#${job.prNumber} action=${action} sha=${job.headSha.slice(0, 7)}`);

  // Fire-and-forget. Webhook handler returns within milliseconds; the audit
  // runs in the background and posts a comment when done (or when it fails).
  processPR(job).catch((err) => {
    log(delivery, `FAILED ${job.owner}/${job.repo}#${job.prNumber}: ${(err as Error).message}`);
    postFailureComment(job, err as Error).catch((postErr) => {
      log(delivery, `also failed to post failure comment: ${(postErr as Error).message}`);
    });
  });

  return c.text(`accepted: ${job.owner}/${job.repo}#${job.prNumber}`, 202);
});

// ----------------------------------------------------------------------------
// Signature verification
// ----------------------------------------------------------------------------

function verifySignature(body: string, sig: string, secret: string): boolean {
  if (!sig.startsWith("sha256=")) return false;
  const expected =
    "sha256=" + createHmac("sha256", secret).update(body).digest("hex");
  if (sig.length !== expected.length) return false;
  try {
    return timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
  } catch {
    return false;
  }
}

// ----------------------------------------------------------------------------
// PR processing
// ----------------------------------------------------------------------------

interface Job {
  delivery: string;
  owner: string;
  repo: string;
  prNumber: number;
  headSha: string;
  cloneUrl: string;
}

async function processPR(job: Job): Promise<void> {
  const { delivery, owner, repo, prNumber, headSha } = job;
  const tag = `${owner}/${repo}#${prNumber}`;

  // 1. Enumerate changed files.
  const files = await ghFetch<Array<{ filename: string; status: string }>>(
    `/repos/${owner}/${repo}/pulls/${prNumber}/files?per_page=100`,
  );
  const scopePaths = files
    .filter((f) => f.status !== "removed")
    .map((f) => f.filename);

  if (scopePaths.length === 0) {
    log(delivery, `${tag}: no files in scope, skipping`);
    return;
  }
  log(delivery, `${tag}: scope = ${scopePaths.length} files`);

  // 2. Clone repo + checkout PR head. The pull/N/head ref works for fork PRs
  //    too, so we don't need to switch on payload.pull_request.head.repo.
  const workDir = await mkdtemp(joinPath(tmpdir(), "secinv-"));
  const repoDir = joinPath(workDir, "repo");

  try {
    await runCmd("git", [
      "clone",
      "--quiet",
      "--no-tags",
      buildAuthedCloneUrl(job.cloneUrl),
      repoDir,
    ]);
    await runCmd("git", [
      "-C",
      repoDir,
      "fetch",
      "--quiet",
      "--no-tags",
      "origin",
      `pull/${prNumber}/head:pr-${prNumber}`,
    ]);
    await runCmd("git", [
      "-C",
      repoDir,
      "checkout",
      "--quiet",
      `pr-${prNumber}`,
    ]);

    // 3. Run the agent. INVESTIGATION_SCOPE makes it focus on the changed
    //    files only. Output lands in {workDir}/security-report.md.
    log(delivery, `${tag}: starting agent`);
    const started = Date.now();
    await runCmd(
      "npx",
      ["tsx", AGENT_PATH, repoDir],
      {
        cwd: workDir,
        timeoutMs: AGENT_TIMEOUT_MS,
        env: {
          ...process.env,
          ANTHROPIC_API_KEY,
          GITHUB_TOKEN: GH_TOKEN,
          INVESTIGATION_SCOPE: scopePaths.join("\n"),
        },
      },
    );
    log(delivery, `${tag}: agent finished in ${Math.round((Date.now() - started) / 1000)}s`);

    // 4. Read report, format, post.
    const reportPath = joinPath(workDir, "security-report.md");
    const report = await readFile(reportPath, "utf-8");
    const comment = formatPRComment({
      report,
      headSha,
      scopeCount: scopePaths.length,
    });

    await ghFetch(`/repos/${owner}/${repo}/issues/${prNumber}/comments`, {
      method: "POST",
      body: JSON.stringify({ body: comment }),
    });
    log(delivery, `${tag}: comment posted`);
  } finally {
    await rm(workDir, { recursive: true, force: true });
  }
}

async function postFailureComment(job: Job, err: Error): Promise<void> {
  const body =
    `## :warning: Security Investigator failed\n\n` +
    `The audit for commit \`${job.headSha.slice(0, 7)}\` did not complete.\n\n` +
    "```\n" +
    String(err.message ?? err).slice(0, 1500) +
    "\n```\n\n" +
    `Push another commit to retry.`;
  await ghFetch(
    `/repos/${job.owner}/${job.repo}/issues/${job.prNumber}/comments`,
    { method: "POST", body: JSON.stringify({ body }) },
  );
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

function buildAuthedCloneUrl(httpsUrl: string): string {
  // GitHub-style token-in-URL clone. Works for both PATs and installation
  // tokens. For public repos this just acts as auth for higher rate limits.
  return httpsUrl.replace(
    "https://",
    `https://x-access-token:${GH_TOKEN}@`,
  );
}

async function ghFetch<T = unknown>(
  path: string,
  init?: RequestInit & { method?: string },
): Promise<T> {
  const res = await fetch(`https://api.github.com${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${GH_TOKEN}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "claude-security-investigator-webhook",
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });
  if (!res.ok) {
    throw new Error(
      `GitHub API ${res.status} ${path}: ${(await res.text()).slice(0, 500)}`,
    );
  }
  // 204 No Content has no body
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

function formatPRComment(args: {
  report: string;
  headSha: string;
  scopeCount: number;
}): string {
  const header =
    `## :mag: Security Investigator Report\n\n` +
    `Audit of commit \`${args.headSha.slice(0, 7)}\` — scoped to ` +
    `${args.scopeCount} changed file${args.scopeCount === 1 ? "" : "s"}.\n\n`;

  const footer =
    `\n\n---\n` +
    `<sub>Generated by the Claude Security Investigator. Re-runs on every push to this PR.</sub>`;

  let body = args.report.trim();
  // Strip the report's redundant H1 — the comment header replaces it.
  body = body.replace(/^# Security Investigation Report\s*\n+/i, "");

  const max = COMMENT_BODY_LIMIT - header.length - footer.length - 200;
  if (body.length > max) {
    body =
      body.slice(0, max) +
      `\n\n_…report truncated (${body.length - max} chars omitted). Full ` +
      `report available in the server logs._`;
  }

  return header + body + footer;
}

function runCmd(
  cmd: string,
  args: string[],
  opts?: {
    cwd?: string;
    env?: NodeJS.ProcessEnv;
    timeoutMs?: number;
  },
): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      cwd: opts?.cwd,
      env: opts?.env ?? process.env,
      stdio: "inherit",
    });
    const timer = opts?.timeoutMs
      ? setTimeout(() => {
          child.kill("SIGTERM");
          // Belt-and-suspenders: SIGKILL after grace period.
          setTimeout(() => child.kill("SIGKILL"), 5000).unref();
          reject(
            new Error(
              `${cmd} ${args.slice(0, 2).join(" ")} timed out after ${opts.timeoutMs}ms`,
            ),
          );
        }, opts.timeoutMs)
      : null;

    child.on("error", (err) => {
      if (timer) clearTimeout(timer);
      reject(err);
    });
    child.on("exit", (code, signal) => {
      if (timer) clearTimeout(timer);
      if (code === 0) resolve();
      else
        reject(
          new Error(
            `${cmd} exited code=${code} signal=${signal ?? "none"}`,
          ),
        );
    });
  });
}

function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) {
    process.stderr.write(`fatal: ${name} is required in env\n`);
    process.exit(1);
  }
  return v;
}

function log(delivery: string, msg: string): void {
  process.stdout.write(
    `[${new Date().toISOString()}] [${delivery.slice(0, 8)}] ${msg}\n`,
  );
}

// ----------------------------------------------------------------------------
// Types — minimal shape we read from the webhook payload
// ----------------------------------------------------------------------------

interface PullRequestPayload {
  action: string;
  pull_request: {
    number: number;
    head: { sha: string };
  };
  repository: {
    name: string;
    clone_url: string;
    owner: { login: string };
  };
}

// ----------------------------------------------------------------------------
// Boot
// ----------------------------------------------------------------------------

serve({ fetch: app.fetch, port: PORT }, (info) => {
  process.stdout.write(
    `webhook server listening on http://localhost:${info.port}\n` +
      `  health:  GET  /health\n` +
      `  webhook: POST /webhook\n`,
  );
});
