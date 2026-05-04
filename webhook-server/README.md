# Security Investigator Webhook Server

A small [Hono](https://hono.dev/) server that wraps the upgraded security
investigator and exposes it as a GitHub PR-review service. Point GitHub's
webhook at it; on every PR open or push, it audits the changed files and posts
the report as a PR comment.

```
GitHub PR ──webhook──▶  POST /webhook  ──▶  verify HMAC
                                       ──▶  list changed files (GitHub API)
                                       ──▶  clone + checkout PR head
                                       ──▶  run upgraded/agent.ts (scoped)
                                       ──▶  POST /repos/.../issues/N/comments
```

The server responds `202 Accepted` immediately and processes the audit in the
background — GitHub's webhook timeout is ~10 s; the agent takes 5–10 min.

## Required env vars

Create `.env` at the repo root (one level up from this directory) with:

| Var | Where to get it | Used for |
|---|---|---|
| `ANTHROPIC_API_KEY` | [console.anthropic.com](https://console.anthropic.com/) → API Keys | The agent's LLM calls |
| `GITHUB_TOKEN` | [github.com/settings/tokens](https://github.com/settings/tokens) — fine-grained PAT with **Pull requests: read & write** and **Contents: read** on the target repo(s) | Cloning, listing PR files, posting comments |
| `GITHUB_WEBHOOK_SECRET` | Anything secret. Generate one with `openssl rand -hex 32` | HMAC verification on incoming webhooks |
| `PORT` | optional, default `3000` | Listen port |

## Run it locally

```bash
# from the repo root
npm install
npx tsx webhook-server/server.ts
```

You should see:

```
webhook server listening on http://localhost:3000
  health:  GET  /health
  webhook: POST /webhook
```

Sanity-check with `curl localhost:3000/health` → `ok`.

## Expose the local server to GitHub

GitHub needs a public URL to deliver webhooks. Two options for development:

### Option A — smee.io (zero-install, recommended)

[smee.io](https://smee.io/) is GitHub's own webhook proxy. It gives you a
public URL that forwards to localhost.

1. Visit <https://smee.io/new>. Copy the channel URL (e.g. `https://smee.io/abc123XYZ`).
2. Forward it to your local server:
   ```bash
   npx smee-client --url https://smee.io/abc123XYZ --target http://localhost:3000/webhook
   ```
3. In your GitHub repo's **Settings → Webhooks → Add webhook**:
   - **Payload URL**: the smee.io channel URL
   - **Content type**: `application/json`
   - **Secret**: same value as `GITHUB_WEBHOOK_SECRET` in your `.env`
   - **Events**: only `Pull requests`
4. Open or push to a PR. Watch the smee.io page (live event stream) and your
   server logs.

### Option B — ngrok

```bash
ngrok http 3000
# copy the https://*.ngrok-free.app URL ngrok prints
```

Use that URL + `/webhook` as the GitHub Payload URL. Same content-type and
secret as above.

### Configuring the GitHub webhook (either option)

Repository scope (one repo) or organization scope (all repos). The webhook
event is **Pull requests**; the only actions the server acts on are `opened`
and `synchronize` (everything else returns 202 with "ignored").

## Test locally without GitHub

You can POST a synthetic payload to your local server. Because of HMAC
verification you have to sign the body with `GITHUB_WEBHOOK_SECRET`.

Save a sample payload:

```bash
cat > /tmp/sample-pr.json <<'JSON'
{
  "action": "opened",
  "pull_request": {
    "number": 1,
    "head": { "sha": "abc1234567890abcdef1234567890abcdef12345" }
  },
  "repository": {
    "name": "my-repo",
    "clone_url": "https://github.com/me/my-repo.git",
    "owner": { "login": "me" }
  }
}
JSON
```

Sign it and POST:

```bash
SECRET="<your GITHUB_WEBHOOK_SECRET>"
BODY=$(cat /tmp/sample-pr.json)
SIG="sha256=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SECRET" -hex | awk '{print $2}')"

curl -i -X POST http://localhost:3000/webhook \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: pull_request" \
  -H "X-GitHub-Delivery: test-$(date +%s)" \
  -H "X-Hub-Signature-256: $SIG" \
  --data-binary "$BODY"
```

Expected response: `HTTP/1.1 202 Accepted` with body `accepted: me/my-repo#1`.
The server will then attempt to clone `github.com/me/my-repo` and run the
agent — point this at a real repo + PR you control to see the full pipeline.

A bad signature returns `401 invalid signature`; the `ping` event GitHub
sends when you first register a webhook returns `200 {"ok":true,"message":"pong"}`.

## Running against your own repo

The fastest end-to-end test:

1. Set up the server with a real `GITHUB_TOKEN` that has access to a small
   repo of yours.
2. Register the webhook with smee.io as above.
3. On that repo, open a PR with a deliberately questionable change (e.g. add
   `app.run(debug=True)` somewhere). Within a few minutes you should see a
   PR comment with the audit.

Each run costs roughly the same as a CLI run of the agent — ~$0.05–$0.70
depending on how much the orchestrator reads, scoped against just the changed
files.

## Operational notes

- **Concurrency.** Each webhook spawns its own subprocess in a fresh `mkdtemp`
  workdir, so two PRs landing simultaneously won't clobber each other's
  reports. There's no queue — if you get a flood of webhooks, you'll get a
  flood of subprocesses. Add a queue (BullMQ, plain in-memory semaphore) if
  this matters at your traffic level.
- **Timeout.** Hard cap is 15 minutes per audit (`AGENT_TIMEOUT_MS` in
  `server.ts`). If hit, the subprocess is SIGTERM'd then SIGKILL'd, and a
  failure comment is posted.
- **Comment size.** GitHub limits comments to 65,536 chars. The server caps
  output at 60,000 and truncates with a `…report truncated` note if needed.
- **Failure mode.** If anything throws (clone failure, agent crash, API
  error), the server posts a `:warning: Security Investigator failed` comment
  on the PR with the error message. Push another commit to retry.
- **Fork PRs.** Handled. The server fetches the `pull/<N>/head` ref from the
  base repo (GitHub mirrors fork PR branches there), so we don't need to
  authenticate against the fork's clone URL.
- **`INVESTIGATION_SCOPE`.** New env var added to `upgraded/agent.ts`. When
  set (newline-separated relative paths), the orchestrator prepends a SCOPE
  OVERRIDE block to its user prompt and audits only the listed files plus
  their direct callers/dependencies. Unset → original whole-repo behavior.
