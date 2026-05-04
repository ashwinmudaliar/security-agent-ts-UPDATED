/**
 * Single-window dev runner — boots the webhook server and smee-client in
 * parallel with prefixed output. Reads SMEE_URL + PORT from .env.
 *
 *     npm run dev
 *
 * Output is interleaved with `[server]` / `[smee]` prefixes so you can tell
 * which child emitted each line. Ctrl+C kills both children cleanly.
 */
import "dotenv/config";
import { spawn, type ChildProcess } from "node:child_process";
import process from "node:process";

const smeeUrl = process.env.SMEE_URL;
if (!smeeUrl) {
  process.stderr.write(
    "fatal: SMEE_URL is not set in .env\n" +
      "       Visit https://smee.io/new to create a channel, then add\n" +
      "       SMEE_URL=https://smee.io/<your-channel> to your .env\n",
  );
  process.exit(1);
}

const port = process.env.PORT ?? "3000";

const PALETTE = {
  server: "\x1b[34m", // blue
  smee: "\x1b[32m", // green
} as const;
const RESET = "\x1b[0m";

function spawnChild(
  name: keyof typeof PALETTE,
  cmd: string,
  args: string[],
): ChildProcess {
  const child = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"] });
  const prefix = `${PALETTE[name]}[${name.padEnd(6)}]${RESET}`;

  const onChunk =
    (stream: NodeJS.WriteStream) =>
    (chunk: Buffer): void => {
      const text = chunk.toString();
      // Split on newline but keep last partial line intact across chunks.
      // For simplicity here we just split — minor cost: long lines may wrap awkwardly.
      const lines = text.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i] ?? "";
        const isLast = i === lines.length - 1;
        if (line.length === 0 && isLast) continue;
        stream.write(`${prefix} ${line}\n`);
      }
    };

  child.stdout!.on("data", onChunk(process.stdout));
  child.stderr!.on("data", onChunk(process.stderr));
  return child;
}

const server = spawnChild("server", "npx", ["tsx", "webhook-server/server.ts"]);
const smee = spawnChild("smee", "npx", [
  "-y",
  "smee-client",
  `--url=${smeeUrl}`,
  `--target=http://localhost:${port}/webhook`,
]);

let exiting = false;
function cleanup(signal: NodeJS.Signals = "SIGTERM"): void {
  if (exiting) return;
  exiting = true;
  server.kill(signal);
  smee.kill(signal);
  setTimeout(() => process.exit(0), 500).unref();
}

process.on("SIGINT", () => cleanup("SIGINT"));
process.on("SIGTERM", () => cleanup("SIGTERM"));
server.on("exit", () => cleanup());
smee.on("exit", () => cleanup());
