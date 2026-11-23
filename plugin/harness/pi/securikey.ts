// securikey-managed: written by `skey setup pi`, removed by `skey setup pi --remove`.
// Runs the securikey hooks for Pi. It only moves JSON between Pi and `skey hook <kind> --host pi`, so the
// matching logic stays in skey. Fails closed: if skey cannot judge a call, the call is blocked, and an
// output that cannot be checked is replaced by a notice. SECURIKEY_HOST_BYPASS=1 in Pi's own environment
// turns the extension into a pass-through.
import { spawnSync } from "node:child_process";

const UV = "@@UV@@";
const SKEY = "@@SKEY@@";
const TIMEOUT_MS = 15000;
const WITHHELD = "securikey: this output was not checked for secrets, so it was withheld.";

type Verdict = { action: string; reason?: string; response?: any; message?: string };

function judge(kind: string, payload: unknown): Verdict {
  const r = spawnSync(UV, ["run", "--quiet", "--script", SKEY, "hook", kind, "--host", "pi"], {
    input: JSON.stringify(payload),
    encoding: "utf8",
    timeout: TIMEOUT_MS,
    maxBuffer: 256 * 1024 * 1024,
  });
  if (r.error || r.status !== 0) {
    throw new Error("skey hook " + kind + " failed: " + (r.error ? r.error.message : "exit " + r.status));
  }
  const verdict = JSON.parse(r.stdout);
  if (!verdict || typeof verdict.action !== "string") throw new Error("skey hook answered without an action");
  return verdict;
}

const bypassed = () => process.env.SECURIKEY_HOST_BYPASS === "1";
const textOf = (value: unknown): string => (typeof value === "string" ? value : "");

export default function (pi: any) {
  pi.on("tool_call", async (event: any, ctx: any) => {
    if (bypassed()) return;
    try {
      const v = judge("pre", { tool: event.toolName, input: event.input, cwd: ctx?.cwd ?? process.cwd() });
      if (v.action === "deny") return { block: true, reason: textOf(v.reason) || "securikey: blocked." };
      if (v.action !== "allow") throw new Error("unexpected action " + v.action);
    } catch (e: any) {
      return { block: true, reason: "securikey: the call was not judged (" + e.message + "), so it was blocked." };
    }
  });

  pi.on("tool_result", async (event: any, ctx: any) => {
    if (bypassed()) return;
    try {
      const response = { content: event.content, details: event.details, structuredContent: event.structuredContent };
      const v = judge("post", { tool: event.toolName, response, cwd: ctx?.cwd ?? process.cwd() });
      if (v.action === "allow") return;
      if (v.action !== "replace") throw new Error("unexpected action " + v.action);
      const r = v.response;
      if (typeof r === "string") return { content: [{ type: "text", text: r }], details: undefined };
      // Replacing `content` drops `structuredContent` in Pi, so a redacted copy is passed along with it.
      return { content: r.content, details: r.details, structuredContent: r.structuredContent };
    } catch {
      return { content: [{ type: "text", text: WITHHELD }], details: undefined };
    }
  });

  pi.on("input", async (event: any, ctx: any) => {
    if (bypassed()) return { action: "continue" };
    try {
      const v = judge("prompt", { text: event.text, cwd: ctx?.cwd ?? process.cwd() });
      if (v.action === "allow") return { action: "continue" };
      ctx?.ui?.notify?.(textOf(v.reason) || "securikey: the prompt was blocked.", "warning");
    } catch (e: any) {
      ctx?.ui?.notify?.("securikey: the prompt was not judged (" + e.message + "), so it was not sent.", "warning");
    }
    return { action: "handled" };
  });
}
