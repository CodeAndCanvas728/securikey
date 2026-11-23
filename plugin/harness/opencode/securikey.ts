// securikey-managed: written by `skey setup opencode`, removed by `skey setup opencode --remove`.
// Runs the securikey hooks for OpenCode (V2 plugins). It only moves JSON between OpenCode and
// `skey hook <kind> --host opencode`, so the matching logic stays in skey. Fails closed: a call or prompt
// that skey cannot judge is blocked (a throw in these hooks blocks), and an output that cannot be checked is
// replaced by a notice. SECURIKEY_HOST_BYPASS=1 in OpenCode's own environment turns the plugin into a
// pass-through.
import { spawnSync } from "node:child_process";

const UV = "@@UV@@";
const SKEY = "@@SKEY@@";
const TIMEOUT_MS = 15000;
const WITHHELD = "securikey: this output was not checked for secrets, so it was withheld.";

type Verdict = { action: string; reason?: string; response?: any; message?: string };

function judge(kind: string, payload: unknown): Verdict {
  const r = spawnSync(UV, ["run", "--quiet", "--script", SKEY, "hook", kind, "--host", "opencode"], {
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
const cwd = (ctx: any): string => ctx?.location?.directory ?? process.cwd();

function withheld(event: any) {
  if (event.status === "error") {
    try {
      event.error.message = WITHHELD;
    } catch {
      /* the message is read-only: nothing more can be done from an after hook */
    }
    return;
  }
  event.result = { metadata: event.result?.metadata, content: WITHHELD };
}

export default {
  id: "securikey",
  async setup(ctx: any) {
    await ctx.tool.hook("execute.before", (event: any) => {
      if (bypassed()) return;
      let v: Verdict;
      try {
        v = judge("pre", { tool: event.tool, input: event.input, cwd: cwd(ctx) });
      } catch (e: any) {
        throw new Error("securikey: the call was not judged (" + e.message + "), so it was blocked.");
      }
      if (v.action !== "allow") throw new Error(v.reason || "securikey: blocked.");
    });

    await ctx.tool.hook("execute.after", (event: any) => {
      if (bypassed()) return;
      try {
        const failed = event.status === "error";
        const response = failed
          ? { error: event.error?.message }
          : { output: event.result?.output, content: event.result?.content };
        const v = judge("post", { tool: event.tool, response, cwd: cwd(ctx) });
        if (v.action === "allow") return;
        if (v.action !== "replace") throw new Error("unexpected action " + v.action);
        const r = v.response;
        if (typeof r === "string") return withheld(event);
        if (failed) {
          event.error.message = r.error;
        } else {
          const result: any = { ...event.result, content: r.content };
          if (r.output === undefined) delete result.output;
          else result.output = r.output;
          event.result = result;
        }
      } catch {
        withheld(event);
      }
    });

    await ctx.session.hook("prompt", (event: any) => {
      if (bypassed()) return;
      let v: Verdict;
      try {
        v = judge("prompt", { text: event.prompt?.text, cwd: cwd(ctx) });
      } catch (e: any) {
        throw new Error("securikey: the prompt was not judged (" + e.message + "), so it was not sent.");
      }
      if (v.action !== "allow") throw new Error(v.reason || "securikey: the prompt was blocked.");
    });
  },
};
