<h1 align="center"><img src="docs/logo.svg" alt="SecuriKey" width="360"></h1>

[![CI](https://github.com/CodeAndCanvas728/securikey/actions/workflows/ci.yml/badge.svg)](https://github.com/CodeAndCanvas728/securikey/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
![Platforms: macOS and Linux](https://img.shields.io/badge/platforms-macOS%20%7C%20Linux-blue)

**Keeps API keys and tokens out of your coding agent's context.** Secrets live in the OS keychain, and the agent only ever works with their **names**. A prompt or tool call that contains a secret is blocked, and tool output is redacted before the model sees it. Built for Claude Code, and the same checks run in [Mistral Vibe](#other-harnesses-vibe-pi-opencode), [Pi](#other-harnesses-vibe-pi-opencode) and [OpenCode](#other-harnesses-vibe-pi-opencode).

One gap, stated up front: in Claude Code, if a command that did **not** get its secret through `skey run` fails (non-zero exit), the redaction hook is skipped and the model sees what it printed. [Details and what covers it](#known-gap-a-failing-command). Vibe, Pi and OpenCode do not have this gap.

![Terminal recording: the agent runs a command with a stored token; the output shows the name, not the value, and the exit status is kept](docs/demo.gif)

*Animated from a real capture: a throwaway keychain entry and a demo value, with the commands typed out and the output exactly as printed. The green line is an annotation, not output.* The same idea in text, with a real API call added:

```text
you    $ skey add github                                  # hidden prompt, stored in the OS keychain
agent  $ skey run --env GH_TOKEN=github -- gh api user    # only the child process gets the value
agent  $ skey run --env GH_TOKEN=github -- sh -c 'echo "token: $GH_TOKEN"; exit 1'
       token: [securikey:github]                          # redacted, and the exit status is still 1
```

## Quickstart

```bash
claude plugin marketplace add CodeAndCanvas728/securikey
claude plugin install securikey@codeandcanvas
skey add github        # in your own terminal; link it first (see Install)
```

Needs [`uv`](https://docs.astral.sh/uv/) and Claude Code 2.1.295 or later. macOS and Linux. For Vibe, Pi or OpenCode, see [Other harnesses](#other-harnesses-vibe-pi-opencode): they need `uv` and a linked `skey`, not Claude Code.

## What it guarantees

| Path a secret could take | What happens |
|---|---|
| You paste a token into a prompt | `UserPromptSubmit` blocks it before it is sent; nothing reaches the API |
| The agent puts a secret in a tool call (command, file edit, MCP call) | `PreToolUse` denies the call and names the secret, never its value |
| A tool call that **succeeds** prints a secret | `PostToolUse` replaces the output with a redacted copy before the model sees it |
| A command started with `skey run` prints a secret, **even if it fails** (when its output is piped, as an agent's is; at a terminal it is not filtered) | `skey run` redacts its child's stdout and stderr itself and keeps the exit status |
| The agent tries to read a dotenv file | Blocked; `skey import` moves the values into the keychain and leaves `securikey:<name>` references |
| A command needs the secret | `skey run` injects it into that one child process's environment |

The table uses Claude Code's hook names. In Vibe, Pi and OpenCode the same rows hold through that harness's own hooks (listed [below](#other-harnesses-vibe-pi-opencode)).

Detection is exact for stored secrets (including their base64 and URL-encoded forms, so no false positives) and pattern-based for common provider formats you haven't stored yet (GitHub, Anthropic, OpenAI, AWS, Slack, Stripe, Google, JWT, private keys: `skey patterns`).

### Known gap: a failing command

Claude Code runs the redaction hook only when a tool call succeeds. A command that exits non-zero hands its output to the model unredacted, and no hook can change that (checked on Claude Code 2.1.316). SecuriKey detects a secret in a failed call and warns you, and `skey run` covers the commands it starts. A failing command that read a secret some other way is not covered: rotate a secret that was printed. This is Claude Code's limit: the hooks of Vibe, Pi and OpenCode can rewrite an error, so failed calls are redacted there. See [docs/limits.md](docs/limits.md#a-failed-call-is-not-redacted-unless-skey-run-started-it).

## Limits at a glance

Full list, with the reasons: [docs/limits.md](docs/limits.md).

- It can't un-run a command: a script that sends a secret over the network still sends it. Redaction controls what the **model** sees.
- Claude Code's local transcript records tool output before a hook rewrites it. The guarantee is about the model and the API, not your disk.
- A command can transform a secret before printing it (reversed, hex, split), and that text is not redacted. [`tests/test_known_bypasses.py`](tests/test_known_bypasses.py) pins this.
- A secret in an unknown format that you never stored can't be recognised; store it and it is covered exactly. Values under 8 characters are never redacted.
- If the keychain is locked, the hooks fall back to pattern matching and tell you.
- Vibe, Pi and OpenCode are covered through `skey setup`, with limits of their own: the harness's own session log can keep the raw value, and an agent allowed to write in the harness's config folder could edit the hooks. [Details](docs/limits.md#other-harnesses-vibe-pi-opencode).
- The `skey` CLI works from any shell.

## Install

From a session:

```text
/plugin marketplace add CodeAndCanvas728/securikey
/plugin install securikey@codeandcanvas
```

Or from the shell:

```bash
claude plugin marketplace add CodeAndCanvas728/securikey
claude plugin install securikey@codeandcanvas
```

To try a checkout instead of installing it: `claude --plugin-dir /path/to/securikey/plugin`.

`bin/` is on Claude Code's `PATH` while the plugin is enabled, so the agent runs `skey` directly. For your own terminal, link it: `ln -s /path/to/securikey/plugin/bin/skey ~/.local/bin/skey`. All three hooks set `onFailure: "block"`, so an input or prompt hook that cannot start stops the call instead of letting it through. That means a missing `uv` stops every tool call: run `skey doctor` after installing, and disable the plugin with `claude plugin disable securikey` if you need to get unstuck.

On macOS the first keychain access asks to allow `python`; choose **Always Allow**. On Linux the keychain needs a Secret Service provider (GNOME Keyring or KWallet). claude.ai and Cowork do not install a plugin with a top-level `bin/` directory, so this plugin is for the Claude Code CLI and the desktop app.

Coming from token-vault? See [docs/migrating.md](docs/migrating.md).

## Other harnesses: Vibe, Pi, OpenCode

The same checks run in [Mistral Vibe](https://docs.mistral.ai/vibe/code/cli/plugins), [Pi](https://github.com/earendil-works/pi) and [OpenCode](https://opencode.ai). You need `uv` and `skey` on your `PATH` (not Claude Code). Link it as above; the install refuses a path inside the Claude plugin cache, because that path changes on every update. Then, from your own terminal:

```sh
skey setup vibe       # ~/.vibe/plugins/securikey, a Vibe plugin
skey setup pi         # ~/.pi/agent/extensions/securikey.ts
skey setup opencode   # ~/.config/opencode/plugins/securikey.ts
skey setup <name> --remove
```

`skey setup` runs only at a terminal, because removing the hooks switches the protection off. It honours `VIBE_HOME`, `PI_CODING_AGENT_DIR` and `OPENCODE_CONFIG_DIR`, and writes the absolute paths of `uv` and `skey` into the hooks, so a harness started from a launcher still finds them. Start a new session (or reload plugins) afterwards.

| | Vibe | Pi | OpenCode |
|---|---|---|---|
| A tool call holding a secret | denied | denied | denied |
| Tool output holding a secret | redacted | redacted | redacted |
| A failed call's error holding a secret | redacted | redacted | redacted |
| A prompt holding a secret | blocked | blocked | blocked |
| Checked on | 3.1.2 | 1.5.2 | 2.2.7 |

**How it works.** Each hook is a small shim that pipes the harness's payload to `skey hook <kind> --host <name>`. skey maps it to the event Claude Code would send, runs the same checks, and answers in the harness's own shape, so there is one copy of the matching code. A call it cannot read (no command, no path, two keys that disagree) is denied. Each hook costs one `uv` start, about 100 ms, the same as in Claude Code.

**Fails closed.** If `skey` is missing or crashes, the call or prompt is blocked and an output that cannot be checked is withheld. To get unstuck, run `skey setup <name> --remove`, or start the harness with `SECURIKEY_HOST_BYPASS=1`, which turns the hooks off for that run only. The setting is read from the harness's own environment, which a tool call cannot change.

**What it cannot cover**, in short (all in [docs/limits.md](docs/limits.md#other-harnesses-vibe-pi-opencode)):
- Anything the harness wrote down before a hook ran. Vibe's session journal keeps the original output, tool input and blocked prompt; the redaction protects what the model sees, not that file.
- Vibe runs hooks for the tools a `run_typescript` script calls, not for the `run_typescript` call itself.
- An agent that is allowed to write in the harness's config folder could edit the hooks.
- Input typed to a running shell in pieces (Vibe's `process_write`) is judged one piece at a time.

## Use

```bash
skey add github                                  # hidden prompt; never pass a value as an argument
skey list
skey gen jwt_secret                                # a new random secret; made and stored without being shown
skey add --config local_api                     # configuration, not a secret (a local server address): not redacted or blocked
skey run --env GH_TOKEN=github -- gh api user
skey import .env --dry-run && skey import .env     # the secrets it recognised become names
skey run --dotenv .env -- npm run dev
skey rm github
```

### Requests from an agent

`rotate`, `sync` and `config` only run for you at a terminal. An agent that needs one does not have to stop and wait:

```bash
skey request rotate github --generate --reason "key pasted into a log"   # the agent files it and carries on
skey pending                                                          # what is waiting, what became of the rest
skey approve                                                          # you, whenever: shows each, y / n / skip
```

A request names an operation and holds no value. `skey approve` shows what each one will do (a sync shows the server it sends to; marking something as configuration says it will stop being redacted), then runs it with the same checks as typing it yourself. `--generate` makes the new value without anyone seeing it. This saves waiting; it does not add protection beyond the terminal check (see [docs/limits.md](docs/limits.md)).

### How the references work

`skey import` moves a value into the keychain and leaves the **name** behind:

```bash
# .env                          # after skey import .env
API_KEY=sk-ant-api03-...        API_KEY=securikey:api_key
```

`securikey:<name>` is a marker, not a value. Nothing expands it on its own, so the file is safe to commit. To hand the value to a command, start the command through `skey run`:

```bash
skey run --dotenv .env -- npm run dev           # the child gets API_KEY=<the real value>
skey run --env API_KEY=api_key -- npm run dev   # or name the secret directly
```

`skey run` resolves the references into the child's environment. At a terminal it then replaces itself with the command. When its stdout is piped (the way an agent runs it) it runs the command, passes the exit status through and redacts stdout and stderr itself; `SECURIKEY_RUN_FILTER=0` turns that off. An application that reads the dotenv file itself, without `skey run`, sees the literal `securikey:api_key`.

`skey run --dotenv <file>` is only allowed when **every** value in the file is already a name: a file that still holds a plaintext value would put it into the child's environment, so the hook blocks it and asks for `skey import` first. `skey import` moves the values it recognises and tells you which ones it left behind, because those are still in the file in plaintext. It treats `KEY`, `TOKEN`, `SECRET`, `PASSWORD`, `PASS`, `PRIVATE`, `CREDENTIAL`, `AUTH` and `DSN` keys, and any provider-shaped token, as secrets; `skey import --all` moves everything.

`scan_all_git_repos.sh --dir ~/Documents [--apply]` does the same across many repositories (dry run by default, backs each file up until the import succeeds). It is a maintenance script and is not shipped with the plugin.

## Unattended agents

Running under Paperclip or another host that injects secrets into the environment: [docs/paperclip.md](docs/paperclip.md) covers `SECURIKEY_WATCH_ENV`, per-org keychain services, headless mode, seeding and rotating secrets, the audit log and `skey doctor --headless`.

## Design choices

- **The OS keychain does the cryptography.** Secrets are one keychain item (a JSON map); there is no vault file and no custom crypto to get wrong.
- **No MCP server.** Any tool that returns a secret puts it into the model's context, which is the thing this plugin exists to prevent.
- **Fail closed where it matters.** All three Claude Code hooks set `onFailure: block`, so a broken install stops tool calls and prompts instead of silently waving them through, and any other failure inside a hook denies, blocks or replaces the output rather than passing it unjudged. The Vibe, Pi and OpenCode hooks do the same.
- **One implementation for every harness.** The other harnesses get thin shims that call `skey hook --host`; payload mapping is unit-tested in the Python suite, and the shims were checked against the real harnesses with a stub model server.
- **The limits are tested, not just written down.** Known bypasses are pinned as tests, and hook behaviour is checked against a real Claude Code session, not only unit tests: that is how the failing-command gap was found.
- **Small:** about 3,400 lines of stdlib Python plus `keyring` and about 170 lines of TypeScript shims, with hermetic tests.

## Develop

```bash
PYTHONPATH=plugin uv run --python 3.12 python -m unittest discover -s tests -t .
claude plugin validate plugin --profile directory
claude plugin validate .
```

```text
plugin/          what an install ships: .claude-plugin/, bin/skey, hooks/, skills/, securikey/ (the code), harness/ (Pi and OpenCode shims)
tests/           hermetic unit tests, including manifest checks
docs/            limits, Paperclip, migration
bench/           hook latency measurement, Claude Code and `--host vibe` (not shipped)
```

The plugin lives in `plugin/` on purpose: a marketplace entry's `source` is a directory and everything under it is installed, so the tests, docs and scripts stay out of what users get. CI runs the tests, `claude plugin validate` (pinned Claude Code) and a check that no secret pattern is committed, on Ubuntu and macOS.

MIT licensed. Changes: [CHANGELOG.md](CHANGELOG.md).
