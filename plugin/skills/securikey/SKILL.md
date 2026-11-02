---
name: securikey
description: Handles API keys, tokens, passwords and .env files without ever exposing their values. Use when a command needs a credential, when a .env file is involved, when the user wants to store or rotate a secret, or when output shows [securikey:NAME] or [redacted:KIND].
---

# SecuriKey

Secrets live in the OS keychain. You work with their **names**; values reach only the process that needs them. Hooks block any tool call or prompt that contains a secret and redact secrets from tool output before you see it, for calls that succeed and for commands started with `skey run`. Output of a *failing* command that did not go through `skey run` is not redacted.

## Rules
- Never ask the user to paste a secret into the chat. Ask them to run `skey add <name>` **in their own terminal** (it prompts with hidden input). Names: lowercase letters, digits, `_`.
- Never put a secret value in a command, file, or message. Never try to recover a redacted value (`[securikey:NAME]`, `[redacted:KIND]`): the redaction is the point.
- Don't read `.env` files (a hook blocks it). `.env.example` is fine.

## Commands
| Need | Command |
|---|---|
| See which secrets exist | `skey list` |
| Run a command with a secret | `skey run --env GITHUB_TOKEN=github -- gh api user` |
| Run with a project's .env | `skey run --dotenv .env -- npm run dev` |
| Make a .env safe to commit | `skey import .env` (values move to the keychain; the file keeps `securikey:<name>`), `--dry-run` first |
| Remove a secret | `skey rm <name>` |
| Replace a secret's value | the user runs `skey rotate <name>` in their own terminal (the old value stays redacted for 7 days) |
| Create the keychain's names in Paperclip | the user runs `skey sync paperclip` in their own terminal (a hook refuses `skey sync` and `skey rotate` from you: they send values to a server) |
| Use a secret Paperclip granted this run | `skey run --env-from-paperclip VAR=key -- <command>` |
| Check the setup before an unattended run | `skey doctor --headless` |

`skey run` passes the command's exit status through and redacts any secret in its stdout and stderr itself, **even when the command fails**. Claude Code skips the redaction hook for any other command that exits non-zero, so a secret such a command prints reaches you unredacted: run commands that handle a secret through `skey run`.

If a needed name is missing, tell the user the exact `skey add <name>` command to run, then continue once they confirm.

If `skey` prints a hint to run `skey migrate`, the user's secrets are still under the pre-3.0.0 name: ask them to run `skey migrate` in their own terminal (it prints names and counts only). `token_vault:<name>` references in a dotenv file still work but are deprecated; `securikey:<name>` is current.
