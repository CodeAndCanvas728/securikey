# Changelog

## [3.2.0] - 2026-11-09

### Added
- An entry can be marked as non-secret configuration, so its value is neither redacted from output nor blocked in a command. A local server address that was stored as an entry used to deny every command containing it, even through `skey run`. `skey add --config <name>` stores a value that way; `skey config <name> on|off` marks or unmarks an entry that exists; `skey list` shows `(config)`. Both refuse to run outside your own terminal (stdin is a TTY, `SECURIKEY_HEADLESS` unset), as `sync` and `rotate` do, because a marked value is readable by the agent. As a second layer, the pre-hook denies a Bash call that names the literal commands `skey config` or `skey add --config` (also nested, quoted or behind a wrapper such as `script`); other uses of the word `config` pass.
- The default is unchanged: every entry is a secret. The marks are a separate keychain item (`config`), so the secrets map keeps its format and an upgrade marks nothing. A mark records a hash of the value it was made for: storing a new value under the name (anything that overwrites it, including `skey add` with a piped value) makes the entry a secret again, and `skey rm` clears the mark. Values rotated out by `skey rotate`, fetched from Paperclip or listed in `SECURIKEY_WATCH_ENV` are never dropped by a mark. A mark item that cannot be read leaves every entry secret.

## [3.1.4] - 2026-11-08

Fewer false positives in the pre-hook: it denies reads, not mentions.

### Changed
- The human-only gate (`skey sync`, `skey rotate`) reads a word with only `*` or `?` globs as a program only if its literal characters can spell `skey` in order. A bold label such as `**Open:**` before `sync` or `rotate` is prose in a heredoc, a quoted argument or after a wrapper such as `make`. Words with `$`, a backtick, `~`, `[` or `/` are still unknown programs, and so are `s*y`, `sk?y` and `*key`.
- The env-file guard no longer denies a command that only names a file in text: `echo` and `printf` (when nothing pipes, redirects, reads or evals their output), `git commit` (only with a known set of plain options and a message; `-F -` with a heredoc), `grep` and `rg` with the name as the pattern, and a heredoc whose receiver is `cat`, `tee`, `tea`, `gh` or `git commit`, with no quote, `#`, second heredoc, pipe or expansion before the tag or after it, and none in an unquoted body. A segment with a `&`, parenthesis, brace or backtick is not judged as a mention. A file argument, `-f`, `-g`, `--pre`, a shell heredoc, `cat`, redirection, `source` and `xargs` are still denied.

## [3.1.3] - 2026-11-03

### Changed
- `skey rotate` no longer prints "Paperclip is not configured: only the keychain changed" when Paperclip is not set up. Most installs do not use it, so the message was noise on every rotate. It stays silent only when no Paperclip setting exists at all: with some settings but not all (a URL and no token), rotate still says the keychain changed but Paperclip did not, and exits 1. With Paperclip configured, the messages for a secret that is not there yet and for a failed update are unchanged.

## [3.1.2] - 2026-11-03

### Changed
- The pre-hook gate for the human-only commands no longer denies ordinary text. A word with a glob or expansion character (`$ * ? [ ~` or a backtick) directly before `sync` or `rotate` is read as an unknown program only in command position (the first word of a line or segment, or any word after a wrapper such as `env`, `sudo`, `xargs`, `uv`, `docker`, `bash -c` or a bare `--`), so a bullet such as `- **Open:** sync the plan` or `- [ ] sync it` passes. A line that starts with such a word is still judged as a command. The `skey <word>` rules are unchanged.
- The denial names what matched (for example `` `$S` before `sync` ``), so a false positive can be fixed in one step.

## [3.1.1] - 2026-11-02

Security review and publication prep. The headline is now honest about one gap (a failing command), and `skey run` closes it for the commands it starts.

### Added
- `skey run` filters its command's output. When stdout is not a terminal (the Bash tool always pipes it) it runs the command itself instead of replacing itself with it, passes the exit status through (128+n for a signal, 127 not found, 126 not executable) and redacts stdout and stderr: the same values the hooks know (stored, rotated-out, fetched from Paperclip, listed in `SECURIKEY_WATCH_ENV`, and the `.env` values under the current directory) in all their forms, token patterns, and private keys even when split across reads. Output is held back by up to 4096 characters (more if a stored value is longer, and for a stored value that spans lines, also across a pause) or 0.25 s so a split value is still found; token patterns are applied only to whole lines, so a long token (a large JWT) is never written out in pieces. A single line that is still unfinished after 1 MB is withheld and replaced by `[securikey: a line over 1 MB was withheld]`, and the rest of it is dropped; releasing part of it could cut a token and print its start. Binary output passes through byte for byte. An unreadable watch list warns, and fails closed under `SECURIKEY_HEADLESS=1`. Checked in Claude Code: a failing `skey run` gives the model `[securikey:name]` and the real exit status. `SECURIKEY_RUN_FILTER=0` keeps the old `exec`. At a terminal nothing changes.
- A `PostToolUseFailure` hook (`skey hook failure`) that warns when a failed call's error text holds a secret: a message to the user and a note to the model not to repeat it. It does not ask Claude Code to stop the turn, so a false positive cannot abort the agent.
- `skey --help` describes every subcommand and shows the usage text; Ctrl-C (exit 130), Ctrl-D and a non-UTF-8 file end with a message instead of a traceback.
- `docs/` (limits, Paperclip, migration); the README is now a short front page. CI also runs on macOS and Python 3.13 (GitHub).

### Changed
- The marketplace is named `codeandcanvas` (it had a different name before): `claude plugin install securikey@codeandcanvas`. Reinstall once if you installed under the old name. The plugin's home is `https://github.com/CodeAndCanvas728/securikey`.
- Whitespace at either end of a value is ignored when the dotenv scan judges it (`KEY=" abc123 "`); whitespace inside still means "not a secret".
- `skey sync` writes its audit line for the names already sent when a later one fails; `skey rotate` reports a bad Paperclip address as "the keychain has the new value, but Paperclip was not updated"; the audit log no longer fails on Windows (`fchmod`); the Paperclip client reports `http.client` errors, an invalid URL and a non-UTF-8 reply as a normal error.

### Security
- **A failed call is not redacted, and now says so.** Claude Code runs `PostToolUse` only when a tool succeeds; a Bash command that exits non-zero fires `PostToolUseFailure`, which cannot rewrite the error text. Checked on Claude Code 2.1.316 in `claude -p` with this plugin loaded: a command that printed a token and exited 3 gave the model the raw token, and a `continue: false` from the new `PostToolUseFailure` hook was logged ("requested preventContinuation") but the next turn still ran, so the hook no longer sends it. The hook now detects a secret in a failed call's error and warns (`skey hook failure`). Rewriting the command so it always succeeds was tried three ways (an EXIT `trap`, an appended `echo "[exit $?]"; true`, a `{ ...; } || echo` group) and Claude Code's permission check refuses or asks about each one, so it is not done. The README's guarantees table and the skill now say what is covered; `skey run` covers the commands it starts (see Added).
- The `jwt` pattern was quadratic on a run of `-eyJ` (160 KB took 8 s, past the hook timeout, so a page or file carrying it could stall the hooks). It no longer starts a match inside a run of token characters (400 KB: 4 ms). The brace expansion in the sync/rotate gate is skipped past 16 KB; such a command is denied if it names `skey`, `sync` or `rotate`.
- Private keys are recognised under every armor header that names one: RSA, EC, OPENSSH, ENCRYPTED, SSH2 ENCRYPTED and PGP `... PRIVATE KEY BLOCK` (the pattern, the filter and the CI scan). Only the first three were before.
- The Paperclip seeding command logs each name to the audit log before its request is made, so a request that failed after reaching the server is still recorded.
- Known and pinned: an unstored JWT glued directly to a token character is not recognised by pattern (`tests/test_known_bypasses.py`); that is the price of the linear-time pattern.
- More env-file names are guarded and scanned: `.envrc`, `.env-prod`, `.env_local`, and `prod.env`, `production.env`, `dev.env`, `staging.env`, `test.env`, `local.env`, `live.env`, `secrets.env`, `credentials.env`, each also with a suffix (`prod.env.local`, `live.env.backup`) (the name check; the content scan reads any file named `*.env`). `process.env` and `.environment` are not matched.

## [3.1.0] - 2026-10-31

Paperclip and unattended agents. Paperclip resolves secrets on its server and injects them into the agent's environment; until now only values in the keychain and in project `.env` files were redacted, so `env` or `echo $X` could show a Paperclip-held value to the model.
### Added
- `SECURIKEY_WATCH_ENV` (comma-separated variable names): the hooks redact those variables' values (8 characters or more, with base64 and URL forms) as `[securikey:env:NAME]` and deny a tool call that carries one. A listed variable that is unset, too short or not a valid name is reported in the hook's message (never with a value).
- `SECURIKEY_HEADLESS=1`: with nobody to read a warning or answer the keychain prompt, `skey warm` reads the keychain with a time limit (20 s, `SECURIKEY_HEADLESS_TIMEOUT`) and exits 1 with the reason on stderr; the tool and prompt hooks deny, block or replace the output when the keychain cannot be read, instead of falling back to pattern checks. The migration hint is not shown (it read the keychain with no time limit).
- `skey doctor [--headless]`: `uv` on PATH, `keyring` and the keychain readable in time, Claude Code >= 2.1.295, securikey enabled at user scope (`--setting-sources user`), every watched variable set. Names and counts only; exit 1 on a failure. Version and user-scope are warnings unless `--headless`.
- `skey sync paperclip [--only a,b] [--update] [--dry-run]`: creates each keychain name as a Paperclip company secret (`POST /api/companies/:id/secrets`). URL, company id and token come from `SECURIKEY_PAPERCLIP_URL`, `SECURIKEY_PAPERCLIP_COMPANY` and the keychain name `paperclip_token` (or `SECURIKEY_PAPERCLIP_TOKEN`), never from arguments; plain http is refused off this machine. Output is names, actions and ids; server error text is redacted against the keychain and cut to 200 characters. Existing names are kept unless `--update` (`POST /api/secrets/:id/rotate`).
- `skey rotate <name> [--keep-days N]`: new value from a hidden prompt or stdin; the old value stays redacted for N days (default 7) through a new expiring `watch` keychain entry; the Paperclip secret is updated when it exists there. A Paperclip failure after the keychain changed exits 1 and says so.
- `skey run --env-from-paperclip VAR=key`: fetches a granted secret with the run's own token (`PAPERCLIP_API_URL`, `PAPERCLIP_API_KEY`) and registers it for redaction for 24 hours before the command starts.
- An audit log: `skey run`, `sync` and `rotate` append name, variable names, time, service, the command's basename and its parent process to `~/.cache/securikey/audit-<service>.log` (mode `0600`). Never a value or an argument.
- `bench/hook_cost.py`: p50/p95/max of both tool hooks, in-process and end to end through `uv run`, with a 150 ms p95 budget (exit 1 when exceeded). Measured here: about 1 ms for the check, p95 107 ms (pre) and 119 ms (post) end to end.

### Security
- `skey sync` and `skey rotate` send keychain values to a server whose address (`SECURIKEY_PAPERCLIP_URL`) a command line can set, so an agent could point `sync` at a host of its choosing. Two layers: the commands refuse to run unless stdin is a terminal and `SECURIKEY_HEADLESS` is unset, and the pre-hook denies any Bash call that names them, also nested (`skey run -- skey sync`, `bash -c`, `$(…)`), by path, quoted (`s''key`), glued to a separator (`true &skey rotate k`, `{ skey sync; }`), behind an expansion (`$S sync`, `$(echo skey) sync`) or inside another program's argument (`git -c alias.x='!skey sync'`). No command is exempt, so a commit message that mentions them is denied. Nested brace lists, any `${…}` expansion, a dynamic subcommand (`skey $X`) and upper case (`SKEY sync`, which runs on the default macOS filesystem) are read as the shell does. Not covered: shell text the hook cannot read (an encoded command) and a process that opens its own pseudo-terminal; a terminal is not proof of a person. This matches the existing limit that `skey run --env X=name -- <command>` hands the value to a command the agent chooses: the guarantee is about the model's context, not a hostile agent with a shell. They are no longer on the `.env`-guard allowlist.
- The Paperclip client refuses redirects: `urllib` copies the `Authorization` header to the redirect target, which would hand the token (and a value in the body) to another host.
- argparse option abbreviations are off for every command. The hook reads `skey run` options by exact name, so `skey run --env-from X=k -- …` was parsed one way by the CLI and another by the hook.
- Known and documented: `--env-from-paperclip` sends the run's own token to `PAPERCLIP_API_URL`, which a command can set inline.

- With `SECURIKEY_HEADLESS=1`, an unreadable pre-3.0.0 keychain item is a failed check too (deny, block, replace the output). It was only a warning nobody reads, so output holding an old value reached the model.
- `SECURIKEY_WATCH_ENV` problems name an entry by position (`entry 2 of SECURIKEY_WATCH_ENV …`), never by its text: a secret pasted into the list by mistake was printed in every hook message and in `skey doctor`.
- `skey migrate` refuses when `SECURIKEY_SERVICE` is set. It copies the whole shared pre-3.0.0 item, so on a per-org service it would pull every org's old values into that org (and `--purge-old` would delete the shared item). Run it once on the default service.

### Changed
- Behaviour change: with `SECURIKEY_SERVICE` set, the hooks no longer also read the shared pre-3.0.0 `token-vault` keychain item, so one org's old values are neither found nor redacted in another org's session. Unset, nothing changes. `skey migrate` runs on the default service only (see Security), and `TOKEN_VAULT_SERVICE` set on purpose keeps the old item in the hooks.
- The keychain service is read from `SECURIKEY_SERVICE` when a store is created, not once at import.
- `warning` is a declared attribute of every store; the hooks no longer reach for it with `getattr`.
- `skey doctor` and `migrate` are treated as commands that print no value, like `add` and `list` (`sync` and `rotate` are not: see Security); `skey run --env-from-paperclip` is parsed as a `skey run` option, so the `.env` guard still judges the command after `--`.

### Fixed
- The Paperclip client closes the error response it reads, so no `ResourceWarning` leaks into a command's output.

## [3.0.0] - 2026-10-23

Renamed from token-vault to SecuriKey, with a one-time keychain migration, and prepared for publishing. Breaking: the binary, the Python package and the reference prefix change.

### Changed
- The plugin is `securikey` (display name SecuriKey), the binary is `skey` (was `tv`, a name that collides with common tools), the package is `plugin/securikey` and the redaction marker is `[securikey:NAME]`. Why: a clearer name and a binary that is unlikely to shadow another command.
- References written by `skey import` are `securikey:<name>`. `token_vault:<name>` still resolves, with a one-line notice on stderr (never the value) asking you to change the prefix; the hook and `skey import` treat both as references, and only a prefix followed by a valid name counts (`securikey:` plus anything else is a plaintext value). The prefix is not rewritten for you.
- Secrets are read from the keychain service `securikey` (was `token-vault`); `SECURIKEY_SERVICE` replaces `TOKEN_VAULT_SERVICE`. The lock file directory is `securikey`.
- `scan_all_git_repos.sh`: `--tv PATH` is `--skey PATH`, and backups are `<name>.skey-backup-<timestamp>` (existing `.tv-backup-*` files are still skipped by the scan).

### Added
- `skey migrate [--dry-run] [--purge-old]` copies every secret from the old keychain item to the new one, reads each back and compares it in memory, and prints names and counts only. It is idempotent (identical items are skipped), refuses to overwrite a name whose value differs (exit 1, with the fix), keeps the old item unless `--purge-old` is given, and deletes it only after every name verified and nothing differs. It holds the existing file lock of both stores. While the new store is empty and the old one has items, `add`, `list`, `rm`, `run`, `import` and `warm` print a one-line hint on stderr to run it; the hooks never do.
- `tests/test_known_bypasses.py` pins the documented transform limit (reversed, hex, split or spaced output is not redacted; plain, base64 and URL-encoded forms are), and `tests/test_manifests.py` checks the manifests, the icon and the hook wiring with the standard library only.
- An icon (`plugin/.claude-plugin/icon.png`, vector source in `plugin/assets/icon.svg`), `homepage` and an author URL in `plugin.json`, and a description for the marketplace. The plugin directory accepts only a square PNG or JPEG icon of 512 to 2048 px, not SVG.

### Gotchas
- Run `skey migrate` once after updating. Until you do, the new store is empty and `skey run --env X=name` fails with "not stored". The hooks keep redacting your values meanwhile: they also read the old keychain item. Old `token_vault:` references keep working after the migration.
- A `tv` symlink you made on your PATH now points at nothing: link `plugin/bin/skey` instead. Hooks and docs call `skey`.
- CI installs Claude Code 2.1.309 and runs `claude plugin validate` with `--profile directory --strict`; the standard-library manifest tests run too. Bump the pinned version deliberately.


## [2.0.1] - 2026-10-23

Fixes from a review of 2.0.0.

### Fixed
- The failure fallback (redaction itself raised) replaced only top-level strings, so a nested tool output such as `{"file": {"content": …}}` reached the model unchecked. Every string at any depth is replaced now, keys included unless they look like field names (`stdout`, `filePath`), except a top-level string `type`: changing that makes Claude Code discard the replacement and use the original output. A list-valued output keeps its list shape (strings replaced) instead of becoming one notice string.
- A store failure other than a locked keychain crashed the hook. It is judged like any failed check now: the input hook denies, the prompt hook blocks, the output hook replaces the output.
- The OpenAI pattern matched hyphenated slugs (`task-sk-update-the-…`), so ordinary branch names were denied. It no longer matches after a letter, digit, underscore or hyphen. Trade-off: an OpenAI key glued directly after one of those (`ORG-sk-proj-…`) isn't caught by the pattern either; a stored key is still caught by the known-value check. The Anthropic pattern is unchanged (`sk-ant-` is never part of a slug).
- Values in the project's own .env files are secrets now: the hook reads the files under the session's directory (depth 4, build folders skipped) and redacts their secret-looking values from any output, and denies calls carrying them, however the file was read (globs, braces, `$(…)`, a script). Reported as a warning when not fully read: files past the walk limit, the part of a file over 1 MB, anything past 4 MB read in one call, and files that aren't regular files. Not covered, and not reported (the hook can't follow a `cd` or a path it can't resolve): files outside the session's directory; a read of one by name is still denied by the name check. Values under 8 characters and values that don't look secret (plain words, slugs, numbers, host:port, URLs without credentials; the password of a credential URL does count) are left alone. The name check stays as a first line for plain names, now in any case and with simple quoting; it no longer tries to follow every shell spelling.
- A store warning no longer replaces the output hook's failure message; both are shown. The dotenv read is bounded to 4 MB per call (no cache: it would put the values on disk).
- `scan_all_git_repos.sh` creates its plaintext backup at mode 0600 instead of copying the original mode first, skips every `*.example`/`.sample`/`.template`/`.dist` file (not only the plain ones), and its usage text names `plugin/bin/tv`.
- `scan_all_git_repos.sh` has tests now (example variants skipped; a `cp` shim shows each backup is 0600 from the moment it exists).
- Docs: all three hooks set `onFailure: "block"` (README said only two); the code is about 1,000 lines, not 450; a duplicated PEM bullet is removed from the 2.0.0 section (the fuller bullet stays).
- A .env file was checked with a `stat` and then opened by name, so a background process could swap it for a FIFO or a device in between and the hook would block on the read until its timeout. The file is opened once now and judged on the open descriptor, so there is no window to race; a FIFO, a device, a directory or a link to one is reported and skipped. The same holds for the file `tv run --dotenv` injects.
- The byte budget of the content scan is counted in bytes now, not in decoded characters, and a file is read within what is left of the budget: a call no longer overshoots its 4 MB budget by a whole file.
- A credential URL's password can't hold a `/`, `?` or `#` (RFC 3986 keeps them out of the userinfo), so `postgres://replica:6333/db/admin@team-db` is no longer read as a password (`6333/db/admin`).
- Every `.env.<suffix>` name is read by the content scan, not only the ones the plain .env pattern covers: `.env.prod~` was skipped without a word.
- A hook call no longer searches every known form in every string of the payload. Each form carries a signature character (its rarest one) and the forms that can't be in the payload are dropped once, before the search: with 1,000 secrets and a 20,000-line output, the output hook takes 0.4 s instead of 1.2 s. The forms that are dropped are the ones that could not have matched, so nothing is missed.
- `scan_all_git_repos.sh` sets the mode of a backup to 0600 again after the copy, so a backup name that was already taken (the same second) can't keep its old mode.
- A plain-word password in a credential URL is no longer a session-wide secret. `DATABASE_URL=postgres://app:password@localhost:5432/app` registered the word `password` itself, so every tool call that mentioned a password field was denied, every output was rewritten and every prompt about a password was blocked. A credential URL's password is judged like any other value now: a word is not a secret, and only a password with a digit, mixed case or a known token format counts.
- An error after the file is opened (a read that fails on a dying mount) is a warning now, not a verdict: it used to escape the scan into the fail-closed path, so every later call was denied, blocked or replaced. An unreadable file is reported and the call goes on.
- The content scan stays under the session's directory: a file that is a link out of it (`.env -> ~/.aws/credentials`) is not read, and it is reported. The scan covers the files under the session's directory, not whatever they point at.
- The budget warning says how much was read, and it is said once.
- A field name longer than 24 characters is kept in the failure fallback, so a long key isn't rewritten into a shape Claude Code doesn't recognise. A key in a known token format is replaced either way: it looks like a field name, but it is a value.
- `scan_all_git_repos.sh` says so when it cannot set the mode of a backup to 0600, instead of swallowing the error: the file still holds plaintext.
- The number of secrets the content scan registers per call is capped (500, shared out between the files; see the fair-share entry below). The walk was bounded, but the value count was not: a repo whose .env files hold a few hundred thousand secret-shaped values made every hook call rebuild the known forms from all of them, and the cost grew with the payload — measured at 2.4 s per call where the cap brings it to 0.09 s, and the bound is absolute now instead of growing with the repo.
- The file that is read is verified to be the file that was judged: the descriptor's device and inode have to match the resolved path's. A link that is re-pointed between the containment check and the open is not followed — the same race the FIFO fix closed, on the containment side.
- A credential URL's password that is one of the placeholders every tutorial uses (`passw0rd`, `admin123`, `ChangeMe`) doesn't count either: they pass the shape gate, and registering one would deny every call that mentions it.
- The budget warning says bytes when the read is small ("only the first 100 bytes"), instead of "only the first 0 KB".
- The content scan parses at most 1,000 lines per file. The 500-secret cap bounded the results, not the work: four committed 1 MB files of `A=1` (a few KB in git) were about a million records per call, each one run through the whole pattern set, on every pre, post and prompt hook against a 15 s timeout. Measured now: 50 files of 1,000 secret-shaped lines take 0.26 s; 4 MB of `A=1` takes 0.01 s. A file cut at the line limit is reported by name.
- The 500-secret cap is shared out between the files (each gets an even share, and what a small file doesn't use goes to the bigger ones) instead of stopping the scan at the first file that fills it. A planted 10 KB root file of 500 secret-shaped values used to switch off the check for the user's own `app/.env.local`. The warning names the file that was cut (`only 498 of 1000 secrets from .env.many were checked`).
- The file that is read is the resolved name, opened with `O_NOFOLLOW`, with its identity taken from `lstat` on that same name; a file whose identity can't be read is skipped and reported instead of being treated as verified. A folder swapped for a link between the resolve and the open is still a window; the cost is a value redacted that should not have been, never one printed.
- The list of `.env`-named files is trimmed to the 50 best-ranked as the walk goes, so it no longer grows with the number of such files in the tree.
- `tests/test_hooks.py` ends with its `unittest.main()` guard again: it sat above the dotenv test classes, so running the file directly skipped them (CI uses `discover` and was not affected).
- The 500-secret cap is shared out in two tiers: the files with an unusual name share at most a quarter of it, whatever the usual names ask for, so none is left with nothing; the files with a usual name (`.env`, `.env.local`…) share the rest. Forty-nine decoys of `.env.a01` used to cut the user's own `.env` to 10 secrets; now they take at most a quarter, so the usual names keep three quarters. Ten nested `.env.local` files of 100 values each can no longer leave a root `.env.prod` with none.
- A hook event with no working directory, or one that is not a folder or can't be resolved, gets a warning ("no .env file was searched") instead of silence: the content scan didn't run, and the user used to be told nothing.
- The warning counts the problems it doesn't list ("; and 2 more"): only the first five are named, and the rest used to vanish.
- The timing test for the unclosed quote times `parse_dotenv` itself: the hook cuts a file at 1,000 lines before it parses, so the old test no longer reached the quadratic path. A new test pins that a quoted value cut at the line limit keeps the lines before it.

### Known limits (unchanged)
- A repo can choose strings for the content scan to register: mixed-case or digit-bearing values under secret-sounding keys (`A_SECRET=JavaScript`) count as secrets, so a call that carries one is denied and an output that shows one is redacted. The scan is meant for the user's own files, and a repo that is cloned is not the user's; a repo author could use this to make calls fail. It is a nuisance and not a leak (nothing is printed), the label names `dotenv:KEY` so the file can be found, and the key rule stays as it is because a stricter one would stop redacting real passwords such as `DB_PASSWORD=Sup3rS3cret`.
- A regular file on a stalled network mount (NFS, CIFS) can still block the hook until its timeout: a read that hangs cannot be told apart from one that is slow. The hooks fail closed, so that call is denied (or the output replaced) and the session stops until it times out.
- In the content scan, the files with a usual name share three quarters or more of the 500-secret cap evenly, with no rank among them: ten `.env.local` files in subfolders, each holding hundreds of secret-shaped values, leave a root `.env` with its even share (about 50) instead of all of its values. The warning names each file that was cut. A fixed cap and files that a repo controls can't both be protected; a rank by depth would move the gap, not close it (a root `.env` could then crowd out `app/.env.local`).
- In the content scan, files with an unusual name (`.env.prod`, `.env.docker`…) share at most a quarter of the 500-secret cap (125 values), even when no usual-named file competes for it. This is the price of the decoy ceiling: a legitimate `.env.docker` holding more than about 125 secret-shaped values is cut, and the warning names it. Rename it to one of the usual names, or `tv import` it, to cover more.
- In the content scan, a credential-URL password that holds a `/` is not found as a password: RFC 3986 keeps `/` out of the userinfo, so it has to be written percent-encoded (`pa%2Fss`); the decoded form of such a password is not redacted.
- In the content scan, a credential-URL password that is a plain word is not redacted (`postgres://app:password@db`). A password that is a word is not a secret, but it is also not something the plugin can tell apart from one; it needs a digit, mixed case or a token format to count.
- In the content scan, a one-segment path with a digit or mixed case under a secret-sounding key (`SECRET_DIR=/Data1Ab9/`) counts as a secret: shape alone can't tell it from a token, and the safe side is to redact it. No key suffix (`_DIR`, `_PATH`, `_ID`, `_NAME`, `_USER`…) exempts a value: a mixed-case or digit-bearing value under `AUTH_USER` or `API_KEY_NAME` is redacted too.
- In the content scan, files are read shallowest first, with the usual names (exact lowercase `.env`, `.env.local`, `.env.production`…; a case variant is an ordinary name) ahead of other names in the same folder, so decoy files can't push them past the 50-file limit or use up the 4 MB budget first. A repo that fills the limits (50 files, 4 MB, 1,000 lines per file) with `.env`-named files in many subfolders can still hide a deeper file; the warning says a limit was hit, and the call is not denied. Within the files that are read, the 500-secret cap is shared out, so no one file can use it up.
- In the content scan, a secret after line 1,000 of a file is not redacted: the scan parses the first 1,000 lines (the file is reported by name, and the call is not denied). A file in a folder deeper than 4 levels is not read, and that one is not reported: the depth limit is silent.
- In the content scan, a base64 secret shaped like a path (`/abc…/xyz…`, about 1 in 170 random values) is treated as a path and not redacted.
- In the failure fallback, a short lowercase word used as a dict key (it looks like a field name) is kept.
- A command can transform a secret before printing it (`tv run --env A=key -- sh -c 'echo $A | rev'`). Redaction matches the stored value and its base64 and URL-encoded forms, nothing else; `tv run` hands the value to the command you chose.

## [2.0.0] - 2026-10-22

Rewrite after an audit found v1 inert and, once wired, unsafe.

### Changed
- Secrets live in the OS keychain (one item, via `keyring`) instead of a custom AES-CBC vault file. No custom cryptography remains.
- Commands get secrets by name through `tv run --env VAR=name` / `--dotenv`, injected into the child process only. The SessionStart export of every secret into the shell environment is gone: any command could print them.
- Detection: exact matches of stored secrets (plus base64/URL-encoded forms) and high-confidence provider patterns, replacing a "32+ characters" heuristic that flagged git SHAs, UUIDs, paths and the hook payload's own session id.
- Hook output uses the documented shapes (`hookSpecificOutput.permissionDecision`, `updatedToolOutput`, `decision: block`). v1's shapes were ignored, so it never blocked or redacted anything.
- Hooks run in exec form (`uv run --script bin/tv hook …`). v1's `"command": "uv run python3"` named a non-existent executable, so no hook ran.
- Block messages name the secret or token kind and never echo a value (v1 echoed the matched text).
- `scan_all_git_repos.sh` now needs an explicit `--dir`, runs as a dry run unless `--apply` is given, and uses `tv import` so the values go to the OS keychain. It no longer copies the plugin into the repositories it scans, no longer writes a vault file inside them, and no longer uses the hardcoded `TOKEN_VAULT_ENCRYPTION_KEY=scan-key` that was committed to this repository.
- The plugin lives in `plugin/`. A marketplace entry's `source` is a directory and everything under it is installed, so with the plugin at the repository root every install shipped the whole repository — the scan script above, the authoring skills, and an accidental `npm init`. The tests, the scan script and the authoring skills stay in the repository and out of the installed package.
- The `.env` guard now requires every `.env` name in a command to be safe. One safe name no longer vouches for the rest, so `cat .env.example .env` is denied. `git` is gated on the subcommand, so `git show HEAD:.env` is denied while `git check-ignore .env` is not. A `Glob` pattern is checked, and a `Grep` pattern is treated as the regex it is rather than as a path.
- The known-secret forms are computed once per hook instead of once per string, so a large tool input or output no longer costs a re-encoding of every secret per string.
- The writer lock is an advisory lock on a file, released by the kernel when the process ends. The previous scheme could spin forever on a lock file it could not remove, and a writer slower than the stale timeout could have its lock taken.
- A malformed hook event now exits 1 instead of 0, so the input and prompt hooks fail closed rather than waving the action through unjudged. An empty stdin fails the same way.
- A `.env` name preceded by `*` is matched, so a `*.env` or `.env.*` glob is caught as well as a spelled-out name. A glob metacharacter after the name is matched too, so `.env*` is caught. The guard allows only commands that cannot print a file's contents, so `find . -name '*.env'` is blocked along with `cat *.env`.
- `tv` is gated the way `git` is: `tv import`, `tv add`, `tv rm`, `tv list`, `tv warm` and `tv patterns` are allowed, and the command a `tv run` executes is checked as one. The CLI makes the `--` separator optional, so `tv run cat .env` is checked as well as `tv run -- cat .env`.
- A `tv run --dotenv <file>` is only allowed when every value in the file is empty or already a name. The check is structural, not heuristic: a value the plugin did not recognise — a connection string with a password in it — is exactly the one that would leak. It applies to every `--dotenv` path whatever it is called, and a relative path is refused when the command changes directory first.
- `ls --from-file=.env` prints the names in the file, so `ls` is only allowed without it.
- A `.env` name behind a brace or a parenthesis is found: `cat ${X}.env` and `cat $(echo .env)` are blocked.
- A shell substitution inside a substitution is scanned as well.
- A failed PostToolUse redaction replaces the output rather than handing the model the unredacted one. The shape is kept, so Claude Code uses the replacement.
- A stored value that is not a string is skipped instead of aborting the whole scan, so one bad entry no longer bricks the hooks.
- The dotenv parser picks the closing quote with the same escape-aware scanner it uses to fold a value, so a value whose first line carries an escaped quote is not mistaken for a closed one.
- The CI secret scan covers every file, the tests included: the fakes in the tests are assembled from parts, so the files themselves no longer hold a string the patterns match, and a real secret pasted into a test is caught.
- An assignment that names a `.env` is no longer skipped: `ENV_FILE=.env && cat $ENV_FILE` names the file, so it is blocked.
- `tv import` reads a dotenv file properly: a quoted value that spans lines is imported whole, and a value that is never closed makes the command fail without touching the file. Before, a multi-line value was truncated to its first line, the rest of the key stayed in the file in plaintext, and the command still said the file now held names only. An inline comment is no longer stored as part of the secret.
- A PEM private key is redacted as a whole block, whatever shape it arrives in: a body that ends mid-line, a key flattened onto one line, RFC 1423 pre-headers, or a byte that is not base64. The pattern consumes everything from the header to the END line, or to the end of the text when there is no END line.
- A secret in a dict key is redacted, not only one in a value, and two keys that redact to the same marker no longer collide.
- `tv import` reports the values it left in the file, and says the file was not changed when the write fails.
- A keychain item that is not a map is an error rather than an empty map. An empty map looks like "no secrets stored", and the next save would then wipe everything that was there.
- The writer lock file moved out of the temporary directory into a per-user one, so another account on the same machine cannot pre-create it and stop the first writer.

### Added
- `tv import` turns a `.env` into `token_vault:<name>` references (atomic write, file mode kept, `--dry-run`).
- `.env` read guard, `tv patterns`, hermetic unit tests, Forgejo CI.
- `.claude-plugin/marketplace.json`, so the plugin installs in one step from a marketplace URL.
- CI runs the unit tests, checks that every manifest is valid JSON, and checks that no secret pattern is committed. The plugin and hook linters live in the `plugin-authoring` and `hook-authoring` Claude Code skills, not in this repository.
- A `SessionStart` hook runs `tv warm`, and `tv add`, `tv rm` and `tv import` take a lock so two writers cannot lose each other's secrets.

### Removed
- The MCP server: it did not speak MCP, and returning a secret through a tool puts it in the model's context.
- `plugin.json` `dependencies` (it declares plugins, not Python packages), and an author entry that did not belong to this project.
- `package.json` and `pnpm-lock.yaml`: an `npm init` with no `index.js` and no `src/`, committed by accident.

### Not on `main`
- The v1 implementation was never on `main`, so nothing was removed from it. It lived on the `token-vault` branch, which was deleted when #5 was closed. That branch carried a `skill-authoring/.env` with a live Anthropic API key, nine `.DS_Store` files and three `.pyc` files; none of them is in this branch.
- The authoring skills are not in this repository either. They are Claude Code skills, and they live in the `skill-authoring`, `hook-authoring`, `plugin-authoring`, `claude-md-authoring` and `subagent-authoring` skills.

### Gotchas
- `updatedToolOutput` must match the tool's output shape, or Claude Code silently keeps the original. `redact_obj` rewrites strings in place to keep the shape.
- On `UserPromptSubmit`, a blocked prompt can still land in local prompt history. The guarantee covers the model and the API, not local files.
- `onFailure: "block"` needs Claude Code 2.1.295 or later. On older versions the field is ignored and a hook that cannot start is a non-blocking error, so the action proceeds.
- claude.ai and Cowork do not install a plugin with a top-level `bin/` directory, so this plugin is for the Claude Code CLI and the desktop app.
- The keychain map is one item, so two processes that both read it and then write it back would each lose the other's secrets — on macOS the second write also fails outright with keychain error -25299. `tv add`, `tv rm` and `tv import` hold a lock for the whole read-modify-write.
- `tv warm` runs at session start, so `uv` resolves keyring and macOS asks for keychain access before the first tool call rather than during it.
- The `.env` guard matches the file name in the command. `find . -name '*.env'` is blocked, because `find` can print a file with `-exec`.
- If the keychain is locked the hooks fall back to pattern matching only, so a stored secret in an unknown format would pass through the output unredacted.
- `scan_all_git_repos.sh` backs a file up to `<name>.tv-backup-<timestamp>` with mode 0600 until the import succeeds, then deletes it: the value is in the keychain by then and a plaintext copy has no reason to stay on disk. A backup that survives a failed import is skipped by the next run, and the summary says how many are left.
