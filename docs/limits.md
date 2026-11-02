# What SecuriKey does not do

The short list is in the [README](../README.md#limits-at-a-glance). This is the full one. `tests/test_known_bypasses.py` pins several of these as tests, so they cannot drift quietly.

## A failed call is not redacted, unless `skey run` started it

Claude Code runs `PostToolUse` only when a tool succeeds. A Bash command that exits non-zero (`curl -f` on a 401, a script that crashes, `cat file; false`) fires `PostToolUseFailure` instead, and a hook cannot rewrite that error text. Checked on Claude Code 2.1.316:

- A command that printed a token and exited 3 gave the model the raw token.
- The `PostToolUseFailure` hook can detect a secret in the error and warn (`skey hook failure`), but its request to stop the turn (`continue: false`) was logged and the next turn still ran in `claude -p`. Interactive mode was not checked.
- Rewriting the command so it always succeeds is refused by Claude Code's own permission check (tried: an `EXIT` trap, an appended `echo`, a `{ ... } ||` group), so the plugin does not try.

What covers it: **`skey run` filters its own command's output** when stdout is piped (which is how an agent runs it). A failing `skey run --env T=name -- cmd` prints `[securikey:name]`, not the value, and still exits with the command's status. Verified end to end in Claude Code with a throwaway keychain service. Costs: a piped child can buffer or colour differently, and output is held back by up to 4096 characters or 0.25 seconds so a value split across two reads is still found. `SECURIKEY_RUN_FILTER=0` turns it off; at a terminal `skey run` still replaces itself with the command.

What is still exposed: a command that fails and printed a secret it did not get through `skey run` (a file it read, a variable already in the environment). Rotate a secret that was printed. The warning is pinned in `tests/test_hooks.py::FailedToolCallTest`, the filter in `tests/test_runfilter.py`.

## Output

- A command can't be un-run: a script that sends a secret over the network still sends it. Redaction controls what the **model** sees.
- Claude Code's local transcript and telemetry record tool output before a hook replaces it, and a blocked prompt can still appear in local prompt history. The guarantee is about the model and the API, not your disk.
- A command can transform a secret before it prints it, and the transformed text is not redacted. Redaction matches the stored value and its base64 and URL-encoded forms, nothing else: `skey run --env A=key -- sh -c 'echo $A | rev'` prints the value reversed, and hex, a value split across lines or output, or one with a separator between every character pass through the same way. `skey run` hands the value to the command you chose; it cannot judge what that command does with it.
- A secret in an unknown format that you never stored can't be recognised. Store it (`skey add`) and it is covered exactly.
- A stored value shorter than eight characters is not matched exactly, so it is not redacted. Short secrets are not really secrets, but the plugin will not pretend otherwise.
- If the keychain is locked, the hooks fall back to pattern matching only. A stored secret in a format the patterns do not know would then pass through unredacted; you are told when this happens.
- A private key is redacted whole, so everything after a `-----BEGIN ... PRIVATE KEY-----` line goes with it. A documentation page that quotes a key header will have the rest of the page redacted too.
- A file on a stalled network mount (NFS, CIFS) can still block the hook until its timeout. The hooks fail closed, so such a call is denied or the output replaced, and the session stops until it times out.

## Dotenv files

- The name guard allows a short list of commands that cannot print a file's contents: `skey import`, `skey add`, `skey rm`, `skey list`, `skey warm`, `skey patterns`, `git status`, `git ls-files`, `git check-ignore`, `git rev-parse`, `ls` and `test`. Everything else that names a dotenv file is blocked, `find . -name '*.env'` and `rsync --exclude '*.env'` included: they are safe to run, but `find` can print a file with `-exec`, so they are not on the list. A command that reaches a dotenv file through a shell expansion (`ls $(cat .env)`) is blocked too, because the command that runs is not the one that is written.
- Names matched: `.env`, `.envrc`, `.env.<suffix>`, `.env-<suffix>`, `.env_<suffix>`, and `prod.env`, `production.env`, `dev.env`, `staging.env`, `test.env`, `local.env`, `live.env`, `secrets.env`, `credentials.env`, in any case and with simple quoting. `process.env` and `.environment` are not names. The content scan below reads any file named `*.env`.
- `skey run` is checked as the command it runs, and it may only inject a file whose values are all names. A file that still holds a plaintext value is refused, because `skey run` would put it into the child's environment.
- The name check is not the guarantee. The hook also reads the project's own dotenv files and redacts their secret-looking values from every output, so a read it can't see by name (a glob, `$(...)`, a script) still doesn't reach the model, as long as the file still has its name when the output is checked. A command that moves the file first (`cat .en?; mv .en? notes.txt`) gets past the scan. That is an accepted gap.
- What the scan covers: the files under the session's directory, depth 4 (deeper folders are skipped without a warning), build folders skipped, a walk limit, 4 MB read per call, 1000 lines parsed per file (a secret after line 1,000 is not redacted; the file is reported by name), 500 values registered per call and shared out between the files (the usual names first), so one file full of values can't crowd out another. What is cut is reported by file name. A directory the command changes into is not scanned. A link that points out of the session's directory is not read, and the file that is opened is verified to be the file that was judged. Example files (`.env.example`, `.sample`, `.template`, `.dist`) are not scanned: they are meant to be committed, so keep real values out of them.
- Which values count: a value counts when it is a known token format, a credential-URL password, or sits under a secret-sounding key with a digit or mixed case. Whitespace at either end of a value is ignored (`KEY=" abc123 "` is judged as `abc123`); whitespace inside means a phrase, not a token, and it is left alone. Plain words (`NODE_ENV=production`), slugs, numbers, host:port, URLs without credentials, and paths that start with `/`, `./`, `../` or `~/` and have two or more segments never count. A lowercase-only passphrase under a secret key isn't treated as a secret either. This is a stricter rule than `skey import`'s.
- A credential URL's password is judged like any other value: it can't hold a `/` (`postgres://app:secret@db` counts, `postgres://replica:6333/db@host` doesn't), and a word is not a secret (`postgres://app:password@db` doesn't count, or every call that mentions a password field would be denied), nor are the placeholders every tutorial uses (`passw0rd`, `admin123`, `ChangeMe`).
- A base64 secret that happens to look like a path (`/abc.../xyz...`, about 1 in 170) is not redacted. A cloned repo can make the scan register words of its choosing (`A_SECRET=JavaScript`), so calls that carry them are denied: a nuisance, not a leak, and the label names `dotenv:KEY`.
- A dotenv file that holds `securikey:<name>` references only resolves when the command is started through `skey run --dotenv`. An application that reads the file itself sees the marker, not the value.

## Other

- The hooks are Claude Code only. The `skey` CLI works from any agent or shell.
- macOS and Linux are supported. On Linux the keychain needs a Secret Service provider (GNOME Keyring or KWallet). Windows is untested.
- `skey sync` and `skey rotate` are for your own terminal. The pre-hook denies a Bash call that names them (also nested, quoted or behind an expansion), but a text match on shell is never complete, and a process that opens its own pseudo-terminal gets past the terminal check: these are layers, not a sandbox. A command longer than 16 KB that names `skey`, `sync` or `rotate` is denied without being parsed.
