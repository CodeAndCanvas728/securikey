# Upgrading from token-vault (before 3.0.0)

The plugin was called token-vault and its binary `tv`. Secrets stay in the old keychain item (service `token-vault`) until you copy them once:

```bash
skey migrate --dry-run     # names and counts only; changes nothing
skey migrate               # copies, reads each back and compares it in memory
skey migrate --purge-old   # later: deletes the old item, only after every name verified
```

`migrate` skips identical items, refuses to overwrite a name whose value differs (it tells you what to do), and keeps the old item unless you pass `--purge-old`. Until you run it, the other commands remind you with a one-line hint. Dotenv files that still hold `token_vault:<name>` references keep working and print a notice asking you to change the prefix to `securikey:`. A `tv` symlink you made on your PATH no longer points anywhere: link `plugin/bin/skey` instead.

If `skey` on your PATH is a symlink into an old plugin cache (`~/.claude/plugins/cache/...`), it runs that old version, not your checkout or the latest install: relink it with `ln -sf /path/to/securikey/plugin/bin/skey ~/.local/bin/skey`.
