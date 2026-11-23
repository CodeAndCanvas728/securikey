"""`skey`: keep secrets in the OS keychain and hand them only to the process that needs them.

  skey add <name>                     value from a hidden prompt or stdin, never from the command line
  skey add --config <name>            store a value that is configuration, not a secret (your terminal only)
  skey config <name> on|off           mark a stored entry as configuration, or back to secret (your terminal only)
  skey gen <name> [--bytes N] [--hex]  store a new random secret; the value is never shown
  skey request rotate|sync|config ...   ask for a command only the user can run, and carry on; they approve it
  skey pending                         the requests waiting, and what became of the answered ones
  skey approve [id]...                 answer the requests, at your own terminal
  skey list | skey rm <name>
  skey run [--env VAR=name]... [--dotenv FILE]... [--env-from-paperclip VAR=key]... -- <command...>
  skey import <.env file> [--all] [--dry-run]   move values into the keychain, leave `securikey:<name>`
  skey migrate [--dry-run] [--purge-old]   copy secrets from the pre-3.0.0 keychain item (service token-vault)
  skey sync paperclip [--only a,b] [--update] [--dry-run]   create the keychain's names as Paperclip company secrets
  skey rotate <name> [--keep-days N] [--generate]  new value; the old one stays redacted for N days; updates Paperclip too
  skey doctor [--headless]            check what would stall an unattended agent (uv, keychain, Claude Code, install)
  skey hook pre|post|failure|prompt   Claude Code hook entry point (reads the event JSON on stdin)
  skey warm                            resolve the runtime and unlock the keychain once, at session start

Environment: SECURIKEY_SERVICE (keychain service, one per org), SECURIKEY_WATCH_ENV (variables a host injects,
redacted like stored secrets), SECURIKEY_HEADLESS=1 (fail closed when the keychain can't be read).
"""
import argparse
import getpass
import json
import os
import re
import sys
import secrets as _random
import tempfile
import time

from securikey import approvals, audit, doctor, harnesses, hooks, hosts, migrate, paperclip, runfilter
from securikey.dotenv import LEGACY_REF_PREFIX, REF_PREFIX, is_ref, parse_dotenv, parse_ref, secret_like
from securikey.redact import MIN_SECRET_LEN, PATTERNS, known_forms, redact
from securikey.store import (LEGACY_SERVICE, KeychainStore, VaultError, check_name, config_names, is_headless,
                             value_mark)

PAPERCLIP_VALUE_TTL = 24 * 3600  # seconds a value fetched from Paperclip stays in the redaction set
DEFAULT_KEEP_DAYS = 7  # days a rotated-out value stays in the redaction set


def _read_value(name):
    """A secret's value from a hidden prompt or stdin, never from the command line."""
    value = getpass.getpass("value for %s: " % name) if sys.stdin.isatty() else sys.stdin.read().rstrip("\n")
    if not value:
        raise VaultError("empty value; nothing stored")
    return value


def cmd_add(args, store):
    name = check_name(args.name)
    if args.config:
        require_terminal("add --config", CONFIG_WHY)
    value = _read_value(name)
    with store.transaction():
        secrets = store.load()
        secrets[name] = value
        store.save(secrets)
        if args.config:
            store.save_config({**store.load_config(), name: value_mark(value)})
    print("stored %s%s" % (name, " (non-secret configuration)" if args.config else ""))


GEN_MIN_BYTES, GEN_MAX_BYTES, GEN_DEFAULT_BYTES = 16, 1024, 32


def _random_value(nbytes, hex_digits=False):
    return _random.token_hex(nbytes) if hex_digits else _random.token_urlsafe(nbytes)


def cmd_gen(args, store):
    """Store a new random secret under a name that is free. The value is made here and never printed, so the
    caller (an agent) learns only that it exists. An existing name is refused: replacing a value is a rotation."""
    name = check_name(args.name)
    if not GEN_MIN_BYTES <= args.bytes <= GEN_MAX_BYTES:
        raise VaultError("--bytes is between %d and %d" % (GEN_MIN_BYTES, GEN_MAX_BYTES))
    value = _random_value(args.bytes, args.hex)
    with store.transaction():
        stored = store.load()
        if name in stored:
            raise VaultError("%s already exists; replacing a value is a rotation, which you run from your own "
                             "terminal (skey rotate %s)" % (name, name))
        stored[name] = value
        store.save(stored)
    print("stored %s (generated, %d bytes)" % (name, args.bytes))
    audit.record(store.service, "gen", [name], ())


def cmd_config(args, store):
    """Mark a stored entry as non-secret configuration, or back to secret."""
    require_terminal("config", CONFIG_WHY)
    name = check_name(args.name)
    with store.transaction():
        secrets = store.load()
        if not isinstance(secrets.get(name), str):
            raise VaultError("no secret named %s" % name)
        marks = dict(store.load_config())
        if args.state == "on":
            marks[name] = value_mark(secrets[name])
        else:
            marks.pop(name, None)
        store.save_config(marks)
    print("%s is %s" % (name, "non-secret configuration: not redacted, not blocked" if args.state == "on"
                        else "a secret"))


def cmd_list(args, store):
    secrets = store.load()
    try:
        marked = config_names(secrets, store.load_config())
    except VaultError:
        marked = set()
    lines = ["%s%s" % (name, "  (config)" if name in marked else "") for name in sorted(secrets)]
    print("\n".join(lines) if lines else "(no secrets stored)")


def cmd_rm(args, store):
    with store.transaction():
        secrets = store.load()
        if secrets.pop(args.name, None) is None:
            raise VaultError("no secret named %s" % args.name)
        store.save(secrets)  # also drops the entry's mark
    print("removed %s" % args.name)


def read_dotenv(path, secrets, plain=None):
    """{VAR: value} from a dotenv file, with `securikey:<name>` references resolved.

    A value that is not a reference and looks like a secret is added to `plain` (when given) as
    {"dotenv-run:KEY": value}, so the caller can redact it from the output of the command it feeds.
    """
    with open(path) as fh:
        text = fh.read()
    records, error = parse_dotenv(text)
    if error is not None:
        raise VaultError("%s: %s" % (path, error))
    env, legacy = {}, False
    for source, prefix, key, sep, value, comment in records:
        if key is None:
            continue
        ref = parse_ref(value)
        if ref:
            name, is_legacy = ref
            legacy = legacy or is_legacy
            value = _lookup(name, secrets, path)
        elif plain is not None:
            for part in hooks._secret_parts(key, value):
                label, n = "dotenv-run:" + key, 2
                while label in plain and plain[label] != part:
                    label, n = "dotenv-run:%s#%d" % (key, n), n + 1
                plain[label] = part
        env[key] = value
    if legacy:
        print("skey: %s uses the deprecated `%s` prefix; write `%s` instead (the old one still works for now)"
              % (path, LEGACY_REF_PREFIX, REF_PREFIX), file=sys.stderr)
    return env


def _lookup(name, secrets, where):
    if name not in secrets:
        raise VaultError("%s refers to %s, which is not stored (skey add %s)" % (where, name, name))
    return secrets[name]


def cmd_run(args, store, exec_fn=os.execvpe):
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        raise VaultError("nothing to run: skey run [--env VAR=name] [--dotenv FILE] -- <command>")
    secrets = store.load()
    env = dict(os.environ)
    names, variables = set(), set()
    plain = {}  # secret-looking values read straight from a --dotenv file: redacted from this run's output
    for path in args.dotenv:
        before = len(plain)
        loaded = read_dotenv(path, secrets, plain)
        if len(plain) > before:
            print("skey: %s holds plain values; the ones that look like secrets are redacted from this command's "
                  "output (short or plain-looking ones are not), and `skey import` would move them into the "
                  "keychain" % path, file=sys.stderr)
        env.update(loaded)
        variables.update(loaded)
    for pair in args.env:
        var, _, name = pair.partition("=")
        if not var or not name:
            raise VaultError("--env takes VAR=name, got %r" % pair)
        env[var] = _lookup(name, secrets, "--env %s" % var)
        names.add(name)
        variables.add(var)
    client = None
    fetched = {}
    for pair in args.env_from_paperclip:
        var, _, key = pair.partition("=")
        if not var or not key:
            raise VaultError("--env-from-paperclip takes VAR=key")
        client = client or paperclip.agent_client(secrets, os.environ)
        value = client.agent_value(key)
        if len(value) < MIN_SECRET_LEN:
            print("skey: the value of %s is under %d characters, so it will not be redacted"
                  % (key, MIN_SECRET_LEN), file=sys.stderr)
        else:
            # Registered before the command starts, so the hooks redact it from the first output; and kept
            # here too, so this run's own filter does not depend on reading the watch list back.
            store.add_watch("paperclip:%s" % key, value, PAPERCLIP_VALUE_TTL)
            fetched["paperclip:%s" % key] = value
        env[var] = value
        names.add("paperclip:%s" % key)
        variables.add(var)
    audit.record(store.service, "run", names, variables, command)
    if exec_fn is os.execvpe and _filter_output():
        return runfilter.run(command, env, known_forms(_redaction_set(store, secrets, fetched, plain)))
    exec_fn(command[0], command, env)


def _filter_output():
    """Whether `skey run` filters the command's output: when stdout is piped (the Bash tool always pipes
    it), unless SECURIKEY_RUN_FILTER=0. At a terminal it still replaces itself with the command."""
    if os.environ.get("SECURIKEY_RUN_FILTER", "1") == "0":
        return False
    try:
        return not sys.stdout.isatty()
    except (ValueError, AttributeError):
        return True


def _redaction_set(store, secrets, fetched=None, plain=None):
    """Everything the hooks would redact that this process can name: the stored secrets, the watched
    values (a rotated-out value) and the values this run fetched from Paperclip, which are held in memory
    so an unreadable watch list cannot drop them, and the plain values a `--dotenv` file put in the environment."""
    try:
        watched = store.load_watch()
    except VaultError as exc:
        if is_headless():  # nobody would read a warning: a reduced redaction set is a failed check
            raise
        print("skey: the watch list could not be read (%s), so values rotated out or fetched from Paperclip "
              "are not redacted from this command's output; the stored secrets still are" % exc, file=sys.stderr)
        watched = {}
    # What hooks.handle adds on top of the store, in the same order: the child inherits the whole
    # environment and runs in the project directory, so a watched variable or a .env value is in its output.
    dotenv_secrets, problems = hooks.project_dotenv_secrets({"cwd": os.getcwd()})
    env_secrets, env_problems = hooks.watched_env_secrets()
    for problem in problems + env_problems:
        print("skey: %s" % problem, file=sys.stderr)
    # What hooks.handle drops: an entry marked as configuration is not redacted from this output either.
    secrets = hooks.drop_config(store, secrets)
    return {**dotenv_secrets, **env_secrets, **watched, **(fetched or {}), **(plain or {}), **secrets}


def _free_name(key, value, secrets):
    base = re.sub(r"[^a-z0-9_]", "_", key.lower()).lstrip("_0123456789") or "secret"
    name, n = base[:60], 2
    while name in secrets and secrets[name] != value:
        name, n = "%s_%d" % (base[:57], n), n + 1
    return name


def cmd_import(args, store):
    with open(args.file, newline="") as fh:  # keep \r\n so the file is written back with its own endings
        text = fh.read()
    records, error = parse_dotenv(text)
    if error is not None:
        # Refuse rather than rewrite half of it: the value would stay in the
        # file in plaintext while the file claimed to hold names only.
        raise VaultError("%s: %s; the file was not changed" % (args.file, error))
    newline = "\r\n" if "\r\n" in text else "\n"
    with store.transaction():
        secrets = store.load()
        lines, moved, left = [], [], []
        for source, prefix, key, sep, value, comment in records:
            if key is not None and secret_like(key, value, args.all):
                name = _free_name(key, value, secrets)
                secrets[name] = value
                moved.append((key, name))
                line = "%s%s%s%s%s" % (prefix, key, sep, REF_PREFIX, name)
                if comment:
                    line += " " + comment
            else:
                line = source
                if key is not None and value and not is_ref(value):
                    left.append(key)
            lines.append(line)
        for key, name in moved:
            print("%s -> %s%s" % (key, REF_PREFIX, name))
        if args.dry_run or not moved:
            print("dry run: nothing changed" if args.dry_run else "no secret-looking values found")
            if left:
                print("%d value(s) did not look like secrets and were left in place: %s"
                      % (len(left), ", ".join(left)))
            return
        store.save(secrets)
        try:
            _atomic_write(args.file, newline.join(lines) + newline)
        except OSError as exc:
            # The values are safe in the keychain, but the file still holds
            # them. Say so, rather than leaving it to be discovered.
            raise VaultError("%s was not changed (%s), but %d value(s) are in the keychain"
                             % (args.file, exc, len(moved)))
    print("moved %d value(s) into the keychain; %s now holds their names" % (len(moved), args.file))
    if left:
        print("%d value(s) did not look like secrets and are still in the file: %s"
              % (len(left), ", ".join(left)))
        print("review them before committing it.")


def _atomic_write(path, text):
    mode = os.stat(path).st_mode & 0o777
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)), prefix=".skey-")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except OSError:
        os.unlink(tmp)
        raise


class _HookStore:
    """What the hooks check against: the current secrets plus any not yet migrated.

    Until `skey migrate` has run, the values are still in the old keychain item, and a hook
    that knew only the new one would let them through. The old item is read-only here and
    its failure becomes the hook's warning: the current store decides whether the hook can run.
    """

    def __init__(self, store, legacy_store):
        self.store, self.legacy_store = store, legacy_store
        self.warning = None

    def load_watch(self):
        return self.store.load_watch()

    def load_config(self):
        return self.store.load_config()

    def load(self):
        current = self.store.load()
        try:
            legacy = self.legacy_store.load()
        except VaultError as exc:
            if is_headless():
                raise  # nobody reads the warning: hooks.handle treats it as a failed check and fails closed
            # Shown by the hook as a systemMessage; the hook keeps running on the current store.
            self.warning = ("securikey: the old keychain item could not be read (%s); values stored only "
                            "there are not checked." % exc)
            return current
        # Keyed by name, so an old value under a name that was stored again would be dropped:
        # it keeps a key of its own, which is not a valid name and so cannot collide with one; the
        # key is also the label a deny message shows.
        merged = dict(current)
        for name, value in legacy.items():
            merged[name if name not in current or current[name] == value else "%s (old keychain item)" % name] = value
        return merged


def cmd_hook(args, store):
    if args.legacy_store is not None:
        store = _HookStore(store, args.legacy_store)
    raw = sys.stdin.read()
    if not raw.strip():
        # No event at all. There is nothing to judge, so the hook fails: exit 1
        # is a non-blocking error by default, but the hooks set
        # onFailure: "block", so for input and prompts the action is blocked rather than
        # waved through unjudged.
        print("skey: no hook event on stdin", file=sys.stderr)
        raise SystemExit(1)
    try:
        event = json.loads(raw)
    except json.JSONDecodeError as exc:
        # The event cannot be judged, so the hook has to fail. stderr carries
        # the reason.
        print("skey: malformed hook event: %s" % exc, file=sys.stderr)
        raise SystemExit(1)
    if args.host:
        return _host_hook(args, event, store)
    out = hooks.handle(args.kind, event, store)
    if out:
        print(json.dumps(out))


def _host_hook(args, event, store):
    """A hook event from another harness (Vibe, Pi, OpenCode). Anything that stops it judging the event
    answers in the harness's own shape with a deny or a withheld output, and exits 1, which the harness
    shims and Vibe's `strict` read as a block."""
    try:
        out = hosts.run(args.host, args.kind, event, store)
    except Exception as exc:  # noqa: BLE001 - an event that cannot be judged must not pass
        reason = "securikey: the check failed (%s: %s), so the call was not judged." % (type(exc).__name__, exc)
        print("skey: %s" % reason, file=sys.stderr)
        print(json.dumps(hosts.fail_response(args.host, args.kind, reason)))
        raise SystemExit(1)
    if out:
        print(json.dumps(out))


def cmd_warm(args, store):
    """Resolve the runtime and unlock the keychain once, before any tool call.

    `uv run --script` downloads keyring on first use, and macOS asks for
    keychain access once. Doing both here, at session start, keeps the first
    tool call inside its timeout instead of stalling on it.
    """
    if is_headless():
        # Nobody can read a warning or answer the keychain prompt, so a keychain that can't be
        # read in time stops the start with an explicit error: it reaches the host's run log on
        # stderr and in the exit code. The tool hooks fail closed on the same condition (see
        # hooks.handle), so the agent could not act meanwhile.
        try:
            doctor.read_with_timeout(store, _headless_timeout())
        except VaultError as exc:
            print("skey: headless: %s. Unlock the keychain for this user, or run `skey doctor --headless`."
                  % exc, file=sys.stderr)
            return 1
    else:
        try:
            store.load()
        except VaultError as exc:
            print("skey: %s" % exc, file=sys.stderr)
    print("skey: warmed", file=sys.stderr)


def _headless_timeout():
    try:
        return max(1.0, float(os.environ.get("SECURIKEY_HEADLESS_TIMEOUT", doctor.KEYCHAIN_TIMEOUT)))
    except ValueError:
        return doctor.KEYCHAIN_TIMEOUT


def cmd_migrate(args, store):
    if not _reads_legacy_item():
        # The old item holds every org's values from before per-org services. Copying it would put
        # them into this org's service (and --purge-old would delete the shared item).
        raise VaultError("`skey migrate` copies the shared pre-3.0.0 item, so it runs on the default service: "
                         "unset SECURIKEY_SERVICE for it")
    return migrate.migrate(store, args.migrate_from, dry_run=args.dry_run, purge_old=args.purge_old)


def cmd_doctor(args, store):
    results = doctor.run_checks(store, headless=args.headless or is_headless(), timeout=_headless_timeout())
    for status, text in results:
        print("%-4s %s" % (status, text))
    return 1 if any(status == "FAIL" for status, _ in results) else 0


def _at_terminal():
    return sys.stdin.isatty()


SEND_WHY = "sends secret values to a server"
CONFIG_WHY = "makes a value readable by the agent (it is no longer redacted or blocked)"


def require_terminal(what, why=SEND_WHY):
    """`sync` and `rotate` send values to a server whose address the environment sets, and marking an entry
    as configuration stops it being redacted, so they run only for a person at a terminal: stdin is a TTY
    and this is not an unattended run (SECURIKEY_HEADLESS). An agent's shell has no TTY. This is the
    control that does not depend on reading shell text; a process that allocates a pseudo-terminal itself
    is outside what this can stop."""
    if is_headless() or not _at_terminal():
        raise VaultError("`skey %s` %s, so it runs only from your own terminal "
                         "(not from an agent, a script or an unattended run)" % (what, why))


SETUP_WHY = "changes what runs around every tool call of another harness, and removing it switches the redaction off"


def cmd_setup(args, store):
    """Install the securikey hooks into Vibe, Pi or OpenCode, or take them out again."""
    require_terminal("setup", SETUP_WHY)
    if args.remove:
        paths = harnesses.remove(args.harness)
        print("skey: removed %s" % (", ".join(map(str, paths)) if paths else "nothing (not installed)"))
        return
    paths = harnesses.install(args.harness)
    print("skey: installed the %s hooks:" % args.harness)
    for path in paths:
        print("  %s" % path)
    print("%s Bypass: start the harness with %s=1." % (harnesses.RELOAD[args.harness], hosts.BYPASS_ENV))


def cmd_sync(args, store):
    """Create the keychain's secrets as Paperclip company secrets. Prints names, actions and ids only."""
    require_terminal("sync")
    secrets = store.load()
    client, company = paperclip.board_client(secrets, os.environ)
    wanted = sorted(n for n in secrets if n != paperclip.TOKEN_NAME)
    if args.only:
        chosen = [n.strip() for n in args.only.split(",") if n.strip()]
        unknown = [n for n in chosen if n not in secrets or n == paperclip.TOKEN_NAME]
        if unknown:
            # Not echoed: a name that is not in the keychain may be a pasted value.
            raise VaultError("--only names %d secret(s) that are not in the keychain" % len(unknown))
        wanted = sorted(set(chosen))
    existing = client.list_secrets(company)
    created = updated = kept = 0
    sent = []  # names whose value was offered to Paperclip: appended before the request, so a request that
    try:      # failed after it reached the server is still in the audit log
        for name in wanted:
            if name not in existing:
                if args.dry_run:
                    print("would create %s" % name)
                else:
                    sent.append(name)
                    print("created %s %s" % (name, client.create(company, name, secrets[name])))
                created += 1
            elif args.update:
                if args.dry_run:
                    print("would update %s %s" % (name, existing[name]))
                else:
                    sent.append(name)
                    client.rotate(existing[name], secrets[name])
                    print("updated %s %s" % (name, existing[name]))
                updated += 1
            else:
                print("exists %s %s (kept; --update stores a new version)" % (name, existing[name]))
                kept += 1
    finally:
        if sent:
            audit.record(store.service, "sync", sent, ())
    print("%s %d, updated %d, kept %d" % ("would create" if args.dry_run else "created", created, updated, kept))


def cmd_rotate(args, store):
    """Store a new value. The old one stays redacted for --keep-days, so it is caught while it may
    still be in a transcript, a log or a process that has not restarted."""
    require_terminal("rotate")
    name = check_name(args.name)
    if args.keep_days < 0:
        raise VaultError("--keep-days is zero or more")
    value = _random_value(GEN_DEFAULT_BYTES) if args.generate else _read_value(name)
    retired = False
    with store.transaction():
        secrets = store.load()
        if name not in secrets:
            raise VaultError("no secret named %s (skey add %s)" % (name, name))
        old = secrets[name]
        if old == value:
            raise VaultError("the new value is the same as the current one; nothing changed")
        if args.keep_days and len(old) >= MIN_SECRET_LEN:
            # Before the new value is saved: if this fails the old one is still the only one.
            store.add_watch("retired:%s" % name, old, args.keep_days * 86400, locked=True)
            retired = True
        secrets[name] = value
        store.save(secrets)
    print("rotated %s; %s" % (name, "the old value stays redacted for %d day(s)" % args.keep_days if retired
                               else "the old value is not kept in the redaction set"))
    audit.record(store.service, "rotate", [name], ())
    if not paperclip.in_use(secrets, os.environ):
        return  # most installs do not use Paperclip: nothing to report
    # A partial set of settings falls through: board_client names what is missing and the except below
    # says the keychain changed but Paperclip did not.
    try:
        # Inside the try: a bad Paperclip address must not hide that the keychain already has the new value.
        client, company = paperclip.board_client(secrets, os.environ)
        secret_id = client.list_secrets(company).get(name)
        if secret_id is None:
            print("%s is not a Paperclip secret yet: `skey sync paperclip` creates it" % name)
            return
        client.rotate(secret_id, value)
    except VaultError as exc:
        print("skey: the keychain has the new value, but Paperclip was not updated: %s" % exc, file=sys.stderr)
        return 1
    print("updated Paperclip secret %s" % secret_id)


APPROVE_WHY = "runs the commands that only you may run"


def _request_options(args):
    if args.op == "rotate":
        return args.name, {"keep_days": args.keep_days, "generate": args.generate}
    if args.op == "config":
        return args.name, {"state": args.state}
    return "paperclip", {"only": args.only, "update": args.update}


def cmd_request(args, store):
    """File a request for a command that needs the user, and return at once. Holds no value."""
    name, options = _request_options(args)
    stored = store.load()
    if args.op != "sync":
        name = check_name(name)
        if name not in stored:
            raise VaultError("no secret named %s (skey gen %s makes one)" % (name, name))
    elif options["only"] and any(n.strip() not in stored for n in options["only"].split(",")):
        # Not echoed: a name that is not in the keychain may be a pasted value.
        raise VaultError("--only names a secret that is not in the keychain")
    if args.reason and redact(args.reason, stored)[1]:
        raise VaultError("the reason contains a secret; say why in words")
    entry, created = approvals.add(store.service, args.op, name, options, args.reason or "")
    print("%s %s: %s. The user answers it from their own terminal with `skey approve`; carry on with other "
          "work, and `skey pending` shows what became of it." % ("queued" if created else "already queued",
                                                                    entry["id"], _describe(entry, short=True)))
    audit.record(store.service, "request", [] if args.op == "sync" else [name], ())


def _names(entry):
    only = entry["options"].get("only") if entry["op"] == "sync" else None
    return [n.strip() for n in only.split(",")] if only else ([] if entry["op"] == "sync" else [entry["name"]])


def _stored(entry, stored):
    """Whether every name the entry mentions is a stored secret. The file can hold anything the agent wrote, and
    a name there may be a pasted value, so a name that is not stored is never printed."""
    return all(n in stored for n in _names(entry))


def _describe(entry, short=False):
    """What approving the entry will do, from its fields only (never from the agent's own words)."""
    op, name, o = entry["op"], entry["name"], entry["options"]
    if op == "rotate":
        new = "a new value made here, shown to nobody" if o["generate"] else "a new value you type"
        keep = "the old one stays redacted %d day(s)" % o["keep_days"] if o["keep_days"] else "the old one is dropped"
        return ("rotate %s" % name) if short else "rotate %s: %s; %s; Paperclip is updated too when it is set up" % (
            name, new, keep)
    if op == "config":
        if o["state"] == "on":
            return ("mark %s as configuration" % name) if short else (
                "mark %s as non-secret configuration: it is no longer redacted or blocked, so anything that "
                "prints it reaches the agent" % name)
        return ("mark %s as a secret" % name) if short else "mark %s as a secret again (redacted and blocked)" % name
    which = o["only"] if o["only"] else "every name in the keychain"
    if short:
        return "sync %s to Paperclip" % ("only " + o["only"] if o["only"] else "all names")
    url = os.environ.get(paperclip.URL_ENV) or "(not set: it will stop with an error)"
    return "send %s to Paperclip at %s%s" % (which, _describe_url(url), "; new versions for names it has" if o["update"]
                                             else "; names it has are kept")


def _describe_url(url):
    return "".join(ch if ch.isprintable() else "?" for ch in url)[:200]


def _age(seconds):
    return "%d min" % (seconds // 60) if seconds < 3600 else "%d h" % (seconds // 3600)


def cmd_pending(args, store):
    entries = approvals.load(store.service)
    if not entries:
        print("no requests")
        return
    now, stored = time.time(), store.load()
    for e in sorted(entries, key=lambda e: e["ts"]):
        what = _describe(e, short=True) if _stored(e, stored) else "(names something that is not stored)"
        print("%s  %-8s %s  (%s ago)" % (e["id"], e["status"], what, _age(int(now - e["ts"]))))


def _ask(prompt):
    try:
        return input(prompt).strip().lower()[:1]
    except EOFError:
        return "s"


def cmd_approve(args, store):
    """Show each waiting request and run it on a yes. Only for a person at a terminal."""
    require_terminal("approve", APPROVE_WHY)
    waiting = [e for e in approvals.load(store.service) if e["status"] == "pending"]
    if args.ids:
        missing = [i for i in args.ids if i not in {e["id"] for e in waiting}]
        if missing:
            raise VaultError("no waiting request has that id (skey pending lists them)")
        waiting = [e for e in waiting if e["id"] in args.ids]
    if not waiting:
        print("no requests waiting")
        return
    failed, stored = False, store.load()
    for entry in waiting:
        if not _stored(entry, stored):
            print("%s names something that is not in the keychain; dropped" % entry["id"], file=sys.stderr)
            approvals.resolve(store.service, entry["id"], "failed")
            failed = True
            continue
        print("\n%s  asked %s ago\n  %s" % (entry["id"], _age(int(time.time() - entry["ts"])), _describe(entry)))
        if entry["reason"]:
            print("  the agent's reason (its own words, not checked): %s" % entry["reason"])
        answer = _ask("approve? [y]es / [n]o, discard / [s]kip: ")
        if answer == "n":
            approvals.resolve(store.service, entry["id"], "denied")
            audit.record(store.service, "deny", [] if entry["op"] == "sync" else [entry["name"]], ())
            print("discarded")
        elif answer == "y":
            try:
                result = COMMANDS[entry["op"]](parser().parse_args(_argv(entry)), store)
            except VaultError as exc:
                print("skey: %s" % exc, file=sys.stderr)
                approvals.resolve(store.service, entry["id"], "failed")
                failed = True
                continue
            approvals.resolve(store.service, entry["id"], "approved")
            audit.record(store.service, "approve", [] if entry["op"] == "sync" else [entry["name"]], ())
            failed = failed or bool(result)
        else:
            print("left waiting")
    return 1 if failed else None


def _argv(entry):
    """The command line the entry stands for, built from its validated fields."""
    op, name, o = entry["op"], entry["name"], entry["options"]
    if op == "rotate":
        return ["rotate", name, "--keep-days", str(o["keep_days"])] + (["--generate"] if o["generate"] else [])
    if op == "config":
        return ["config", name, o["state"]]
    return ["sync", "paperclip"] + (["--only", o["only"]] if o["only"] else []) + (["--update"] if o["update"] else [])


def parser():
    lines = (__doc__ or "").splitlines()
    p = argparse.ArgumentParser(prog="skey", description=lines[0] if lines else None, allow_abbrev=False,
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog="\n".join(lines[1:]).strip("\n"))
    sub = p.add_subparsers(dest="cmd", required=True, metavar="<command>")
    add = sub.add_parser("add", help="store a secret (hidden prompt or stdin)", allow_abbrev=False)
    add.add_argument("name", help="lowercase letters, digits and _")
    add.add_argument("--config", action="store_true",
                     help="store it as non-secret configuration (not redacted or blocked); your terminal only")
    gen = sub.add_parser("gen", help="store a new random secret; the value is never shown", allow_abbrev=False)
    gen.add_argument("name", help="lowercase letters, digits and _")
    gen.add_argument("--bytes", type=int, default=GEN_DEFAULT_BYTES, metavar="N",
                     help="bytes of randomness (default %d)" % GEN_DEFAULT_BYTES)
    gen.add_argument("--hex", action="store_true", help="hex digits instead of URL-safe base64")
    req = sub.add_parser("request", help="ask the user to run rotate, sync or config; they approve it later "
                         "with skey approve", allow_abbrev=False)
    ops = req.add_subparsers(dest="op", required=True, metavar="<op>")
    for op, text in (("rotate", "a new value for a stored secret"), ("sync", "create the names in Paperclip"),
                     ("config", "mark a stored entry as non-secret configuration, or back")):
        one = ops.add_parser(op, help=text, allow_abbrev=False)
        if op == "sync":
            one.add_argument("target", choices=["paperclip"])
            one.add_argument("--only", metavar="a,b")
            one.add_argument("--update", action="store_true")
        else:
            one.add_argument("name")
        if op == "rotate":
            one.add_argument("--keep-days", type=int, default=DEFAULT_KEEP_DAYS, metavar="N")
            one.add_argument("--generate", action="store_true", help="make the new value without showing it")
        if op == "config":
            one.add_argument("state", choices=["on", "off"])
        one.add_argument("--reason", metavar="TEXT", help="why, in a few words; shown to the user")
    sub.add_parser("pending", help="list the requests waiting for approval, and what became of the answered ones",
                   allow_abbrev=False)
    sub.add_parser("approve", help="answer the waiting requests (your terminal only)",
                   allow_abbrev=False).add_argument("ids", nargs="*", metavar="id")
    cfg = sub.add_parser("config", help="mark a stored entry as non-secret configuration, or back (your terminal "
                         "only)", allow_abbrev=False)
    cfg.add_argument("name")
    cfg.add_argument("state", choices=["on", "off"])
    sub.add_parser("list", help="list the stored names (never values)", allow_abbrev=False)
    sub.add_parser("rm", help="delete a secret", allow_abbrev=False).add_argument("name")
    run = sub.add_parser("run", help="run a command with secrets in its environment", allow_abbrev=False)
    run.add_argument("--env", action="append", default=[], metavar="VAR=name")
    run.add_argument("--dotenv", action="append", default=[], metavar="FILE")
    run.add_argument("--env-from-paperclip", action="append", default=[], metavar="VAR=key",
                     help="fetch a secret granted to this Paperclip run and register it for redaction")
    run.add_argument("command", nargs=argparse.REMAINDER)
    imp = sub.add_parser("import", help="move the secrets in a dotenv file into the keychain", allow_abbrev=False)
    imp.add_argument("file")
    imp.add_argument("--all", action="store_true", help="import every value, not only secret-looking ones")
    imp.add_argument("--dry-run", action="store_true")
    hook = sub.add_parser("hook", help="hook entry point (reads the event on stdin)", allow_abbrev=False)
    hook.add_argument("kind", choices=sorted(hooks.HANDLERS))
    hook.add_argument("--host", choices=hosts.HOSTS,
                      help="the event comes from this harness instead of Claude Code (vibe, pi, opencode)")
    setup = sub.add_parser("setup", help="install the hooks into Vibe, Pi or OpenCode (your terminal only)",
                           allow_abbrev=False)
    setup.add_argument("harness", choices=harnesses.HARNESSES)
    setup.add_argument("--remove", action="store_true", help="take the hooks out again")
    sub.add_parser("warm", help="unlock the keychain once, at session start", allow_abbrev=False)
    mig = sub.add_parser("migrate", help="copy secrets from the pre-3.0.0 keychain item", allow_abbrev=False)
    mig.add_argument("--dry-run", action="store_true", help="show what would be copied; change nothing")
    mig.add_argument("--purge-old", action="store_true",
                     help="delete the old keychain item, after every name is verified in the new one")
    sync = sub.add_parser("sync", help="create the keychain's names as Paperclip secrets (your terminal only)",
                          allow_abbrev=False)
    sync.add_argument("target", choices=["paperclip"])
    sync.add_argument("--only", metavar="a,b", help="sync only these names")
    sync.add_argument("--update", action="store_true", help="store a new version for names Paperclip already has")
    sync.add_argument("--dry-run", action="store_true")
    rot = sub.add_parser("rotate", help="store a new value; keep the old one redacted for a while "
                                        "(your terminal only)", allow_abbrev=False)
    rot.add_argument("name")
    rot.add_argument("--generate", action="store_true",
                     help="make the new value here instead of asking for it; nobody sees it")
    rot.add_argument("--keep-days", type=int, default=DEFAULT_KEEP_DAYS, metavar="N",
                     help="days the old value stays redacted (default %d, 0 for none)" % DEFAULT_KEEP_DAYS)
    sub.add_parser("doctor", help="check the setup (uv, keychain, Claude Code version, install)",
                   allow_abbrev=False).add_argument("--headless", action="store_true",
                                                    help="treat the unattended-setup checks as failures")
    sub.add_parser("patterns", help="list the token formats recognised without being stored", allow_abbrev=False)
    return p


COMMANDS = {"add": cmd_add, "gen": cmd_gen, "request": cmd_request, "pending": cmd_pending,
            "approve": cmd_approve, "config": cmd_config, "list": cmd_list, "rm": cmd_rm, "run": cmd_run, "import": cmd_import,
            "hook": cmd_hook, "setup": cmd_setup, "warm": cmd_warm, "migrate": cmd_migrate, "sync": cmd_sync,
            "rotate": cmd_rotate, "doctor": cmd_doctor,
            "patterns": lambda a, s: print("\n".join(sorted(PATTERNS)))}


# Commands that point at `skey migrate` when the new store is empty and the old one is not. Not the
# hooks (they run on every tool call and talk to Claude Code) and not `patterns` (no store involved).
HINTED = {"add", "gen", "list", "rm", "run", "import", "warm"}


def _reads_legacy_item():
    """Whether this process still reads the pre-3.0.0 keychain item: on the default service, or when
    TOKEN_VAULT_SERVICE is set on purpose."""
    return not os.environ.get("SECURIKEY_SERVICE") or bool(os.environ.get("TOKEN_VAULT_SERVICE"))


def _hint_migration(store, legacy_store):
    if legacy_store is not None and migrate.needs_migration(store, legacy_store):
        print("skey: no secrets here yet, but the pre-3.0.0 keychain item has some: run `skey migrate`",
              file=sys.stderr)


def main(argv=None, store=None, legacy_store=None):
    """`legacy_store` is the old keychain item; when `store` is injected (tests) it must be too."""
    args = parser().parse_args(argv)
    if store is None:
        store, legacy_store = KeychainStore(), KeychainStore(LEGACY_SERVICE)
    # `skey migrate` is an explicit request, so it always has its source. The hooks and the hint
    # read the pre-3.0.0 item only on the default service: a process with its own service
    # (SECURIKEY_SERVICE=securikey-client) must not see, or redact, another org's old values.
    args.migrate_from = legacy_store
    args.legacy_store = legacy_store if _reads_legacy_item() else None
    try:
        # Not headless: the hint reads the keychain on this thread with no time limit, and a prompt
        # nobody can answer would hang here before `warm` could time out and report it.
        if args.cmd in HINTED and not is_headless():
            _hint_migration(store, args.legacy_store)
        return COMMANDS[args.cmd](args, store) or 0
    except (VaultError, OSError) as exc:
        print("skey: %s" % exc, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("skey: interrupted; nothing was changed by this step", file=sys.stderr)
        return 130
    except EOFError:
        print("skey: no input (the prompt needs a value, or stdin was closed)", file=sys.stderr)
        return 1
    except UnicodeDecodeError:
        print("skey: a file or input is not valid UTF-8 text", file=sys.stderr)
        return 1
