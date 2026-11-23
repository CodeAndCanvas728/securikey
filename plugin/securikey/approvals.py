"""Requests an agent files for the commands only a person can run, and what the person decided.

An agent that needs a rotation, a sync to Paperclip or a configuration mark does not stop and wait: it files
a request and carries on. The person runs `skey approve` at a terminal whenever they like, sees exactly
what each request will do, and answers. Nothing runs without that: the commands keep their own terminal
check (cli.require_terminal), and a request only names an operation. It never holds a value.

The file is `~/.cache/securikey/requests-<service>.json`, readable by this user only. The agent can write
to it too (it is the same user), so nothing in it is trusted: every entry is validated on every read, the
text shown for it comes from its fields and not from the agent's words, and an approval applies the copy
the person was shown, not a second read of the file. A forged "approved" entry does nothing, because only
`skey approve` runs anything.
"""
import contextlib
import json
import os
import re
import secrets
import time
import unicodedata

try:
    import fcntl
except ImportError:  # Windows: no advisory lock; the write is still atomic
    fcntl = None

from securikey import audit
from securikey.store import VaultError, check_name

OPS = ("rotate", "sync", "config")
STATUSES = ("pending", "approved", "denied", "failed")
MAX_PENDING = 20
MAX_REASON = 160
MAX_ONLY = 500
PENDING_TTL = 7 * 86400  # a request nobody answered in a week is dropped
DONE_TTL = 86400  # an answered one stays a day, so the agent can see what happened
CLOCK_SKEW = 300  # seconds a time may be ahead of this machine and still be believed
ID_RE = re.compile(r"r[0-9a-f]{6}")


def path(service):
    log = audit.log_path(service)
    return log.with_name(log.name.replace("audit-", "requests-", 1).replace(".log", ".json"))


def _line(text):
    """One printable line: control and format characters (an escape sequence, a bidi override) become spaces."""
    text = "".join(" " if unicodedata.category(ch).startswith("C") else ch for ch in str(text))
    return " ".join(text.split())[:MAX_REASON]


def _int(value, low, high):
    return isinstance(value, int) and not isinstance(value, bool) and low <= value <= high


def _clean(raw):
    """A valid entry as this module writes it, or None. Unknown keys are dropped."""
    if not isinstance(raw, dict):
        return None
    op, name, options, status = raw.get("op"), raw.get("name"), raw.get("options"), raw.get("status")
    if op not in OPS or status not in STATUSES or not isinstance(options, dict):
        return None
    if not isinstance(raw.get("id"), str) or not ID_RE.fullmatch(raw["id"]) or not _int(raw.get("ts"), 0, 10 ** 11):
        return None
    try:
        if op == "rotate":
            if not (_int(options.get("keep_days"), 0, 3650) and isinstance(options.get("generate"), bool)):
                return None
            options = {"keep_days": options["keep_days"], "generate": options["generate"]}
            check_name(name)
        elif op == "config":
            if options.get("state") not in ("on", "off"):
                return None
            options = {"state": options["state"]}
            check_name(name)
        else:
            only = options.get("only")
            if name != "paperclip" or not isinstance(options.get("update"), bool):
                return None
            if only is not None:
                if not isinstance(only, str) or len(only) > MAX_ONLY:
                    return None
                for part in only.split(","):
                    check_name(part.strip())
            options = {"only": only, "update": options["update"]}
    except (VaultError, AttributeError, TypeError):
        return None
    entry = {"id": raw["id"], "op": op, "name": name, "options": options, "reason": _line(raw.get("reason", "")),
             "ts": raw["ts"], "status": status}
    if status != "pending" and _int(raw.get("done"), 0, 10 ** 11):
        entry["done"] = raw["done"]
    return entry


def load(service, now=None):
    """The valid, unexpired entries. A missing or unreadable file is no requests."""
    now = time.time() if now is None else now
    try:
        raw = json.loads(path(service).read_text())
    except (OSError, ValueError):
        return []
    kept = []
    for item in raw if isinstance(raw, list) else []:
        entry = _clean(item)
        if entry is None:
            continue
        if max(entry["ts"], entry.get("done", 0)) > now + CLOCK_SKEW:
            continue  # dated in the future: written by hand, and would never expire
        age = now - entry.get("done", entry["ts"])
        if age < (PENDING_TTL if entry["status"] == "pending" else DONE_TTL):
            kept.append(entry)
    return kept


@contextlib.contextmanager
def _locked(service):
    target = path(service)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(str(target.with_suffix(".lock")), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if fcntl:
            fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)  # closing releases the lock


def _save(service, entries):
    target = path(service)
    tmp = target.with_name("%s.%d.tmp" % (target.name, os.getpid()))
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(json.dumps(entries, indent=1, sort_keys=True))
        os.replace(str(tmp), str(target))
    finally:
        if tmp.exists():
            tmp.unlink()


def add(service, op, name, options, reason="", now=None):
    """(entry, created). An identical pending request is returned as it is instead of filed twice."""
    now = time.time() if now is None else now
    entry = _clean({"id": "r" + secrets.token_hex(3), "op": op, "name": name, "options": options,
                    "reason": reason, "ts": int(now), "status": "pending"})
    if entry is None:
        raise VaultError("that is not a request this tool can file")
    with _locked(service):
        entries = load(service, now)
        for old in entries:
            if old["status"] == "pending" and (old["op"], old["name"], old["options"]) == (op, name, entry["options"]):
                return old, False
        if sum(e["status"] == "pending" for e in entries) >= MAX_PENDING:
            raise VaultError("%d requests are already waiting; the user has to answer some first" % MAX_PENDING)
        entries.append(entry)
        _save(service, entries)
    return entry, True


def resolve(service, request_id, status, now=None):
    """Record the person's answer on one request. Other entries, including new ones, are kept."""
    now = time.time() if now is None else now
    with _locked(service):
        entries = load(service, now)
        for entry in entries:
            if entry["id"] == request_id:
                entry["status"], entry["done"] = status, int(now)
        _save(service, entries)
