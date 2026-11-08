"""Secret storage in the OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service).

All secrets live in one keychain item as a JSON map of name -> value, so the OS does the encryption
and access control and this project ships no cryptography of its own.
"""
import contextlib
import hashlib
import hmac
import json
import os
import re
import tempfile
import time
from pathlib import Path

try:
    import fcntl
except ImportError:  # Windows
    fcntl = None
    import msvcrt

DEFAULT_SERVICE = "securikey"


def current_service():
    """The keychain service this process uses. Read from the environment on every call, so one
    machine can keep one service per org (`SECURIKEY_SERVICE=securikey-client`) and a test or a
    parent process can change it after import."""
    return os.environ.get("SECURIKEY_SERVICE") or DEFAULT_SERVICE


def is_headless():
    """True when SECURIKEY_HEADLESS is set: nobody is there to read a warning or answer a prompt.

    A hook cannot tell this from the outside (its stdin is always a pipe, so a missing terminal
    proves nothing), so the host says so: Paperclip sets it in the agent's env.
    """
    return os.environ.get("SECURIKEY_HEADLESS", "").strip().lower() in ("1", "true", "yes")


SERVICE = current_service()  # kept for callers that import it; new code calls current_service()
# Where secrets lived before 3.0.0 (the plugin was called token-vault). Only `skey migrate` and the hooks read it.
LEGACY_SERVICE = os.environ.get("TOKEN_VAULT_SERVICE", "token-vault")
ACCOUNT = "secrets"
WATCH_ACCOUNT = "watch"  # values that are redacted for a while: retired by `skey rotate`, fetched from Paperclip
CONFIG_ACCOUNT = "config"  # entries a person marked as non-secret configuration: {name: hash of the marked value}
NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
LOCK_TIMEOUT = 10.0  # seconds to wait for another process to finish


class VaultError(Exception):
    """A user-facing failure: the message is safe to print and never contains a secret value."""


def check_name(name):
    if not NAME_RE.match(name):
        # The name is not echoed: it can come from a file, and a file may hold
        # a secret.
        raise VaultError("secret names are lowercase letters, digits and _ (start with a letter)")
    return name


def _take(fd):
    """Take an exclusive lock on fd. False when another process holds it."""
    if fcntl is not None:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            return False
    try:
        # msvcrt locks a region from the current position and needs a byte to
        # lock, so the write is inside the attempt: if it fails, the caller
        # retries rather than the command aborting.
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, b"\0")
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        return True
    except OSError:
        return False


def _lock_path(service):
    """Where the lock file goes: a directory only this user can write.

    A predictable path in the temporary directory can be pre-created by another
    account, which would stop the first writer dead, so a per-user directory
    is used when there is one.
    """
    base = os.environ.get("XDG_RUNTIME_DIR") or os.path.join(os.path.expanduser("~"), ".cache")
    # The legacy service keeps its 2.x lock file, so a 2.x writer and `skey migrate` exclude each other.
    directory = Path(base) / ("token-vault" if service == LEGACY_SERVICE else "securikey")
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError:
        directory = Path(tempfile.gettempdir())
    user = getattr(os, "getuid", lambda: 0)()
    name = re.sub(r"[^A-Za-z0-9_-]", "-", service)
    return directory / ("%d-%s.lock" % (user, name))


@contextlib.contextmanager
def _exclusive(service):
    """Hold an exclusive lock for one load-modify-save of the keychain map.

    keyring has no transaction: two processes that both read the map and then
    write it back would each lose the other's secrets. The lock is an advisory
    lock on a file, which the kernel releases when the process ends, so a
    crashed writer cannot leave the map locked, and the lock cannot be stolen
    by a stale file.
    """
    path = _lock_path(service)
    fd = os.open(str(path), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        deadline = time.monotonic() + LOCK_TIMEOUT
        while not _take(fd):
            if time.monotonic() > deadline:
                raise VaultError("another securikey process holds the lock (%s)" % path)
            time.sleep(0.05)
        yield
    finally:
        os.close(fd)


class KeychainStore:
    """Reads and writes the secret map in the OS keychain via the `keyring` package."""

    # Set by a store that had a partial failure; the hooks show it as a systemMessage.
    warning = None

    def __init__(self, service=None):
        self.service = service or current_service()

    def load_watch(self):
        """{label: value} of the watched values that have not expired. Never raises for a bad item:
        the watch list only adds protection, so a corrupt one is treated as empty."""
        keyring = _keyring()
        try:
            raw = keyring.get_password(self.service, WATCH_ACCOUNT)
        except keyring.errors.KeyringError as exc:
            raise VaultError("keychain unavailable: %s" % type(exc).__name__) from exc
        return _live(_parse_watch(raw), time.time())

    def add_watch(self, label, value, ttl_seconds, locked=False):
        """Redact `value` as `label` for ttl_seconds. Expired entries are dropped on the way.

        locked=True when the caller already holds transaction(): the lock is not reentrant, so
        taking it again would wait out LOCK_TIMEOUT and fail.
        """
        keyring = _keyring()
        with (contextlib.nullcontext() if locked else self.transaction()):
            try:
                items = _parse_watch(keyring.get_password(self.service, WATCH_ACCOUNT))
                now = time.time()
                items = {k: v for k, v in items.items() if v["until"] > now}
                items[label] = {"value": value, "until": now + ttl_seconds}
                keyring.set_password(self.service, WATCH_ACCOUNT, json.dumps(items, sort_keys=True))
            except keyring.errors.KeyringError as exc:
                raise VaultError("keychain unavailable: %s" % type(exc).__name__) from exc

    def load_config(self):
        """{name: hash} of the entries marked as non-secret configuration. A missing, corrupt or
        unreadable item is empty: nothing is marked, so every entry stays secret."""
        keyring = _keyring()
        try:
            return _parse_config(keyring.get_password(self.service, CONFIG_ACCOUNT))
        except keyring.errors.KeyringError as exc:
            raise VaultError("keychain unavailable: %s" % type(exc).__name__) from exc

    def save_config(self, marks):
        keyring = _keyring()
        try:
            if marks:
                keyring.set_password(self.service, CONFIG_ACCOUNT, json.dumps(marks, sort_keys=True))
            else:
                try:
                    keyring.delete_password(self.service, CONFIG_ACCOUNT)
                except keyring.errors.PasswordDeleteError:
                    pass
        except keyring.errors.KeyringError as exc:
            raise VaultError("keychain unavailable: %s" % type(exc).__name__) from exc

    def load(self):
        keyring = _keyring()
        try:
            raw = keyring.get_password(self.service, ACCOUNT)
        except keyring.errors.KeyringError as exc:
            raise VaultError("keychain unavailable: %s" % type(exc).__name__) from exc
        if not raw:
            return {}
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise VaultError("keychain item %r is not a securikey map" % self.service) from exc
        if not isinstance(data, dict):
            # Not a map. Returning an empty one would look like "no secrets
            # stored", and the next save would then wipe whatever is there.
            raise VaultError("keychain item %r is not a securikey map" % self.service)
        return data

    def save(self, secrets):
        keyring = _keyring()
        try:
            # Every write path goes through here, so a mark never outlives the value it was made for:
            # dropped first, so a failure after it leaves an entry secret, never marked.
            marks = _parse_config(keyring.get_password(self.service, CONFIG_ACCOUNT))
            kept = {name: mark for name, mark in marks.items() if name in config_names(secrets, marks)}
            if kept != marks:
                self.save_config(kept)
            keyring.set_password(self.service, ACCOUNT, json.dumps(secrets, sort_keys=True))
        except keyring.errors.KeyringError as exc:
            raise VaultError("keychain unavailable: %s" % type(exc).__name__) from exc

    def delete(self):
        """Remove the keychain item. A missing item is not an error."""
        keyring = _keyring()
        try:
            keyring.delete_password(self.service, ACCOUNT)
        except keyring.errors.PasswordDeleteError:
            pass
        except keyring.errors.KeyringError as exc:
            raise VaultError("keychain unavailable: %s" % type(exc).__name__) from exc

    def transaction(self):
        """Hold the lock across a load-modify-save cycle."""
        return _exclusive(self.service)


class MemoryStore:
    """In-memory store with the same interface, for tests."""

    warning = None

    def __init__(self, secrets=None, service="memory"):
        self.service = service
        self.secrets = dict(secrets or {})
        self.watch = {}  # label -> {"value", "until"}
        self.config = {}  # name -> hash of the value that was marked as non-secret

    def load_config(self):
        return dict(self.config)

    def save_config(self, marks):
        self.config = dict(marks)

    def load_watch(self):
        return _live(self.watch, time.time())

    def add_watch(self, label, value, ttl_seconds, locked=False):
        self.watch[label] = {"value": value, "until": time.time() + ttl_seconds}

    def load(self):
        return dict(self.secrets)

    def save(self, secrets):
        marked = config_names(secrets, self.config)
        self.config = {name: mark for name, mark in self.config.items() if name in marked}
        self.secrets = dict(secrets)

    def delete(self):
        self.secrets = {}

    def transaction(self):
        """One process, so there is nothing to lock."""
        return contextlib.nullcontext()


def _parse_watch(raw):
    """{label: {"value": str, "until": float}} from the stored JSON; anything malformed is dropped."""
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items()
            if isinstance(k, str) and isinstance(v, dict) and isinstance(v.get("value"), str)
            and isinstance(v.get("until"), (int, float))}


def _parse_config(raw):
    """{name: hash} from the stored JSON; anything malformed is dropped, which leaves the entry secret."""
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, str)}


def value_mark(value):
    """What a mark records about a value, so it holds only for that value."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def config_names(secrets, marks):
    """The names whose mark still matches the stored value. A value stored again (anything that
    overwrites it) no longer matches, so the entry is a secret again. save() also drops the stale mark,
    so storing the old value a third time does not bring the mark back."""
    return {name for name, mark in marks.items()
            if isinstance(secrets.get(name), str) and hmac.compare_digest(mark, value_mark(secrets[name]))}


def _live(items, now):
    """{label: value} for the entries whose expiry is still ahead."""
    return {k: v["value"] for k, v in items.items() if v["until"] > now}


def _keyring():
    try:
        import keyring
        import keyring.errors  # noqa: F401  (submodule used by callers)
    except ImportError as exc:
        raise VaultError("the `keyring` package is missing: run skey through `uv run --script` (bin/skey does)") from exc
    return keyring
