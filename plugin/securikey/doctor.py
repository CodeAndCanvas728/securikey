"""`skey doctor`: check, before an unattended agent starts, what would otherwise stall it silently.

A hook that cannot start (no `uv` on the daemon's PATH, a first-run download) blocks every tool
call, and nobody is there to see it. A locked keychain makes the hooks check patterns only, with a
message nobody reads. Each check prints one line and never a secret value, only names and counts.
"""
import json
import os
import re
import shutil
import subprocess
import threading
from pathlib import Path

from securikey import hooks
from securikey.store import VaultError, current_service

MIN_CLAUDE = (2, 1, 295)  # the first Claude Code with the hook output fields securikey uses
KEYCHAIN_TIMEOUT = 20.0  # seconds; a daemon cannot answer the macOS keychain prompt


def read_with_timeout(store, timeout):
    """The store's secrets, or a VaultError. A prompt nobody can answer shows up as a timeout."""
    box = {}

    def target():
        try:
            box["secrets"] = store.load()
        except BaseException as exc:  # noqa: BLE001 - handed to the caller, which reports it
            box["error"] = exc

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        raise VaultError("the keychain did not answer within %d s (a prompt nobody can answer?)" % timeout)
    if "error" in box:
        if isinstance(box["error"], VaultError):
            raise box["error"]
        raise VaultError("the keychain could not be read (%s)" % type(box["error"]).__name__)
    return box["secrets"]


def _claude_version(run=subprocess.run):
    try:
        out = run(["claude", "--version"], capture_output=True, text=True, timeout=10, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", out)
    return tuple(int(g) for g in match.groups()) if match else None


def _user_scope_enabled(environ):
    """Whether securikey is enabled in the user settings, which `--setting-sources user` reads."""
    root = Path(environ.get("CLAUDE_CONFIG_DIR") or os.path.join(os.path.expanduser("~"), ".claude"))
    try:
        enabled = json.loads((root / "settings.json").read_text()).get("enabledPlugins", {})
    except (OSError, ValueError, AttributeError):
        return False
    return isinstance(enabled, dict) and any(
        isinstance(k, str) and k.startswith("securikey@") and v for k, v in enabled.items())


def run_checks(store, headless=False, environ=None, which=shutil.which, claude_version=_claude_version,
               timeout=KEYCHAIN_TIMEOUT):
    """[(status, text)]: status is "ok", "warn" or "FAIL". Outside headless mode the two checks about
    the unattended setup (Claude Code version, user-scope install) are warnings, not failures."""
    environ = os.environ if environ is None else environ
    soft = "FAIL" if headless else "warn"
    results = []

    uv = which("uv")
    results.append(("ok", "uv is on PATH") if uv else
                   ("FAIL", "uv is not on PATH: every hook would fail to start and block the agent"))

    try:
        secrets = read_with_timeout(store, timeout)
        results.append(("ok", "keychain readable (service %s, %d secrets)" % (store.service, len(secrets))))
    except VaultError as exc:
        results.append(("FAIL", "keychain: %s" % exc))

    version = claude_version()
    if version is None:
        results.append((soft, "claude is not on PATH, so its version is unknown (needs >= %s)" %
                        ".".join(map(str, MIN_CLAUDE))))
    elif version < MIN_CLAUDE:
        results.append((soft, "Claude Code %s is older than %s" % (".".join(map(str, version)),
                                                                   ".".join(map(str, MIN_CLAUDE)))))
    else:
        results.append(("ok", "Claude Code %s" % ".".join(map(str, version))))

    results.append(("ok", "securikey is enabled at user scope") if _user_scope_enabled(environ) else
                   (soft, "securikey is not enabled in ~/.claude/settings.json; a run with "
                          "--setting-sources user would not load its hooks"))

    watched, problems = hooks.watched_env_secrets(environ)
    results.extend(("FAIL", problem) for problem in problems)
    if watched:
        results.append(("ok", "%d watched variable(s) set" % len(watched)))
    elif not problems and not environ.get(hooks.WATCH_ENV):
        results.append(("ok", "%s is not set (no injected variables watched)" % hooks.WATCH_ENV))

    results.append(("ok", "keychain service for this process: %s" % (store.service or current_service())))
    return results
