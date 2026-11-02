"""A local record of which secrets were handed out, to reconcile with Paperclip's `secret_access_events`.

One JSON line per event: time, keychain service, command, secret names, variable names, the
command's basename and its parent process. Never a value and never the command line (an argument
can hold one). The file is `~/.cache/securikey/audit-<service>.log`, readable by this user only.
Failing to write it never stops the command: the person is told on stderr and the run goes on.
"""
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path


def log_path(service):
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return Path(base) / "securikey" / ("audit-%s.log" % re.sub(r"[^A-Za-z0-9_-]", "-", service))


def _parent_name():
    """The parent process's name, or None. `ps` is on macOS and Linux; anywhere else this is None."""
    try:
        out = subprocess.run(["ps", "-o", "comm=", "-p", str(os.getppid())], capture_output=True,
                             text=True, timeout=2, check=False).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    return os.path.basename(out) or None


def record(service, cmd, names=(), variables=(), command=None):
    """Append one event. `command` is the argv of what `skey run` starts; only its basename is kept."""
    entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "service": service, "cmd": cmd,
             "names": sorted(names), "vars": sorted(variables),
             "command": os.path.basename(command[0]) if command else None, "parent": _parent_name()}
    path = log_path(service)
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(str(path), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            if hasattr(os, "fchmod"):  # not on Windows before Python 3.13
                os.fchmod(fd, 0o600)  # a log made by an older umask or by hand is tightened too
            os.write(fd, (json.dumps(entry, sort_keys=True) + "\n").encode())
        finally:
            os.close(fd)
    except OSError as exc:
        print("skey: the audit log could not be written (%s)" % type(exc).__name__, file=sys.stderr)
