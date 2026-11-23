"""`skey setup <harness>`: install or remove the securikey hooks for Vibe, Pi or OpenCode.

The hooks are thin shims that pipe JSON to `skey hook <kind> --host <host>` (see hosts.py). Installing writes
them into the harness's home with the absolute paths of `uv` and `skey` filled in, because a harness started
from a launcher may not have `~/.local/bin` on its PATH. A file carries MARKER, and `--remove` deletes only
files that carry it.
"""
import json
import os
import shlex
import shutil
from pathlib import Path

from securikey.store import VaultError

MARKER = "securikey-managed"
HARNESSES = ("vibe", "pi", "opencode")
PLUGIN_ROOT = Path(__file__).resolve().parent.parent
CACHE_PART = "/.claude/plugins/cache/"
VIBE_SCHEMA = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
VIBE_EXTENSION = "ai.mistral.vibe"
HOOK_TIMEOUT_S = 15
RELOAD = {"vibe": "Start a new Vibe session (or run /reload-plugins).",
          "pi": "Start a new Pi session (or run /reload).",
          "opencode": "Restart OpenCode."}


def harness_home(harness, env=None):
    env = os.environ if env is None else env
    home = Path(env.get("HOME") or Path.home())
    if harness == "vibe":
        return Path(env.get("VIBE_HOME") or home / ".vibe")
    if harness == "pi":
        return Path(env.get("PI_CODING_AGENT_DIR") or home / ".pi" / "agent")
    if harness == "opencode":
        if env.get("OPENCODE_CONFIG_DIR"):
            return Path(env["OPENCODE_CONFIG_DIR"])
        return Path(env.get("XDG_CONFIG_HOME") or home / ".config") / "opencode"
    raise VaultError("unknown harness %r" % harness)


def skey_path():
    """The absolute path the shims run. The link on PATH when it points at this checkout (it survives
    relinking), else this checkout's bin/skey. A path into the plugin cache is refused: it is versioned and
    goes stale on the next update."""
    here = PLUGIN_ROOT / "bin" / "skey"
    found = shutil.which("skey")
    chosen = Path(os.path.abspath(found)) if found and Path(found).resolve() == here.resolve() else here
    if CACHE_PART in chosen.resolve().as_posix():
        raise VaultError("skey runs from the plugin cache (%s), a path that changes on every update. Link a "
                         "stable copy first: ln -sf /path/to/securikey/plugin/bin/skey ~/.local/bin/skey, "
                         "then run `skey setup` through that link." % chosen.resolve())
    return str(chosen)


def uv_path():
    found = shutil.which("uv")
    if not found:
        raise VaultError("uv is not on PATH; the hooks run through `uv run --script`")
    return os.path.abspath(found)


def version():
    manifest = PLUGIN_ROOT / ".claude-plugin" / "plugin.json"
    try:
        return json.loads(manifest.read_text(encoding="utf-8"))["version"]
    except (OSError, ValueError, KeyError):
        return "0.0.0"


def _escaped(value):
    """A value for the inside of a double-quoted TypeScript string."""
    return json.dumps(value)[1:-1]


def _fill(text, uv, skey):
    return text.replace("@@UV@@", _escaped(uv)).replace("@@SKEY@@", _escaped(skey))


def _vibe_files(uv, skey):
    manifest = {"$schema": VIBE_SCHEMA, "name": "securikey", "version": version(),
                "description": "Redacts secrets from tool output and blocks them in tool calls and prompts.",
                "extensions": {VIBE_EXTENSION: {"schemaVersion": 1}}}
    lines = ["# %s: written by `skey setup vibe`, removed by `skey setup vibe --remove`." % MARKER, ""]
    # post_tool runs for failed calls as well (tool_status is "failure"): the one hook covers both.
    for name, event, kind in (("pre", "pre_tool", "pre"), ("post", "post_tool", "post"),
                              ("prompt", "pre_agent", "prompt")):
        command = shlex.join([uv, "run", "--quiet", "--script", skey, "hook", kind, "--host", "vibe"])
        lines += ["[[hooks]]", 'name = "%s"' % name, 'type = "%s"' % event]
        if event != "pre_agent":
            lines.append('match = "*"')
        lines += ["command = %s" % json.dumps(command, ensure_ascii=False), "strict = true", "timeout = %d" % HOOK_TIMEOUT_S, ""]
    return {"plugin.json": json.dumps(manifest, indent=2) + "\n",
            VIBE_EXTENSION + "/hooks.toml": "\n".join(lines)}


def plan(harness, uv, skey, env=None):
    """{absolute path: content} of every file `skey setup <harness>` writes, and the one that carries MARKER."""
    home = harness_home(harness, env)
    if harness == "vibe":
        root = home / "plugins" / "securikey"
        files = {root / rel: text for rel, text in _vibe_files(uv, skey).items()}
        return files, root / VIBE_EXTENSION / "hooks.toml"
    folder = "extensions" if harness == "pi" else "plugins"
    target = home / folder / "securikey.ts"
    source = (PLUGIN_ROOT / "harness" / harness / "securikey.ts").read_text(encoding="utf-8")
    return {target: _fill(source, uv, skey)}, target


def _managed(path):
    try:
        return MARKER in path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False


def install(harness, env=None):
    """Write the files. Returns their paths. Refuses to overwrite a file securikey did not write."""
    files, marked = plan(harness, uv_path(), skey_path(), env)
    existing = [path for path in files if path.exists()]
    if existing and not (marked.exists() and _managed(marked)):
        raise VaultError("%s exists and was not written by securikey; move it first" % existing[0])
    for path, text in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return sorted(files)


def remove(harness, env=None):
    """Delete the files `install` wrote. Returns what was removed. A file without MARKER is left alone."""
    files, marked = plan(harness, "uv", "skey", env)
    if not marked.exists():
        return []
    if not _managed(marked):
        raise VaultError("%s was not written by securikey, so it was left alone" % marked)
    removed = []
    for path in sorted(files):
        if path.exists():
            path.unlink()
            removed.append(path)
    if harness == "vibe":  # the plugin's own folders; Pi's and OpenCode's folders are shared and stay
        for folder in (marked.parent, marked.parent.parent):
            try:
                folder.rmdir()
            except OSError:
                pass
    return removed
