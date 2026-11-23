"""Run the securikey hooks for agent harnesses other than Claude Code.

Each harness sends its own payload. This module maps it to the Claude event the hooks already understand,
runs `hooks.handle`, and renders the result in the harness's own response shape, so the matching logic exists
once. The harness shims (harness/) only move JSON between the harness and `skey hook <kind> --host <host>`.

Three hosts:
  vibe      Mistral Vibe. Native payloads of the `pre_tool`, `post_tool` and `pre_agent` hooks; the response is
            the JSON Vibe reads (`decision`, `reason`, `system_message`).
  pi        Pi coding agent.
  opencode  OpenCode (V2 plugins).
            Pi and OpenCode have no hook protocol of their own, so their shims send one neutral payload
            (`tool`, `input`, `cwd` / `tool`, `response`, `cwd` / `text`, `cwd`) and get `{"action": ...}` back.

A call the mapping cannot read (no command, no path, bad base64) raises HostError and is denied: a wrong
field name would otherwise skip the shell and `.env` guards without a sound.
"""
import base64
import binascii
import json
import os

from . import hooks

HOSTS = ("vibe", "pi", "opencode")
BYPASS_ENV = "SECURIKEY_HOST_BYPASS"

# Harness tool name (lower case) -> the Claude tool name the hooks' guards are keyed on. A tool that is not
# listed keeps its name and is still scanned for secrets by the generic string scan.
TOOLS = {
    "vibe": {"bash": "Bash", "file_system.bash": "Bash", "process_start": "Bash", "process_write": "Bash",
             "read_file": "Read", "write_file": "Write", "edit": "Edit", "search_replace": "Edit",
             "grep": "Grep"},
    "pi": {"bash": "Bash", "read": "Read", "write": "Write", "edit": "Edit", "grep": "Grep", "find": "Glob",
           "ls": "Read"},
    "opencode": {"bash": "Bash", "shell": "Bash", "read": "Read", "write": "Write", "edit": "Edit",
                 "patch": "Edit", "grep": "Grep", "glob": "Glob"},
}
# Where a path may sit in a harness's input. Every one that is present must agree; it becomes `file_path`.
PATH_KEYS = ("file_path", "filePath", "path")
COMMAND_KEYS = ("command", "cmd")
# Tools whose path is optional (they default to the working directory).
OPTIONAL_PATH = {"ls", "grep", "find", "glob"}


class HostError(Exception):
    """The harness payload could not be read, so the call cannot be judged."""


def bypassed():
    """True when the harness was started with the bypass set. Read from the hook's own environment, which is
    the harness's: a tool call cannot change it."""
    return os.environ.get(BYPASS_ENV) == "1"


def _text(value):
    return value if isinstance(value, str) else None


def _single(native, keys, what):
    """The one string a harness reads from any of `keys`. Two keys that disagree are denied: the guards
    judge one value and the harness may act on the other. A key that is present but not a string is denied."""
    found = []
    for key in keys:
        if key not in native or native[key] is None:
            continue
        if not isinstance(native[key], str):
            raise HostError("%s: %s is not a string" % (what, key))
        found.append(native[key])
    if len(set(found)) > 1:
        raise HostError("%s: %s hold different values" % (what, "/".join(keys)))
    return found[0] if found else None


def _bash_command(name, native):
    command = _single(native, COMMAND_KEYS, name + " call")
    if name == "process_write":
        if command is not None:
            # The harness writes `text` and the bytes, not a command: judging a prefix the harness never
            # sends would change what the guards anchor on.
            raise HostError("process_write call with a command key")
        parts = [_text(native.get("text")) or ""]
        encoded = native.get("bytesBase64")
        if isinstance(encoded, str) and encoded:
            try:
                parts.append(base64.b64decode(encoded, validate=True).decode("utf-8", "replace"))
            except (binascii.Error, ValueError) as exc:
                raise HostError("process_write bytesBase64 is not valid base64: %s" % exc) from exc
        elif encoded is not None and not isinstance(encoded, str):
            raise HostError("process_write bytesBase64 is not a string")
        command = "".join(parts)
        if not command and "control" not in native:
            raise HostError("process_write has no text, bytes or control key")
        return command
    if command is None:
        raise HostError("%s call without a command string" % name)
    return command


def claude_tool(host, name, native):
    """(Claude tool name, tool_input) for one harness tool call."""
    if not isinstance(name, str) or not name:
        raise HostError("tool call without a tool name")
    if not isinstance(native, dict):
        raise HostError("tool_input of %s is not an object" % name)
    key = name.lower()
    claude = TOOLS[host].get(key)
    tool_input = dict(native)
    if claude is None:
        return name, tool_input
    if claude == "Bash":
        tool_input["command"] = _bash_command(key, native)
        return claude, tool_input
    path = _single(native, PATH_KEYS, name + " call")
    if not path:
        if key in OPTIONAL_PATH:
            return claude, tool_input
        raise HostError("%s call without a file path" % name)
    tool_input["file_path"] = path
    return claude, tool_input


def _cwd(payload):
    cwd = payload.get("cwd")
    return cwd if isinstance(cwd, str) and cwd else os.getcwd()


def _vibe_output(payload):
    """The text the model would see, as one string: the error of a failed call and the output."""
    parts = [payload.get(k) for k in ("tool_error", "tool_output_text")]
    parts = [p for p in parts if isinstance(p, str) and p]
    if not parts and payload.get("tool_output") is not None:
        parts = [json.dumps(payload["tool_output"], ensure_ascii=False, default=str)]
    return "\n".join(parts)


def translate(host, kind, payload):
    """(hook kind, Claude event) for one harness payload."""
    if host not in HOSTS:
        raise HostError("unknown host %r" % host)
    if not isinstance(payload, dict):
        raise HostError("the payload is not a JSON object")
    kind = "post" if kind == "failure" else kind
    event: dict = {"cwd": _cwd(payload)}
    if kind == "pre":
        if host == "vibe":
            name, native = payload.get("tool_name"), payload.get("tool_input")
        else:
            name, native = payload.get("tool"), payload.get("input")
        event["tool_name"], event["tool_input"] = claude_tool(host, name, native)
        event["hook_event_name"] = "PreToolUse"
    elif kind == "post":
        event["hook_event_name"] = "PostToolUse"
        event["tool_name"] = payload.get("tool_name") or payload.get("tool") or ""
        event["tool_response"] = _vibe_output(payload) if host == "vibe" else payload.get("response")
    elif kind == "prompt":
        event["hook_event_name"] = "UserPromptSubmit"
        prompt = payload.get("prompt") if host == "vibe" else payload.get("text")
        if not isinstance(prompt, str):
            raise HostError("the prompt is not a string")
        event["prompt"] = prompt
    else:
        raise HostError("hook kind %r has no mapping for %s" % (kind, host))
    return kind, event


def _reason(out):
    specific = (out or {}).get("hookSpecificOutput") or {}
    return specific.get("permissionDecisionReason") or (out or {}).get("reason") or "securikey: blocked."


def render(host, kind, out):
    """The harness response for the hook output `out` (None for nothing to say). None means pass through."""
    kind = "post" if kind == "failure" else kind
    out = out or {}
    specific = out.get("hookSpecificOutput") or {}
    message = out.get("systemMessage")
    if host == "vibe":
        if kind == "pre" and specific.get("permissionDecision") == "deny":
            return {"decision": "deny", "reason": _reason(out)}
        if kind == "prompt" and out.get("decision") == "block":
            return {"decision": "deny", "reason": _reason(out)}
        if kind == "post" and "updatedToolOutput" in specific:
            # Vibe replaces the output text with the reason of a deny.
            replaced = specific["updatedToolOutput"]
            text = replaced if isinstance(replaced, str) else json.dumps(replaced, ensure_ascii=False)
            return {"decision": "deny", "reason": text,
                    "system_message": message or specific.get("additionalContext") or ""}
        return {"system_message": message} if message else None
    if kind == "pre" and specific.get("permissionDecision") == "deny":
        return {"action": "deny", "reason": _reason(out)}
    if kind == "prompt" and out.get("decision") == "block":
        return {"action": "block", "reason": _reason(out)}
    if kind == "post" and "updatedToolOutput" in specific:
        return {"action": "replace", "response": specific["updatedToolOutput"],
                "message": message or specific.get("additionalContext")}
    response = {"action": "allow"}
    if message:
        response["message"] = message
    return response


def fail_response(host, kind, reason):
    """What a hook that could not judge says: deny the call or prompt, withhold the output."""
    kind = "post" if kind == "failure" else kind
    if host == "vibe":
        return {"decision": "deny", "reason": reason}
    if kind == "post":
        return {"action": "replace", "response": reason, "message": reason}
    return {"action": "block" if kind == "prompt" else "deny", "reason": reason}


def run(host, kind, payload, store):
    """The harness response to one payload, or None to pass through. Raises HostError for an unreadable one."""
    if bypassed():
        return {"action": "allow"} if host != "vibe" else None
    hook_kind, event = translate(host, kind, payload)
    return render(host, hook_kind, hooks.handle(hook_kind, event, store))
