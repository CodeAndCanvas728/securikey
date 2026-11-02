#!/usr/bin/env python3
"""Measure what the PreToolUse and PostToolUse hooks cost per tool call.

Two numbers per hook, over N runs (default 100):
  in-process   hooks.handle() alone, on a store holding a few secrets: what the check itself costs
  end-to-end   `uv run --script plugin/bin/skey hook <kind>` as Claude Code starts it: adds uv's startup,
               the interpreter and the imports, which is what every tool call really pays

The end-to-end run uses a keychain service that does not exist (SECURIKEY_SERVICE=securikey-bench-<pid>), so
it never reads your real secrets and never prompts. It therefore measures the hook with an empty store;
the in-process run covers the cost of known-value matching.

  python bench/hook_cost.py [--runs 100] [--budget-ms 150]

Exit 1 when an end-to-end p95 is over the budget, so CI or a person can gate on it.
"""
import argparse
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "plugin"))

from securikey import hooks  # noqa: E402
from securikey.store import MemoryStore  # noqa: E402

# Fake values, assembled so the file holds nothing the CI secret scan would flag.
SECRETS = {"deploy_key": "bench-Value-" + "Ab12Cd34Ef56", "api_token": "bench-Token-" + "Gh78Ij90Kl12"}
OUTPUT = "\n".join("line %d: build step ok, 0 warnings, artifact written" % i for i in range(200))


def event(kind, cwd):
    if kind == "pre":
        return {"hook_event_name": "PreToolUse", "cwd": cwd, "tool_name": "Bash",
                "tool_input": {"command": "pytest -q tests/ && echo done"}}
    return {"hook_event_name": "PostToolUse", "cwd": cwd, "tool_name": "Bash",
            "tool_input": {"command": "pytest -q tests/"}, "tool_response": {"stdout": OUTPUT, "stderr": ""}}


def percentile(samples, q):
    ordered = sorted(samples)
    return ordered[min(len(ordered) - 1, round(q * (len(ordered) - 1)))]


def summarise(samples):
    return {"p50": statistics.median(samples), "p95": percentile(samples, 0.95), "max": max(samples)}


def in_process(kind, runs, cwd):
    store, ev, samples = MemoryStore(SECRETS), event(kind, cwd), []
    for _ in range(runs):
        started = time.perf_counter()
        hooks.handle(kind, ev, store)
        samples.append((time.perf_counter() - started) * 1000)
    return summarise(samples)


def end_to_end(kind, runs, cwd):
    env = {**os.environ, "SECURIKEY_SERVICE": "securikey-bench-%d" % os.getpid(), "TOKEN_VAULT_SERVICE": ""}
    command = ["uv", "run", "--quiet", "--script", str(ROOT / "plugin" / "bin" / "skey"), "hook", kind]
    payload = json.dumps(event(kind, cwd))
    samples = []
    for i in range(runs + 1):
        started = time.perf_counter()
        done = subprocess.run(command, input=payload, text=True, capture_output=True, env=env, timeout=60)
        elapsed = (time.perf_counter() - started) * 1000
        if done.returncode != 0:
            raise SystemExit("the hook exited %d: %s" % (done.returncode, done.stderr.strip()[:300]))
        if i:  # the first run may download keyring: it is the warm-up, not a sample
            samples.append(elapsed)
    return summarise(samples)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runs", type=int, default=100)
    parser.add_argument("--budget-ms", type=float, default=150.0, help="end-to-end p95 budget per hook")
    parser.add_argument("--skip-end-to-end", action="store_true", help="measure in-process only (no uv needed)")
    args = parser.parse_args()
    over = False
    with tempfile.TemporaryDirectory() as cwd:
        print("%-12s %-5s %9s %9s %9s" % ("mode", "hook", "p50 ms", "p95 ms", "max ms"))
        for mode, fn in (("in-process", in_process), ("end-to-end", end_to_end)):
            if mode == "end-to-end" and args.skip_end_to_end:
                continue
            for kind in ("pre", "post"):
                s = fn(kind, args.runs, cwd)
                flag = ""
                if mode == "end-to-end" and s["p95"] > args.budget_ms:
                    over, flag = True, "  OVER BUDGET (%.0f ms)" % args.budget_ms
                print("%-12s %-5s %9.1f %9.1f %9.1f%s" % (mode, kind, s["p50"], s["p95"], s["max"], flag))
    return 1 if over else 0


if __name__ == "__main__":
    sys.exit(main())
