"""Fail if any file in the working tree holds a string shaped like a real secret.

Every file is scanned, the tests included: a real secret pasted into a test while debugging is still a
leak. The fakes in the tests are assembled from parts, so the files themselves do not hold a string
these patterns match. Run from the repository root: `python3 ci/scan_secrets.py`.
"""
import pathlib
import re
import sys

PATTERNS = [
    r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})",
    r"\bsk-ant-[A-Za-z0-9_-]{20,}",
    r"\bsk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}",
    r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
    r"\bxox[abposr]-[A-Za-z0-9-]{10,}",
    r"\b[rs]k_live_[A-Za-z0-9]{20,}",
    r"\bAIza[A-Za-z0-9_-]{35}\b",
    r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----",
]
CHUNK = 1 << 20
OVERLAP = 4096


def matches(path):
    # Read in chunks with an overlap, so a key that straddles a chunk boundary is still found and a
    # large file is not read into memory at once.
    try:
        with path.open("rb") as fh:
            tail = ""
            while True:
                chunk = fh.read(CHUNK)
                if not chunk:
                    return False
                text = tail + chunk.decode("utf-8", "ignore")
                if any(re.search(rx, text) for rx in PATTERNS):
                    return True
                tail = text[-OVERLAP:]
    except OSError:
        return False


def main():
    hits = [str(p) for p in pathlib.Path(".").rglob("*")
            if p.is_file() and ".git" not in p.parts
            and p.suffix not in {".png", ".jpg", ".pyc"}
            and "__pycache__" not in p.parts
            and matches(p)]
    print("\n".join(hits) or "clean")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
