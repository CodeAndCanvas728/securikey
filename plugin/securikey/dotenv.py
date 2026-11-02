"""Reading dotenv files: parsing, folding, and deciding what looks like a secret.

Shared by the CLI and the hook, so both agree on what a dotenv file says.
"""
import re

from securikey.redact import NO_KNOWN, find

REF_PREFIX = "securikey:"
LEGACY_REF_PREFIX = "token_vault:"  # the name before 3.0.0: still resolved, never written


_REF_RE = re.compile(r"^(%s|%s)([a-z][a-z0-9_]{0,63})$" % (re.escape(REF_PREFIX), re.escape(LEGACY_REF_PREFIX)))


def parse_ref(value):
    """(name, is_legacy) for a reference to a stored name, else None.

    The whole value has to be a prefix and a valid name: `securikey:` followed by anything
    else is a plaintext value, and is treated as one rather than echoed in an error.
    """
    match = _REF_RE.match(value)
    return (match.group(2), match.group(1) == LEGACY_REF_PREFIX) if match else None


def is_ref(value):
    """Whether a value is a reference to a stored name rather than a value."""
    return parse_ref(value) is not None
LINE_RE = re.compile(r"^(\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_]*)(\s*=\s*)(.*)$")
# A key that names a secret. The lookarounds keep a word inside a longer name
# from matching: PASSPORT is not a password, AUTHOR is not an auth token.
SECRET_KEY_RE = re.compile(
    r"(?<![A-Za-z0-9])(KEY|TOKEN|SECRET|PASSWORD|PASSWD|PASS|PRIVATE|CREDENTIAL|AUTH|DSN)"
    r"(?![A-Za-z0-9])", re.I)
ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\", '"': '"', "'": "'", "0": "\0"}


def _unescape(value):
    """Decode the escapes a double-quoted value carries."""
    out = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 1 < len(value) and value[index + 1] in ESCAPES:
            out.append(ESCAPES[value[index + 1]])
            index += 2
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _scan_quote(raw, quote, start):
    """(end, resume): the closing quote's index or -1, and where a scan of raw
    with more text appended should resume. Resuming keeps a multi-line value
    linear: each byte is scanned once, with the same escape handling."""
    index = start
    while index < len(raw):
        char = raw[index]
        if char == "\\" and quote == '"':
            index += 2
            continue
        if char == quote:
            return index, index
        index += 1
    return -1, index


def _closing_quote(raw, quote):
    """The index of the closing quote, honouring backslash escapes.

    -1 when the quote is never closed.
    """
    return _scan_quote(raw, quote, 1)[0]


LINE_DOTALL_RE = re.compile(LINE_RE.pattern, re.DOTALL)  # a quoted value may span lines


def raw_quoted_value(source):
    """A quoted value as written in the file (escapes not decoded), or None if it isn't quoted."""
    match = LINE_DOTALL_RE.match(source.strip())
    raw = match.group(4).strip() if match else ""
    if raw[:1] not in ("'", '"'):
        return None
    end = _closing_quote(raw, raw[0])
    return raw[1:end] if end != -1 else raw[1:]


def _split_value(raw):
    """(value, comment) for a raw dotenv value.

    A quoted value may span lines, so `raw` is the whole value including any
    continuation lines. Returns (None, None) when a quote is never closed,
    because then the value is not knowable and the file must not be touched.
    """
    raw = raw.strip()
    if raw[:1] in ("'", '"'):
        quote = raw[0]
        end = _closing_quote(raw, quote)
        if end == -1:
            return None, None
        value = raw[1:end]
        if quote == '"':
            value = _unescape(value)
        return value, raw[end + 1:].strip()
    # An unquoted value ends at a # that starts a word.
    match = re.search(r"(?:^|\s)#", raw)
    if match:
        return raw[:match.start()].strip(), raw[match.start():].strip()
    return raw, ""


def parse_dotenv(text):
    """Parse a dotenv file into records.

    Each record is (source, prefix, key, sep, value, comment): `source` is the
    text the record came from, and key is None for a line that is not an
    assignment. A quoted value that spans lines is folded into one value.

    Returns (records, None), or (None, message) when a quoted value is never
    closed. Such a file must not be rewritten: half of it would keep the
    value in plaintext while the file claimed to hold names only.
    """
    lines = text.splitlines()
    records = []
    index = 0
    while index < len(lines):
        start = index
        line = lines[index]
        index += 1
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            records.append((line, None, None, None, None, None))
            continue
        match = LINE_RE.match(stripped)
        if not match:
            records.append((line, None, None, None, None, None))
            continue
        prefix, key, sep, raw = match.group(1), match.group(2), match.group(3), match.group(4)
        raw = raw.strip()
        quote = raw[:1]
        end, resume = _scan_quote(raw, quote, 1) if quote in ("'", '"') else (0, 0)
        if end == -1:
            # The value continues on the next lines. The same escape-aware
            # scanner decides, so a value whose first line carries an escaped
            # quote is not mistaken for a closed one; it resumes where it
            # stopped, so an unclosed quote costs one pass, not one per line.
            while index < len(lines):
                raw += "\n" + lines[index]
                index += 1
                end, resume = _scan_quote(raw, quote, resume)
                if end != -1:
                    break
            else:
                return None, "a quoted value is never closed"
        value, comment = _split_value(raw)
        if value is None:
            return None, "a quoted value is never closed"
        source = "\n".join(lines[start:index])
        records.append((source, prefix, key, sep, value, comment))
    return records, None


def secret_like(key, value, import_all=False):
    """Whether a value in a dotenv file should be treated as a secret."""
    if not value or is_ref(value):
        return False
    return import_all or bool(SECRET_KEY_RE.search(key)) or bool(find(value, known=NO_KNOWN))
