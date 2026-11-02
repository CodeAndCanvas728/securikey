"""Find and redact secrets in text. Results name what was found; they never contain a secret value.

Two detectors:
- known values: exact matches of stored secrets (plus their base64 and URL-encoded forms), no false positives;
- patterns: high-confidence formats of common provider tokens, for secrets that were never stored.
"""
import base64
import re
import urllib.parse

MIN_SECRET_LEN = 8  # shorter stored values would redact ordinary words

# A PEM private key, whole. The header is matched and then everything up to
# the END line is consumed, because the body is the key and anyone can put it
# under a standard header. The body may span lines, may be JSON-escaped, may
# carry RFC 1423 pre-headers, and may end mid-line, so it is not matched
# shape by shape: a header means everything after it is redacted.
# The header is whole words, then the literal (RSA, EC, OPENSSH, SSH2 ENCRYPTED, PGP ... BLOCK). A character
# class that could also match the literal made a long run of "PRIVATE KEY " quadratic.
# Runs of spaces are their own token (` +`), never part of a class that can also match a word, so extra
# spaces are tolerated and the match stays linear.
PEM_HEADER = r"(?:[A-Z0-9]+ +)*PRIVATE +KEY(?: +BLOCK)? *-----"
PEM_RE = r"-----BEGIN +" + PEM_HEADER + r"[\s\S]*?(?:-----END +" + PEM_HEADER + r"|$)"

PATTERNS = {
    "github": r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})",
    "anthropic": r"\bsk-ant-[A-Za-z0-9_-]{20,}",
    # Not after a letter, digit, underscore or hyphen: `task-sk-update-the-…` is a branch name, not a key.
    "openai": r"(?<![A-Za-z0-9_-])sk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}",
    "aws_access_key": r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
    "slack": r"\bxox[abposr]-[A-Za-z0-9-]{10,}",
    "stripe": r"\b[rs]k_live_[A-Za-z0-9]{20,}",
    "google_api_key": r"\bAIza[A-Za-z0-9_-]{35}\b",
    "jwt": r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    # The whole PEM block, not just the header: the body is the key, and
    # anyone can prepend a standard header to it.
    "private_key": PEM_RE,
}
_COMPILED = {kind: re.compile(rx) for kind, rx in PATTERNS.items()}


def _variants(value):
    if not isinstance(value, str):
        # A stored value that is not a string cannot be matched, and must not
        # raise: a corrupt map must not take the hook down.
        return []
    forms = {value, base64.b64encode(value.encode()).decode(), urllib.parse.quote(value, safe="")}
    return [f for f in forms if len(f) >= MIN_SECRET_LEN]


# The characters that are rare in ordinary text, rarest first. A form's signature is the
# rarest character it holds, so a text without that character cannot hold the form.
_RARITY = "~^`\\|&{}[]<>$%*#@!?+=:;/,-_."


def _signature(form):
    """The character a text must hold for the form to be in it.

    A form that is a substring of a text has all of its characters in that text, so this
    never rules out a real hit: it only lets most texts be ruled out with one lookup.
    """
    for char in _RARITY:
        if char in form:
            return char
    for char in form:
        if char.isdigit():
            return char
    for char in form:
        if char.isupper():
            return char
    return form[0]


class KnownForms(list):
    """[(form, name)] for every stored secret, longest first, with the signature of each form.

    A list of pairs, so it is used like the list of pairs it was before. The signatures are
    what makes a hook call cheap: a form can only be in a text that holds its signature
    character, so the forms that can't be in the payload are dropped once, and the rest are
    the only ones searched for.
    """

    def __init__(self, pairs):
        super().__init__((form, name) for form, name, _ in pairs)
        self.signatures = {form: signature for form, _, signature in pairs}

    def in_text(self, text):
        """The pairs whose form can be in text: the ones whose signature character is in it.

        A form that is in the text has all of its characters there, so this never drops a
        form that could match. The text is scanned once per signature character, not once
        per form.
        """
        if not self:
            return []
        present = {signature for signature in self.signatures.values() if signature in text}
        return [pair for pair in self if self.signatures[pair[0]] in present]


def known_forms(secrets):
    """The forms of every stored secret, longest first.

    A secret that contains another is replaced whole, so the longest form has
    to come first. Build this once per hook invocation: rebuilding it for
    every string in a tool input or output is what made the hooks slow on a
    large payload.
    """
    pairs = [(form, name, _signature(form)) for name, value in secrets.items()
             if isinstance(value, str) and len(value) >= MIN_SECRET_LEN
             for form in _variants(value)]
    return KnownForms(sorted(pairs, key=lambda p: -len(p[0])))


NO_KNOWN = known_forms({})  # nothing is stored, so there is nothing to match


def find(text, secrets=None, known=None):
    """Sorted labels of everything secret in text: stored secret names and pattern kinds.

    known: the pairs from known_forms(), when the caller already has them.
    """
    pairs = known if known is not None else known_forms(secrets or {})
    labels = {name for form, name in pairs if form in text}
    labels |= {kind for kind, rx in _COMPILED.items() if rx.search(text)}
    return sorted(labels)


def redact(text, secrets=None, known=None):
    """(redacted text, labels). Stored values become [securikey:NAME]; pattern hits [redacted:KIND]."""
    pairs = known if known is not None else known_forms(secrets or {})
    labels = set()
    for form, name in pairs:
        if form in text:
            text = text.replace(form, "[securikey:%s]" % name)
            labels.add(name)
    for kind, rx in _COMPILED.items():
        text, n = rx.subn("[redacted:%s]" % kind, text)
        if n:
            labels.add(kind)
    return text, sorted(labels)


def redact_obj(obj, secrets=None, known=None):
    """Redact every string inside a JSON-like value, keeping its shape. Returns (value, labels)."""
    if isinstance(obj, str):
        return redact(obj, secrets, known)
    labels = set()
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            # A key can carry a secret too: a parsed dotenv or an MCP map is
            # keyed by content.
            new_key, found = redact(k, secrets, known)
            labels.update(found)
            # Two keys that redact to the same marker must not collide, or one
            # value would be dropped from the response.
            if new_key in out:
                suffix = 2
                while "%s#%d" % (new_key, suffix) in out:
                    suffix += 1
                new_key = "%s#%d" % (new_key, suffix)
            out[new_key], found = redact_obj(v, secrets, known)
            labels.update(found)
        return out, sorted(labels)
    if isinstance(obj, list):
        out = []
        for v in obj:
            item, found = redact_obj(v, secrets, known)
            labels.update(found)
            out.append(item)
        return out, sorted(labels)
    return obj, []
