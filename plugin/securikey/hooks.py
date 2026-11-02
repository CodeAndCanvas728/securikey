"""Claude Code hook handlers. Each takes the hook's input event and returns the JSON to print (or None).

- PreToolUse: deny tool calls whose input carries a secret, and plain reads of .env files.
- PostToolUse: replace tool output containing secrets with a redacted copy before Claude sees it.
  Values in the project's own .env files count as secrets, however the file was read.
- UserPromptSubmit: block prompts that contain a secret.
Messages name what was found (secret names, token kinds); they never contain a value.
"""
import heapq
import os
import re
import stat
import sys
from pathlib import Path

from securikey import dotenv
from securikey.redact import MIN_SECRET_LEN, find, known_forms, redact_obj
from securikey.store import VaultError, is_headless

# `.env`, `.envrc`, `.env.local`, `.env-prod`, `.env_local`, and a named environment in front of the
# extension (`prod.env`, `secrets.env`). The prefixed form is a short list, not any word: `process.env` is code.
ENV_FILE_RE = re.compile(
    r"(?:^|[\s/\"'=<:*$(){},])"
    r"(\.env(?:rc)?(?:[._-][A-Za-z0-9*]+)*"  # `_` and `-` only separate: a body class holding them is exponential
    r"|(?:prod(?:uction)?|dev(?:elopment)?|stag(?:e|ing)|test|local|live|secrets?|credentials?)\.env)"
    r"(?=$|[\s\"';|&)>*?$(),=])", re.IGNORECASE)
# An example file, also as a suffix (`.env.local.example`), the same rule the scan script uses.
SAFE_ENV_RE = re.compile(r"(?:[A-Za-z0-9_-]+)?\.env(?:rc)?(?:[._-][A-Za-z0-9]+)*\.(?:example|sample|template|dist)\b",
                         re.IGNORECASE)
# The names the content scan reads: `.env` and anything after a dot. A name the plain .env
# pattern doesn't cover (`.env.prod~`) still holds secrets, so it is read too.
DOTENV_NAME_RE = re.compile(r"^(?:\.env(?:rc)?(?:[._-][^\s/\\]+)?|[^\s/\\]+\.env)$", re.IGNORECASE)
METADATA_COMMANDS = {"ls", "test", "["}  # touch .env without printing its values
# `ls --from-file=.env` prints the names in the file, so ls is only metadata
# without it.
LS_READS_A_FILE = "--from-file"
# git prints file contents, so it is gated on the subcommand, not on the name.
GIT_METADATA = {"status", "ls-files", "check-ignore", "rev-parse"}
# skey is gated the same way: `skey run -- <command>` runs a command, and that
# command is checked as one.
TV_METADATA = {"import", "add", "rm", "list", "warm", "patterns", "doctor", "migrate"}
# Subcommands that send values to a server whose address the command line can set
# (the Paperclip URL variable set inline, then `skey sync`): the person runs them, not the agent.
HUMAN_ONLY = {"sync", "rotate"}
MAX_BRACE_SCAN_CHARS = 16384
MAX_BRACE_PASSES = 64  # brace nesting the gate expands; deeper is denied
# skey's own options, and the value each one takes.
TV_RUN_OPTIONS = {"--env": 1, "--dotenv": 1, "--env-from-paperclip": 1}
# A command that changes the directory, so a relative path is not resolvable.
CHANGES_DIRECTORY = {"cd", "pushd"}
MAX_NESTED = 3  # how deep `skey run -- skey run -- ...` is followed
MAX_DOTENV_BYTES = 1 << 20  # a dotenv file bigger than this is not read
# A shell substitution runs another command.
SUBSTITUTION_RE = re.compile(r"\$\(([^()]*)\)|`([^`]*)`|<\(([^()]*)\)")
# The fields that carry a file path, per tool. A Grep's `pattern` is a regex,
# not a path, so it is not one of them.
PATH_FIELDS = {
    "Read": ("file_path",),
    "Grep": ("path", "glob"),
    "Glob": ("pattern",),
    "Edit": ("file_path", "path"),
    "Write": ("file_path", "path"),
    "MultiEdit": ("file_path", "path"),
    "NotebookEdit": ("notebook_path", "path"),
}


def _strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)


def _env_names(text):
    r"""The .env file names written out in text, in any case (macOS names are case-insensitive),
    also with plain quoting removed (`.'env'`, `\.env`).

    A best-effort name check that gives a clear message. The shell has more ways to
    spell a name than a parser can follow (globs, braces, `$(…)`), so the guarantee is
    on the output side: values from the project's .env files are redacted wherever they
    show up (see project_dotenv_secrets).
    """
    plain = re.sub(r"[\\'\"]", "", text)
    names = []
    for src in dict.fromkeys((text, plain)):
        names += [m.group(1) for m in ENV_FILE_RE.finditer(src) if m.group(1) not in names]
    return names


# .env files are found by walking the session's directory: deep enough for app/.env.local,
# bounded so a hook stays fast in a big tree.
DOTENV_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".build", "target", "vendor"}
# Exact, lowercase names only: a case variant (`.ENV.LOCAL`) is an ordinary name, so it can't tie with these.
DOTENV_COMMON_NAMES = frozenset(
    [".env"] + [".env.%s%s" % (env, local) for env in ("local", "development", "production", "staging", "test")
                for local in ("", ".local")])
DOTENV_MAX_DEPTH = 4
DOTENV_MAX_FILES = 50  # files read per hook call
DOTENV_MAX_DIRS = 1000  # a repo walks in 1-10 ms; this bounds a session started in ~ to about 0.2 s
DOTENV_MAX_TOTAL_BYTES = 4 << 20  # read per hook call: bounds the parse, which the walk limits don't
DOTENV_MAX_SECRETS = 500  # values registered per hook call: bounds the forms the hook builds and scans
MAX_SHOWN_PROBLEMS = 5  # dotenv problems named in the warning; the rest are counted
DOTENV_MAX_LINES = 1000  # lines parsed per file: bounds the parse, which the byte limit doesn't


def _dotenv_files(root, problems):
    """The .env files under root. What the walk can't cover goes to problems: a folder it
    can't list, and anything past the folder or file limit."""
    root, found, seen = Path(root), [], 0
    unlisted = []
    # Shallowest first, and the names that hold real secrets before any other name, so a file or
    # byte limit drops the deepest, oddly named files, and decoys named `.env.a01` can't push
    # `.env.local` out. A name only lowers the file's rank, never skips it.
    for count, (dirpath, dirnames, filenames) in enumerate(os.walk(root, onerror=unlisted.append)):
        if count >= DOTENV_MAX_DIRS:
            problems.append("the search stopped after %d folders, so deeper .env files were not read" % DOTENV_MAX_DIRS)
            break
        depth = len(Path(dirpath).relative_to(root).parts)
        dirnames[:] = [d for d in dirnames if d not in DOTENV_SKIP_DIRS and depth < DOTENV_MAX_DEPTH]
        names = [name for name in filenames if DOTENV_NAME_RE.match(name) and not SAFE_ENV_RE.fullmatch(name)]
        seen += len(names)
        # Only the best-ranked files are kept as the walk goes, so the list can't grow with the tree.
        found = heapq.nsmallest(
            DOTENV_MAX_FILES,
            found + [((depth, name not in DOTENV_COMMON_NAMES, str(Path(dirpath) / name)), Path(dirpath) / name)
                     for name in names])
    if unlisted:
        problems.append("%d folder(s) could not be listed" % len(unlisted))
    if seen > DOTENV_MAX_FILES:
        problems.append("only the first %d of %d .env files were read" % (DOTENV_MAX_FILES, seen))
    return [path for _, path in found]


def _read_regular(path, limit, identity=None):
    """(data, problem) for a regular file.

    data: the file's bytes, at most limit + 1 of them, so a file longer than the limit
    shows up as one byte over it. problem: None, "is not a regular file",
    "can't be read (ErrorName)" or "changed while it was being read".

    The file is opened once and judged on the open descriptor: a stat followed by an open
    leaves a window in which a background process can swap the file for a FIFO or a device,
    and reading that would block the hook until its timeout. O_NONBLOCK keeps even the open
    of a FIFO from waiting for a writer. When identity is given, the descriptor has to be
    the file that was stat'd, and a link in the final name is not followed (O_NOFOLLOW): the
    caller passes the resolved name. A folder swapped for a link between that resolve and the
    open is still a window; its cost is a value redacted that should not have been.

    Every error is a problem, not a failure: a file that can't be read is reported to the
    user, because a file in a cloned repo must not be able to stop the session.
    """
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    if identity is not None:
        flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(path), flags)
    except OSError as exc:
        return None, "can't be read (%s)" % type(exc).__name__
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return None, "is not a regular file"
        if identity is not None and (info.st_dev, info.st_ino) != identity:
            return None, "changed while it was being read"
        chunks, total = [], 0
        while total <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks), None
    except OSError as exc:
        return None, "can't be read (%s)" % type(exc).__name__
    finally:
        try:
            os.close(fd)
        except OSError:
            pass  # the descriptor is gone either way


def _read_dotenv(path, problems, limit, identity=None, label=None):
    """(text, nbytes, cut) for the file, or (None, 0, False) if it can't be read.

    At most limit bytes are read. cut says the file was longer than that, so the caller
    can report a limit that was hit.
    """
    data, problem = _read_regular(path, limit, identity)
    if problem:
        problems.append("%s %s" % (label or path.name, problem))
        return None, 0, False
    cut = len(data) > limit
    return data[:limit].decode("utf-8", errors="replace"), min(len(data), limit), cut


def _dotenv_pairs(text):
    """(key, value, raw) for each assignment. A file the parser rejects (an unclosed quote)
    is read line by line instead of dropped whole."""
    records, _ = dotenv.parse_dotenv(text)
    if records is not None:
        for source, _, key, _, value, _ in records:
            if key:
                yield key, value, dotenv.raw_quoted_value(source)  # the model reads the raw form
        return
    for line in text.splitlines():
        match = dotenv.LINE_RE.match(line.strip())
        if match:
            value = match.group(4).strip().strip("'\"")
            yield match.group(2), value, None


# What counts as a secret in a .env file. Stricter than `skey import`'s rule (which the user
# reviews with --dry-run), because here a false positive redacts ordinary output and blocks
# prompts: a known token format, the password of a credential URL, or a value under a
# secret-sounding key that is shaped like a secret.
# The password of a credential URL. RFC 3986 keeps `/`, `?` and `#` out of the userinfo,
# so they end the password: `postgres://replica:6333/db@host` has no password, it has a
# port and a path.
_CRED_URL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://[^:/@\s]*:([^@/\s?#]+)@")
_URL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
# Passwords that pass the shape gate but are the placeholders every tutorial uses. A value
# under a key that says PASSWORD is the user's own word for it; a password guessed out of a
# URL under a key that says URL is the hook's guess, so the obvious placeholders don't count.
_PLACEHOLDER_PASSWORDS = frozenset([
    "password", "passwd", "passw0rd", "p@ssword", "p@ssw0rd", "password1", "password123",
    "changeme", "change_me", "changeit", "admin123", "administrator", "letmein", "welcome1",
    "qwerty123", "secret123", "test1234", "example123", "notarealpassword", "yourpassword",
])
# A path has at least two segments (/api/v1/callback, ./certs/dev, ~/keys/x). A single `/`-led
# token is not a path: about 1 in 64 base64 secrets starts with `/`.
_PATH_RE = re.compile(r"^(?:\.{0,2}/|~/)[^/\s]+/[^/\s]+")  # a trailing slash alone doesn't make a path
_PLAIN_RE = re.compile(r"^(?:[a-z]+(?:[-_.][a-z0-9]+)*|[\d.]+|[A-Za-z0-9.-]+:\d+(?:/\S*)?)$")


def _shaped_like_a_secret(value):
    """Whether the value looks like a secret rather than an ordinary word.

    A digit, or mixed case. `my_secret_value` and other lowercase identifiers are not;
    a lowercase-only passphrase is a stated limit.
    """
    mixed_case = any(c.islower() for c in value) and any(c.isupper() for c in value)
    return any(c.isdigit() for c in value) or mixed_case


def _secret_parts(key, value):
    # Whitespace at either end is padding (`KEY=" abc "`, a trailing space): judge and register the
    # value without it. Whitespace inside is still "not a secret": a phrase, not a token.
    value = value.strip() if isinstance(value, str) else value
    if not value or dotenv.is_ref(value):
        return []
    credential = _CRED_URL_RE.match(value)
    if credential:
        # The password of a credential URL is judged like any other value: `password` and
        # `changeme` are words, and registering a word would deny every call that mentions
        # it (a file about a password field, a prompt about changing a password). The
        # pattern keeps `/` and whitespace out of the password, so only the word, the
        # placeholder and the shape are left to judge.
        password = credential.group(1)
        if _PLAIN_RE.match(password) or password.lower() in _PLACEHOLDER_PASSWORDS:
            return []
        if not (_shaped_like_a_secret(password) or find(password, known=dotenv.NO_KNOWN)):
            return []
        return [password]
    if find(value, known=dotenv.NO_KNOWN):
        return [value]
    if _URL_RE.match(value) or _PATH_RE.match(value) or _PLAIN_RE.match(value) or any(c.isspace() for c in value):
        return []
    if not dotenv.SECRET_KEY_RE.search(key):
        return []
    return [value] if _shaped_like_a_secret(value) else []


def _budget_problem(read):
    """The warning for a call that read only part of the project's dotenv files."""
    if read < 1024:
        return "only the first %d bytes of the project's dotenv files were read" % read
    return "only the first %d KB of the project's dotenv files were read" % (read >> 10)


def _identity(path):
    """(device, inode) of the path itself (no link followed), or None if it can't be stat'd."""
    try:
        info = os.stat(str(path), follow_symlinks=False)
    except OSError:
        return None
    return info.st_dev, info.st_ino


def _resolve_inside(base, path):
    """The path with its links followed, if that is under base; otherwise None.

    The scan covers the files under the session's directory. A link that points out of it
    (`.env -> ~/.aws/credentials`) is not one of them, and reading it would widen the scan
    to files the session never asked about. The caller reads the resolved name, so the file
    that was judged is the file that is opened.
    """
    try:
        resolved = path.resolve()
    except OSError:
        return None
    return resolved if resolved == base or resolved.is_relative_to(base) else None


def _fair_shares(counts, cap):
    """How many values each file may register: the cap split evenly, and what a small file
    doesn't use is shared out among the bigger ones. No file can use the whole cap, so one
    file full of values can't crowd out the others."""
    shares, remaining = {}, cap
    for left, index in zip(range(len(counts), 0, -1), sorted(range(len(counts)), key=counts.__getitem__)):
        shares[index] = min(counts[index], remaining // left)
        remaining -= shares[index]
    return [shares[i] for i in range(len(counts))]


def _ranked_shares(usual, counts, cap):
    """_fair_shares in two tiers. The files with an unusual name share at most a quarter of
    the cap, however little the usual names ask for: that is the ceiling for decoys named
    `.env.a01`, and the floor that keeps many usual names from starving `.env.prod`. The files
    with a usual name (`.env`, `.env.local`…) share the rest. Not protected: a usual name
    against another usual name. Files named `.env.local` in many subfolders share their tier
    evenly, so they can dilute a root `.env` (the warning names each file that was cut)."""
    shares = [0] * len(counts)
    remaining = cap
    for is_usual, limit in ((False, cap // 4), (True, cap)):
        members = [i for i, usual_name in enumerate(usual) if usual_name == is_usual]
        extra = _fair_shares([counts[i] for i in members], min(limit, remaining))
        for index, share in zip(members, extra):
            shares[index] = share
        remaining -= sum(extra)
    return shares


def project_dotenv_secrets(event):
    """({"dotenv:KEY": secret}, problems) for the .env files under the session's directory.

    The hook reads them; the model never does. With the secrets in the known set, a value
    is redacted (or a call carrying it denied) whichever command or glob read the file.
    `problems` lists what could not be checked (a file too big, not a regular file, a link
    out of the directory, the walk limit, too many values); the caller shows it to the user
    instead of failing silently. It does not block: a file in a cloned repo must not be able
    to stop the session.
    """
    cwd = event.get("cwd")
    out, problems = {}, []
    if not cwd or not os.path.isdir(cwd):
        problems.append("the session has no readable working directory, so no .env file was searched")
        return out, problems
    try:
        base = Path(cwd).resolve()
    except OSError:
        problems.append("the session's working directory can't be resolved, so no .env file was searched")
        return out, problems
    total = 0
    parsed = []  # (file name, [(key, secret)], has a usual name) in rank order
    for path in _dotenv_files(cwd, problems):
        # The per-file limit and what is left of the call's budget: the file is read within
        # the smaller of the two, so a call can't overshoot its budget by a whole file.
        limit = min(MAX_DOTENV_BYTES, DOTENV_MAX_TOTAL_BYTES - total)
        if limit <= 0:
            problems.append(_budget_problem(total))
            break
        resolved = _resolve_inside(base, path)
        if resolved is None:
            problems.append("%s is a link out of the session's directory, so it was not read" % path.name)
            continue
        # The file that is opened has to be the file that was judged: the resolved name is
        # read, and the descriptor must match the stat of that same name. No identity is
        # no verification, so the file is skipped.
        identity = _identity(resolved)
        if identity is None:
            problems.append("%s can't be read (it can't be inspected)" % path.name)
            continue
        text, nbytes, cut = _read_dotenv(resolved, problems, limit, identity, label=path.name)
        if text is None:
            continue
        total += nbytes
        lines = text.splitlines()  # the splitter the parser uses: `\r` and the like end a line too
        if len(lines) > DOTENV_MAX_LINES:
            # A file of `A=1` is a million records in 4 MB: the parse is bounded by lines.
            text = "\n".join(lines[:DOTENV_MAX_LINES])
            problems.append("%s has over %d lines, only its start was read" % (path.name, DOTENV_MAX_LINES))
        found = []
        for key, value, raw in _dotenv_pairs(text):
            for secret in dict.fromkeys(s for v in (value, raw) if v for s in _secret_parts(key, v)):
                if len(secret) >= MIN_SECRET_LEN:
                    found.append((key, secret))
        parsed.append((path.name, found, path.name in DOTENV_COMMON_NAMES))
        if cut:
            # The file was longer than what was read: say which limit was hit. The budget
            # stops the scan, the per-file limit doesn't.
            if limit == MAX_DOTENV_BYTES:
                problems.append("%s is over %d KB, only its start was read" % (path.name, MAX_DOTENV_BYTES >> 10))
            else:
                problems.append(_budget_problem(total))
                break
    # A few hundred values are what a project has; hundreds of thousands would blow the
    # hook's timeout on the forms built from them. The cap is shared out between the files,
    # usual names first, so a planted file full of values can't switch off the check for the user's own.
    shares = _ranked_shares([usual for _, _, usual in parsed], [len(found) for _, found, _ in parsed],
                            DOTENV_MAX_SECRETS)
    for (file_name, found, _), share in zip(parsed, shares):
        if share < len(found):
            problems.append("only %d of %d secrets from %s were checked" % (share, len(found), file_name))
        for key, secret in found[:share]:
            name, n = "dotenv:" + key, 2
            while name in out and out[name] != secret:  # same key, another file or form
                name, n = "dotenv:%s#%d" % (key, n), n + 1
            out[name] = secret
    return out, problems


def _words(segment):
    """The words of a command, without the leading VAR=value assignments.

    An assignment whose value names a .env file is kept, because
    `ENV_FILE=.env && cat $ENV_FILE` does name the file.
    """
    words = []
    for word in segment.strip().split():
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", word) and not _env_names(word.partition("=")[2]):
            continue
        words.append(word)
    return words


def _substitution_bodies(text):
    """The text inside each $(...) or `...` in the text."""
    bodies = []
    index = 0
    while index < len(text):
        if text.startswith("$(", index) or text.startswith("<(", index):
            end = _matching_paren(text, index + 1)
            if end == -1:
                bodies.append(text[index + 2:])
                break
            bodies.append(text[index + 2:end])
            index = end + 1
            continue
        if text[index] == "`":
            end = text.find("`", index + 1)
            if end == -1:
                bodies.append(text[index + 1:])
                break
            bodies.append(text[index + 1:end])
            index = end + 1
            continue
        index += 1
    return bodies


def _matching_paren(text, start):
    """The index of the ) that closes the ( at start - 1, or -1."""
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "(":
            depth += 1
        elif text[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _substitutions(segment, depth=0):
    """The commands a shell substitution in the segment would run.

    A substitution can hold another one, so the body is scanned again.
    """
    out = []
    for body in _substitution_bodies(segment):
        out.append(body)
        if depth < MAX_NESTED:
            out.extend(_substitutions(body, depth + 1))
    return out


def _has_substitution(segment):
    """Whether the segment expands something at runtime."""
    return any(token in segment for token in ("$(", "`", "${", "<(", ">("))


def _tv_run_command(words):
    """(command, dotenv files) for a `skey run`, from the words after `skey run`.

    The separator is optional in the CLI, so `skey run cat .env` and
    `skey run -- cat .env` both run `cat .env`.
    """
    index = 0
    command, dotenvs = [], []
    while index < len(words):
        word = words[index]
        if word == "--":
            command = words[index + 1:]
            break
        if word == "--dotenv":
            if index + 1 < len(words):
                dotenvs.append(words[index + 1])
            index += 2
            continue
        if word.startswith("--dotenv="):
            dotenvs.append(word.partition("=")[2])
            index += 1
            continue
        if word in ("--env", "--env-from-paperclip"):
            index += 2
            continue
        if word.startswith(("--env=", "--env-from-paperclip=")):
            index += 1
            continue
        command = words[index:]
        break
    return command, dotenvs


def _dotenv_is_imported(path, cwd, uncertain_cwd=False):
    """Whether every value in the file is empty or a securikey: reference.

    A file that still holds a plaintext value would put it into the child's
    environment, where no command can be trusted to keep it out of the
    transcript. The check is structural, not heuristic: a value the plugin did
    not recognise — a connection string with a password in it, say — is
    exactly the one that would leak.
    """
    target = Path(path)
    if not target.is_absolute():
        if uncertain_cwd:
            # The command changes directory, so a relative path is not
            # resolvable here.
            return False
        if cwd:
            target = Path(cwd) / target
    try:
        # Only a regular file is read, and it is judged on the open descriptor: a stat
        # followed by an open can be raced (a FIFO swapped in between), and reading that
        # would block the hook until its timeout.
        data, problem = _read_regular(target, MAX_DOTENV_BYTES)
        if problem or len(data) > MAX_DOTENV_BYTES:
            return False
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    records, error = dotenv.parse_dotenv(text)
    if error is not None:
        return False
    for source, prefix, key, sep, value, comment in records:
        if key is None or not value:
            continue
        if not dotenv.is_ref(value):
            return False
    return True


def _is_metadata(segment, depth=0, cwd=None, uncertain_cwd=False):
    """Whether the command only touches metadata, never the contents of a file.

    `git show HEAD:.env` prints the file, so git is allowed only for the
    subcommands that report names and hashes. `skey run` executes a command, so
    that command is checked as one.
    """
    words = _words(segment)
    if not words:
        # Nothing to run. A name that was seen is still a name.
        return not _env_names(segment)
    command = words[0].rsplit("/", 1)[-1]
    if command == "git":
        sub = words[1].rsplit("/", 1)[-1] if len(words) > 1 else ""
        return sub in GIT_METADATA
    if command == "skey":
        sub = words[1].rsplit("/", 1)[-1] if len(words) > 1 else ""
        if sub in TV_METADATA:
            return True
        if sub == "run":
            inner, dotenvs = _tv_run_command(words[2:])
            if depth < MAX_NESTED:
                return not _reads_env_file("Bash", {"command": " ".join(inner)}, depth + 1, cwd)
        return False
    if command == "ls":
        # `ls --from-file=.env` prints the names in the file.
        return not any(word.startswith(LS_READS_A_FILE) for word in words)
    return command in METADATA_COMMANDS


def _unquoted(word):
    """The word as the shell reads it after quote removal: `s''key`, `"skey"` and `s\\key` are all skey."""
    return re.sub(r"[\"'\\]", "", word)


def _runs_human_only(command):
    """Whether a Bash command runs `skey sync` or `skey rotate`.

    Also when nested (`skey run -- skey sync`, `bash -c "skey sync"`, `$(skey sync)`), run by path, glued to
    a separator (`true &skey rotate k`, `{ skey sync; }`), written with shell quoting (`s''key`), or
    reached through an expansion that can produce the name (`$S sync`, `s*y sync`). No command is exempt:
    a text-only command can still run code (`git -c alias.x='!skey sync'`), so a commit message that
    mentions `skey sync` is denied too. This is one layer; the commands also refuse to run without a
    terminal (cli.require_terminal), because a pattern match on shell text is never complete.
    """
    if not isinstance(command, str):
        return False
    # The command as written; with each `$(...)` / backtick substitution replaced by a placeholder
    # (`$(echo skey) sync` has no `skey` next to `sync`, but `$SUB sync` is a word that can be anything);
    # and with brace lists and $IFS read as the shell does (`{skey,sync}`, `skey${IFS}sync`).
    flat = re.sub(r"\$\([^()]*\)|`[^`]*`", "$SUB", command)
    # Nested expansions such as `${IFS:-${X}}` are beyond a regex: fail closed when one appears next to a
    # name this gate guards.
    lowered = command.lower()
    if "${" in command and ("skey" in lowered or re.search(r"\b(?:%s)\b" % "|".join(HUMAN_ONLY), lowered)):
        return True
    braced = command
    if len(command) > MAX_BRACE_SCAN_CHARS:
        # The brace regex below is quadratic in an unclosed run of `{`. A command this long that names a
        # guarded word is not judged; one that does not cannot build the word from a brace list.
        if "skey" in lowered or re.search(r"\b(?:%s)\b" % "|".join(HUMAN_ONLY), lowered):
            return True
    else:
        for _ in range(MAX_BRACE_PASSES):  # innermost first: `{skey,{sync,x}}`; each pass removes a brace pair
            again = re.sub(r"\{([^{}]*,[^{}]*)\}", lambda m: m.group(1).replace(",", " "), braced)
            if again == braced:
                break
            braced = again
        else:
            return True  # nested deeper than any real command: not a fixed point, so not judged safe
    # Any parameter expansion (`${IFS}`, `${IFS:0:1}`, `${IFS%?}`, `$IFS`) becomes its own dynamic word, so
    # `skey${IFS:0:1}sync` reads as `skey $X sync`: a subcommand that is not known.
    spaced = re.sub(r"\$\{[^{}]*\}|\$IFS\b", " $X ", braced)
    for text in (command, flat, spaced):
        for segment in re.split(r"&&|\|\||[;|&\n(){}]", text):
            for part in [segment] + _substitutions(segment):
                words = [_unquoted(w.strip("`")) for w in _words(part)]
                for word, following in zip(words, words[1:]):
                    # What follows the last `=`, `!` or `:` is the program: `alias.x=!skey`, `--pre=skey`.
                    # Lower case: the default macOS filesystem is case-insensitive, so `SKEY sync` runs.
                    program = re.split(r"[=!:]", word)[-1].rsplit("/", 1)[-1].lower()
                    sub = following.rsplit("/", 1)[-1].lower()
                    dynamic_word = any(c in word for c in "$*?[`~")
                    dynamic_sub = any(c in sub for c in "$*?[`~")
                    if program == "skey" and (sub in HUMAN_ONLY or dynamic_sub):
                        return True  # `skey sync`, and `skey $X`: the subcommand is not known
                    if sub in HUMAN_ONLY and dynamic_word:
                        return True  # `$S sync`: the program is not known
    return False


def _is_tv_run(segment):
    """Whether the segment is a `skey run`."""
    words = _words(segment)
    if len(words) < 2:
        return False
    return words[0].rsplit("/", 1)[-1] == "skey" and words[1].rsplit("/", 1)[-1] == "run"


def _tv_run_dotenvs(segment):
    """The files a `skey run` injects into the child."""
    return _tv_run_command(_words(segment)[2:])[1]


def _reads_env_file(tool, tool_input, depth=0, cwd=None):
    if tool == "Bash":
        command = tool_input.get("command", "")
        if not isinstance(command, str):
            return False
        segments = re.split(r"&&|\|\||[;|\n]", command)
        # A command that changes directory makes a relative path
        # unresolvable, so the file it names cannot be checked.
        uncertain_cwd = any(_words(segment) and _words(segment)[0].rsplit("/", 1)[-1] in CHANGES_DIRECTORY
                            for segment in segments)
        for segment in segments:
            # A `skey run` is checked even when it names no .env: the file it
            # injects is the thing that matters, and its name can be anything.
            if _is_tv_run(segment):
                for path in _tv_run_dotenvs(segment):
                    # The values this run injects must be names, or no command
                    # can be trusted to keep them out of the transcript.
                    if not _dotenv_is_imported(path, cwd, uncertain_cwd):
                        return True
            # A shell substitution runs another command, so `ls $(cat .env)` is
            # a read of .env whatever the outer command is.
            for part in [segment] + _substitutions(segment):
                names = _env_names(part)
                if not names:
                    continue
                # Every name has to be safe. One safe name does not vouch for
                # the rest: `cat .env.example .env` reads both files.
                if all(SAFE_ENV_RE.fullmatch(name) for name in names):
                    continue
                if part is segment and not _has_substitution(segment) and _is_metadata(part, depth, cwd):
                    continue
                return True
        return False
    if tool in PATH_FIELDS:
        # Each field on its own, so a safe path in one field cannot cover an
        # unsafe path in another.
        for field in PATH_FIELDS[tool]:
            names = _env_names(str(tool_input.get(field, "")))
            if any(not SAFE_ENV_RE.fullmatch(name) for name in names):
                return True
        return False
    return False


WATCH_ENV = "SECURIKEY_WATCH_ENV"
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def watched_env_secrets(environ=None):
    """({"env:VAR": value}, problems) for the variables listed in SECURIKEY_WATCH_ENV.

    A host that injects secrets into the agent's environment (Paperclip) lists the variable
    names here; their values are then redacted and denied like stored ones, in every form
    redact.known_forms builds. `problems` are shown to the user as a warning. They name an entry
    by its position, never by its text: a secret pasted into the list by mistake would otherwise be
    printed on every hook call.
    """
    environ = os.environ if environ is None else environ
    out, problems = {}, []
    for index, name in enumerate((n.strip() for n in environ.get(WATCH_ENV, "").split(",")), 1):
        if not name:
            continue
        where = "entry %d of %s" % (index, WATCH_ENV)
        if not ENV_NAME_RE.match(name):
            problems.append("%s is not a valid variable name" % where)
            continue
        value = environ.get(name)
        if not value:
            problems.append("%s names a variable that is not set" % where)
        elif len(value) < MIN_SECRET_LEN:
            problems.append("%s names a variable shorter than %d characters, so it is not redacted"
                            % (where, MIN_SECRET_LEN))
        else:
            out["env:" + name] = value
    return out, problems


def _deny(reason):
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                   "permissionDecisionReason": reason}}


def _known_for(secrets, *payloads):
    """The known forms that can be in the payloads.

    A form can only be in a text that holds its signature character (see redact), so the
    payload is scanned once for those characters and the forms that can't be in it are
    dropped. A hook call then searches for the remaining forms only, not for every form:
    with many secrets and a large output, that is the difference between a scan per form
    and a scan per payload.
    """
    known = known_forms(secrets)
    if not known:
        return []
    text = "\n".join(s for payload in payloads for s in _strings(payload))
    return known.in_text(text)


def pre_tool_use(event, secrets):
    tool = event.get("tool_name", "")
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {}
    known = _known_for(secrets, tool_input)
    found = sorted({label for s in _strings(tool_input) for label in find(s, known=known)})
    if found:
        return _deny("securikey: this tool call contains a secret (%s). Refer to secrets by name and let "
                     "`skey run --env VAR=<name> -- <command>` inject them." % ", ".join(found))
    if tool == "Bash" and _runs_human_only(tool_input.get("command")):
        return _deny("securikey: `skey sync` and `skey rotate` send secret values to a server, and the "
                     "address can be set on the command line, so you run them in your own terminal, "
                     "not the agent.")
    if _reads_env_file(tool, tool_input, cwd=event.get("cwd")):
        return _deny("securikey: reading .env files puts secret values in the transcript. Run "
                     "`skey import <file>` once (values move to the keychain, the file keeps names), then "
                     "`skey run --dotenv <file> -- <command>`. .env.example files are allowed.")
    return None


def post_tool_use_failure(event, secrets):
    """A tool that failed. Claude Code runs PostToolUse only for a call that succeeds, and gives this event
    no way to replace the error text, so a secret in a failed call's output cannot be redacted, only
    noticed: stop the turn and say so. (A hook cannot make the call succeed either. Appending to a Bash
    command, or wrapping it, makes Claude Code's own permission check ask about the added part, and a
    `trap` is refused outright; tried and ruled out.)"""
    error = event.get("error")
    known = _known_for(secrets, error)
    found = sorted({label for s in _strings(error) for label in find(s, known=known)})
    if not found:
        return None
    return {"continue": False,
            "stopReason": "securikey: a failed %s call printed a secret (%s). Claude Code does not let a hook "
                          "redact a failed call's output, so the model has seen it: rotate it if it matters. "
                          "Run commands that handle secrets through `skey run`, which redacts its command's "
                          "output even when the command fails." % (event.get("tool_name") or "tool", ", ".join(found))}


def post_tool_use(event, secrets):
    response = event.get("tool_response")
    redacted, found = redact_obj(response, known=_known_for(secrets, response))
    if not found:
        return None
    return {"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": redacted,
                                   "additionalContext": "securikey redacted secrets from this output: %s."
                                                        % ", ".join(found)}}


def user_prompt_submit(event, secrets):
    prompt = event.get("prompt")
    if not isinstance(prompt, str):
        prompt = ""
    found = find(prompt, known=_known_for(secrets, prompt))
    if not found:
        return None
    return {"decision": "block",
            "reason": "securikey: your prompt contains a secret (%s), so it was not sent. Store it from your "
                      "own terminal with `skey add <name>` and refer to it by name." % ", ".join(found)}


HANDLERS = {"pre": pre_tool_use, "post": post_tool_use, "prompt": user_prompt_submit,
            "failure": post_tool_use_failure}


def _replace_output(tool_response, notice):
    """The tool output with everything in it replaced by a notice.

    The shape is kept, so Claude Code uses the replacement instead of the
    original. Used when the redaction itself failed: the raw output must not
    reach the model. Only a top-level string `type` survives: it names the
    output's shape, and a shape Claude Code doesn't recognise makes it fall back
    to the original output. (A secret put in that one field would pass; it is
    the tool's own shape field, not content.)
    """
    if isinstance(tool_response, dict):
        return {_kept_key(k, i, notice): (v if k == "type" and isinstance(v, str) else _replace_strings(v, notice))
                for i, (k, v) in enumerate(tool_response.items())}
    if isinstance(tool_response, list):
        return _replace_strings(tool_response, notice)
    return notice


# A key shaped like a field name (`stdout`, `filePath`, `content`) is kept, so the
# output keeps a shape Claude Code recognises. Anything else could be content (a
# secret used as a key) and is replaced. A key in a known token format is replaced
# too: it looks like a field name, but it is a value. Accepted limit: a short
# lowercase word used as a key still passes, and in this failure path nothing else
# catches it.
SHAPE_KEY_RE = re.compile(r"[a-z][A-Za-z0-9_]{0,63}")


def _kept_key(key, index, notice):
    if isinstance(key, str) and SHAPE_KEY_RE.fullmatch(key) and not find(key, known=dotenv.NO_KNOWN):
        return key
    return "%s #%d" % (notice, index)


def _replace_strings(value, notice):
    """Every string at any depth becomes the notice, keys included unless they look like
    field names; numbers, booleans and None stay."""
    if isinstance(value, dict):
        return {_kept_key(k, i, notice): _replace_strings(v, notice) for i, (k, v) in enumerate(value.items())}
    if isinstance(value, list):
        return [_replace_strings(v, notice) for v in value]
    return notice if isinstance(value, str) else value


def handle(kind, event, store):
    """Run one hook. If the keychain can't be read, known-value checks are skipped (patterns still run)
    and the user is told; the hook itself never crashes.

    A failure that is not a locked keychain is reported, and the action is
    blocked rather than passed through unjudged: the input and prompt hooks
    deny, and the output hook says the output was not checked.
    """
    load_error = None
    retired = {}
    try:
        secrets = store.load()
        retired = store.load_watch()
        warning = store.warning  # set by a store that had a partial failure
    except VaultError as exc:
        if is_headless():
            # Nobody can read "checking token patterns only" or unlock the keychain, so a
            # keychain that can't be read is a failed check: deny, block, replace the output.
            # stderr (below) carries the reason into the host's run log.
            secrets, warning, load_error = {}, None, exc
        else:
            secrets, retired, warning = {}, {}, "securikey: %s; checking token patterns only." % exc
    except Exception as exc:  # noqa: BLE001 - an unexpected store failure is judged like a failed check
        secrets, warning, load_error = {}, None, exc
    try:
        if load_error is not None:
            raise load_error
        dotenv_secrets, problems = project_dotenv_secrets(event)
        env_secrets, env_problems = watched_env_secrets()
        if env_problems:
            note = "securikey: %s." % "; ".join(env_problems)
            warning = "%s %s" % (warning, note) if warning else note
        secrets = {**dotenv_secrets, **env_secrets, **retired, **secrets}
        if problems:
            shown = "; ".join(problems[:MAX_SHOWN_PROBLEMS])
            if len(problems) > MAX_SHOWN_PROBLEMS:
                shown += "; and %d more" % (len(problems) - MAX_SHOWN_PROBLEMS)
            note = "securikey: some .env values were not checked: %s." % shown
            warning = "%s %s" % (warning, note) if warning else note
        out = HANDLERS[kind](event, secrets)
    except Exception as exc:  # noqa: BLE001 - the hook must not crash the session
        print("securikey: the %s hook failed: %s: %s" % (kind, type(exc).__name__, exc), file=sys.stderr)
        kind_name = type(exc).__name__
        if kind == "pre":
            out = _deny("securikey: the check failed (%s), so the call was not judged." % kind_name)
        elif kind == "prompt":
            out = {"decision": "block",
                   "reason": "securikey: the check failed (%s), so the prompt was not sent." % kind_name}
        elif kind == "failure":
            out = {"continue": False,
                   "stopReason": "securikey: the check of a failed tool call failed (%s), so its error text was "
                                 "not judged." % kind_name}
        else:
            notice = "securikey: the output was not checked for secrets."
            out = {"hookSpecificOutput": {"hookEventName": "PostToolUse",
                                         "updatedToolOutput": _replace_output(event.get("tool_response"), notice)},
                   "systemMessage": "securikey: the %s hook failed (%s), so the output was replaced rather "
                                     "than redacted." % (kind, kind_name)}
    if warning:
        out = dict(out or {})
        out["systemMessage"] = "%s %s" % (out["systemMessage"], warning) if out.get("systemMessage") else warning
    return out
