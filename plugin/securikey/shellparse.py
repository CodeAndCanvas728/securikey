"""A small, quote-aware reader for the shell commands the Bash gate has to judge.

The gate decides whether a command reads a .env file. That needs the commands, their words as the
shell reads them (quotes and backslashes removed), their redirects and their heredocs: cutting the
raw text at `;` or `|` also cuts inside a quoted string or a heredoc body, which is what made a note
that merely names a file look like a command.

`parse(text)` returns a list of `Command`, or None when the text uses shell this reader does not
model. None is not "safe": the caller must treat it as unknown. The Bash gate denies an unknown command
that holds a file name it guards; a name built by an expansion (`$'\x2e...'`) is not seen, as before.

Not modelled (None): `$'...'` and `$"..."`, `${...}`, subshells and groups, compound keywords
(`if`, `for`, `while`, `case`, ...), `;;`, an unclosed quote or substitution, a heredoc with no
closing line, a `<<` inside a substitution, and input over MAX_PARSE_CHARS.

The reader is one left-to-right pass: no backtracking, so its time grows with the input length only.
"""
from dataclasses import dataclass, field

MAX_PARSE_CHARS = 64 * 1024
MAX_COMMANDS = 500  # the gate compares commands with each other, so their number is bounded
MAX_HEREDOCS = 64

# A command that starts with one of these is control flow: its parts are not judged as commands.
KEYWORDS = frozenset(["if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case",
                      "esac", "function", "select", "{", "}", "!", "coproc"])
_NAME_START = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_")
_SPECIAL = frozenset("0123456789@*#?!$-")
_SPACE = " \t"


@dataclass
class Word:
    text: str = ""
    dynamic: bool = False  # an expansion, glob, `~` or brace list: the shell may turn it into something else
    quoted: bool = False  # some part was quoted or escaped (a heredoc tag that is quoted is not expanded)
    subs: list = field(default_factory=list)  # raw bodies of $(...), `...` and <(...) in the word


@dataclass
class Heredoc:
    tag: str
    quoted: bool
    strip_tabs: bool
    body: str = ""


@dataclass
class Command:
    assignments: list = field(default_factory=list)
    argv: list = field(default_factory=list)
    redirects: list = field(default_factory=list)  # (operator, Word)
    heredocs: list = field(default_factory=list)
    piped: bool = False  # its output goes into the next command


class _Unsupported(Exception):
    pass


def parse(text):
    """The commands in text, or None when the text is not fully understood."""
    if not isinstance(text, str) or len(text) > MAX_PARSE_CHARS:
        return None
    try:
        return _Reader(text).run()
    except _Unsupported:
        return None  # a RecursionError (quotes and substitutions nested too deep) is left to the caller: deny


def match_substitution(text, start):
    """The index of the `)` that closes a `$(` whose body starts at start, or raises _Unsupported.

    Quotes and escapes are skipped, so a `)` in a string does not end the body. A heredoc inside the
    body is not modelled: its text would be read as shell.
    """
    depth, i, n = 1, start, len(text)
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == "'":
            end = text.find("'", i + 1)
            if end < 0:
                raise _Unsupported
            i = end + 1
            continue
        if c == '"':
            i = _skip_double(text, i + 1)
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        elif c == "<" and text.startswith("<<", i) and not text.startswith("<<<", i):
            raise _Unsupported
        i += 1
    raise _Unsupported


def _skip_double(text, i):
    """The index just after the `"` that closes a double-quoted string whose body starts at i."""
    n = len(text)
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == '"':
            return i + 1
        if c == "$" and text.startswith("$(", i):
            i = match_substitution(text, i + 2) + 1
            continue
        if c == "`":
            end = _backtick_end(text, i + 1)
            i = end + 1
            continue
        i += 1
    raise _Unsupported


def _backtick_end(text, i):
    n = len(text)
    while i < n:
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == "`":
            return i
        i += 1
    raise _Unsupported


class _Reader:
    def __init__(self, text):
        self.text = text
        self.n = len(text)
        self.i = 0
        self.commands = []
        self.cur = Command()
        self.word = None  # the word being read
        self.pending = None  # the redirect operator waiting for its word
        self.queued = []  # heredocs of this line whose bodies follow the newline

    # -- words -----------------------------------------------------------------------------------
    def _w(self):
        if self.word is None:
            self.word = Word()
        return self.word

    def _end_word(self):
        word, self.word = self.word, None
        if word is None:
            return
        if self.pending is not None:
            op, self.pending = self.pending, None
            if op in ("<<", "<<-"):
                if word.dynamic or word.subs:
                    raise _Unsupported
                if len(self.queued) >= MAX_HEREDOCS:
                    raise _Unsupported
                heredoc = Heredoc(word.text, word.quoted, op == "<<-")
                self.cur.heredocs.append(heredoc)
                self.queued.append(heredoc)
            else:
                self.cur.redirects.append((op, word))
            return
        if not self.cur.argv and _is_assignment(word.text):
            self.cur.assignments.append(word)
            return
        if not self.cur.argv and word.text in KEYWORDS and not word.quoted:
            raise _Unsupported
        self.cur.argv.append(word)

    def _end_command(self, piped=False):
        self._end_word()
        if self.pending is not None:
            raise _Unsupported
        cur = self.cur
        if cur.assignments or cur.argv or cur.redirects or cur.heredocs:
            cur.piped = piped
            self.commands.append(cur)
            if len(self.commands) > MAX_COMMANDS:
                raise _Unsupported
        elif piped:
            raise _Unsupported  # `| x` with nothing before it
        self.cur = Command()

    # -- the pass ----------------------------------------------------------------------------------
    def run(self):
        text, n = self.text, self.n
        while self.i < n:
            c = text[self.i]
            if c in _SPACE:
                self._end_word()
                self.i += 1
            elif c == "\n":
                self._end_command()
                self.i += 1
                if self.queued:
                    self._read_heredocs()
            elif c == "#" and self.word is None:
                end = text.find("\n", self.i)
                self.i = n if end < 0 else end
            elif c == ";":
                if text.startswith(";;", self.i) or text.startswith(";&", self.i):
                    raise _Unsupported
                self._end_command()
                self.i += 1
            elif c == "&":
                self._ampersand()
            elif c == "|":
                if text.startswith("||", self.i):  # `||` ends a command: it does not pipe
                    self._end_command()
                    self.i += 2
                else:
                    self._end_command(piped=True)
                    self.i += 2 if text.startswith("|&", self.i) else 1
            elif c in "<>":
                self._redirect()
            elif c in "()":
                raise _Unsupported
            else:
                self._word_char(c)
        self._end_command()
        if self.queued or (self.commands and self.commands[-1].piped):
            raise _Unsupported  # a heredoc on the last line has no body, or a pipe has no right side
        return self.commands

    def _ampersand(self):
        text, i = self.text, self.i
        if text.startswith("&>", i):  # `&> file`, `&>> file`
            self._end_word()
            self.pending = ">>" if text.startswith("&>>", i) else ">"
            self.i += 3 if text.startswith("&>>", i) else 2
            return
        self._end_command()
        self.i += 2 if text.startswith("&&", i) else 1

    def _redirect(self):
        text, i = self.text, self.i
        # `2>file`: a word made only of digits just before the operator is the file descriptor.
        if self.word is not None and self.word.text.isdigit() and not self.word.quoted:
            self.word = None
        else:
            self._end_word()
        for op in ("<<<", "<<-", "<<", "<>", "<(", ">>", ">&", "<&", ">|", ">(", "<", ">"):
            if text.startswith(op, i):
                break
        if op in ("<(", ">("):  # a process substitution is a word of its own
            end = match_substitution(text, i + 2)
            word = self._w()
            word.text += text[i:end + 1]
            word.dynamic = True
            word.subs.append(text[i + 2:end])
            self.i = end + 1
            return
        self.i += len(op)
        if op in (">&", "<&"):
            op = op[0]
        elif op == ">|":
            op = ">"
        self.pending = op

    def _word_char(self, c):
        text, i = self.text, self.i
        word = self._w()
        if c == "\\":
            if i + 1 >= self.n:
                raise _Unsupported
            if text[i + 1] == "\n":  # a line continuation
                self.i += 2
                return
            word.text += text[i + 1]
            word.quoted = True
            self.i += 2
        elif c == "'":
            end = text.find("'", i + 1)
            if end < 0:
                raise _Unsupported
            word.text += text[i + 1:end]
            word.quoted = True
            self.i = end + 1
        elif c == '"':
            word.quoted = True
            self._double()
        elif c == "$":
            self._dollar(word, in_double=False)
        elif c == "`":
            end = _backtick_end(text, i + 1)
            word.subs.append(text[i + 1:end])
            word.text += text[i:end + 1]
            word.dynamic = True
            self.i = end + 1
        else:
            if c == "=" and not word.text and text.startswith("=(", i):
                raise _Unsupported  # zsh `=(...)`
            if c in "*?[~{":
                word.dynamic = True
            word.text += c
            self.i += 1

    def _double(self):
        text, word = self.text, self._w()
        i, n = self.i + 1, self.n
        while i < n:
            c = text[i]
            if c == '"':
                self.i = i + 1
                return
            if c == "\\":
                if i + 1 >= n:
                    raise _Unsupported
                nxt = text[i + 1]
                if nxt == "\n":
                    i += 2
                    continue
                word.text += nxt if nxt in '$`"\\' else c + nxt
                i += 2
            elif c == "$":
                self.i = i
                self._dollar(word, in_double=True)
                i = self.i
            elif c == "`":
                end = _backtick_end(text, i + 1)
                word.subs.append(text[i + 1:end])
                word.text += text[i:end + 1]
                word.dynamic = True
                i = end + 1
            else:
                word.text += c
                i += 1
        raise _Unsupported

    def _dollar(self, word, in_double):
        text, i = self.text, self.i
        nxt = text[i + 1] if i + 1 < self.n else ""
        if nxt == "(":
            end = match_substitution(text, i + 2)
            word.subs.append(text[i + 2:end])
            word.text += text[i:end + 1]
            word.dynamic = True
            self.i = end + 1
        elif nxt == "{":
            raise _Unsupported
        elif nxt in ("'", '"') and not in_double:
            raise _Unsupported
        else:
            if nxt in _NAME_START or nxt in _SPECIAL:
                word.dynamic = True
            word.text += "$"
            self.i = i + 1

    # -- heredoc bodies ----------------------------------------------------------------------------
    def _read_heredocs(self):
        text, n = self.text, self.n
        for heredoc in self.queued:
            lines = []
            while True:
                if self.i >= n:
                    raise _Unsupported  # no closing line
                end = text.find("\n", self.i)
                line = text[self.i:n if end < 0 else end]
                self.i = n if end < 0 else end + 1
                compare = line.lstrip("\t") if heredoc.strip_tabs else line
                if compare == heredoc.tag:
                    break
                lines.append(compare if heredoc.strip_tabs else line)
            heredoc.body = "\n".join(lines)
        self.queued = []


def _is_assignment(text):
    name, eq, _ = text.partition("=")
    if not eq or not name or name[0] not in _NAME_START:
        return False
    return all(ch in _NAME_START or ch.isdigit() for ch in name)
