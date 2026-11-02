"""Redact the output of a command that `skey run` starts.

Claude Code runs its PostToolUse redaction only for a tool call that succeeds. A command that exits
non-zero hands its output to the model as it is, and no hook can change that. `skey run` is the one
place a secret is handed to a command on purpose, so it also filters that command's stdout and stderr:
the value never reaches the output of a failing `skey run`, whatever the hooks see.

Used only when stdout is not a terminal (the Bash tool always pipes it); at a terminal `skey run` still
replaces itself with the command. A piped child may buffer or colour differently, and output is held back
by up to HOLD_MIN characters (or until QUIET seconds pass with nothing new) so a value split across two
reads is still found.
"""
import codecs
import os
import re
import select
import signal
import subprocess
import sys
import threading

from securikey.redact import PEM_HEADER, redact

HOLD_MIN = 4096  # characters kept back until more output arrives; more if a stored form is longer
QUIET = 0.25  # seconds without output after which every complete line is released
READ_SIZE = 65536
MAX_HELD = 1 << 20  # a cap on what is held back while waiting for a line that never ends
LONG_LINE_NOTICE = "[securikey: a line over 1 MB was withheld]"
LINE_BREAK = re.compile(r"[\r\n]")
# Any armor header that names a private key; the same form as redact.PEM_RE, so one fix covers both.
PEM_BEGIN = re.compile(r"-----BEGIN +" + PEM_HEADER)
PEM_END = re.compile(r"-----END +" + PEM_HEADER)
PEM_TAIL = 64  # kept while inside a key, so an END line split across two reads is still seen


class StreamFilter:
    """Feed bytes in, get redacted text out through `write(text)`. Text that is held back is released
    by later output, by `quiet()` (a pause) or by `finish()` (end of the stream)."""

    def __init__(self, known, write):
        self.known, self.write = known, write
        longest = max((len(form) for form, _ in known), default=0)
        self.hold = max(HOLD_MIN, longest)
        # A stored value that spans lines can be split by a pause between two of its lines, so with one
        # a pause releases only what is older than the hold-back, not every complete line.
        self.multiline = any("\n" in form for form, _ in known)
        # surrogateescape: bytes that are not UTF-8 (a binary download on stdout) survive the round trip
        # unchanged instead of being replaced.
        self.decoder = codecs.getincrementaldecoder("utf-8")(errors="surrogateescape")
        self.buf = ""
        self.skipping = False  # inside a line that was withheld for its length: its rest is dropped
        self.in_pem = False
        self.pem_tail = ""

    def feed(self, data):
        self._absorb(self.decoder.decode(data))
        self._release()

    def quiet(self):
        self._release(quiet=True)

    def finish(self):
        self._absorb(self.decoder.decode(b"", True))
        self._release(final=True)

    def _absorb(self, fresh):
        """Add new text to the held-back text. The held text is already free of keys and must not be read
        as the inside of one, so while inside a key only the new text is scanned for its END line. Outside a
        key the held text is scanned again with the new text, because a header can be split across reads."""
        if self.in_pem:
            self.buf += self._scrub_pem(fresh)
        else:
            self.buf = self._scrub_pem(self.buf + fresh)

    def _scrub_pem(self, text):
        """The text without any private key in it. A key can span reads, so once a header has been seen
        everything is dropped until its END line, and what follows an END line is kept."""
        out = []
        if self.in_pem:
            text = self.pem_tail + text
            self.pem_tail = ""
        while text:
            if self.in_pem:
                end = PEM_END.search(text)
                if not end:
                    self.pem_tail = text[-PEM_TAIL:]
                    break
                self.in_pem, text = False, text[end.end():]
                continue
            begin = PEM_BEGIN.search(text)
            if not begin:
                out.append(text)
                break
            out.append(text[:begin.start()] + "[redacted:private_key]")
            self.in_pem, text = True, text[begin.end():]
        return "".join(out)

    def _release(self, final=False, quiet=False):
        text, self.buf = self.buf, ""
        if self.skipping:
            text = self._drop_rest_of_line(text)
            if not text:
                return
        # Stored values are replaced in everything held. The patterns run only on what is released, which
        # ends at a line break (see below): a pattern of unbounded length (a JWT) matched on a token that is
        # still arriving would redact its start and let the rest through.
        text, _ = redact(text, known=self.known, patterns=False)
        if final:
            cut = len(text)
        elif quiet and not self.multiline:
            cut = text.rfind("\n") + 1
        else:
            # Release only whole lines older than the hold-back: no pattern spans a line break, so a
            # token longer than the hold-back (a large JWT) is never written out in pieces. This also
            # covers a pause while a stored multi-line value is held: the cut is still a line break, never
            # a point inside a line, which would split a long token.
            limit = max(0, len(text) - self.hold)
            cut = max(text.rfind("\n", 0, limit), text.rfind("\r", 0, limit)) + 1
        if len(text) - cut > MAX_HELD:
            # One line too long to hold. Releasing a prefix could cut a token (a JWT has no length limit)
            # and print its start unredacted, so the line is withheld: a notice stands in for it, and the
            # rest of it is dropped as it arrives (see `skipping`).
            if cut:
                self.write(redact(text[:cut], known=(), patterns=True)[0])
            self.write(LONG_LINE_NOTICE)
            self.skipping = True
            self.buf = self._drop_rest_of_line(text[cut:])
            return
        if cut:
            self.write(redact(text[:cut], known=(), patterns=True)[0])
        self.buf = text[cut:]

    def _drop_rest_of_line(self, text):
        """What is left of text after the rest of the withheld line, which ends at the first line break."""
        end = LINE_BREAK.search(text)
        if end is None:
            return ""
        self.skipping = False
        return text[end.start():]


def _pump(pipe, flt):
    try:
        fd = pipe.fileno()
        while True:
            ready, _, _ = select.select([fd], [], [], QUIET)
            if not ready:
                flt.quiet()
                continue
            data = os.read(fd, READ_SIZE)
            if not data:
                break
            flt.feed(data)
        flt.finish()
    except Exception:
        # Fail closed: print nothing more from this stream, but never leave the pipe undrained, or the
        # child blocks on a full pipe and `skey run` hangs. If draining fails too, close the read end so
        # the child gets a broken pipe instead.
        try:
            while os.read(pipe.fileno(), READ_SIZE):
                pass
        except Exception:
            try:
                pipe.close()
            except Exception:
                pass


def _sink(stream):
    lock = threading.Lock()
    state = {"open": True}

    def write(text):
        with lock:
            if not state["open"]:
                return
            try:
                stream.write(text.encode("utf-8", "surrogateescape"))
                stream.flush()
            except (BrokenPipeError, ValueError, OSError):
                state["open"] = False  # the reader went away: keep draining the child so it can finish

    return write


def run(command, env, known, stdout=None, stderr=None):
    """Run command with its stdout and stderr redacted. Returns its exit status (128 + n for signal n)."""
    try:
        child = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        print("skey: %s: command not found" % command[0], file=sys.stderr)
        return 127
    except PermissionError:
        print("skey: %s: permission denied" % command[0], file=sys.stderr)
        return 126
    sinks = (_sink(stdout or sys.stdout.buffer), _sink(stderr or sys.stderr.buffer))
    threads = [threading.Thread(target=_pump, args=(pipe, StreamFilter(known, sink)), daemon=True)
               for pipe, sink in zip((child.stdout, child.stderr), sinks)]
    previous = {}
    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        try:  # only the main thread may install handlers; a caller on another thread just goes without
            previous[number] = signal.signal(number, lambda n, _f: child.poll() is None and child.send_signal(n))
        except ValueError:
            break
    try:
        for thread in threads:
            thread.start()
        code = child.wait()
        for thread in threads:
            thread.join()
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
        child.stdout.close()
        child.stderr.close()
    return 128 - code if code < 0 else code
