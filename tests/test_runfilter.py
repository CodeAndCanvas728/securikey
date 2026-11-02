import io
import os
import sys
import unittest
from unittest import mock

from securikey import cli, runfilter
from securikey.redact import known_forms
from securikey.store import MemoryStore, VaultError

SECRET = "s3cr3t-Deploy-Value-42"
GH = "ghp_" + "a1B2c3D4e5" * 4  # assembled: the CI secret scan flags a whole token
PEM_HEAD = "-----BEGIN " + "RSA PRIVATE KEY-----"
PEM_END = "-----END " + "RSA PRIVATE KEY-----"
KNOWN = known_forms({"deploy_key": SECRET})


def filtered(chunks, known=KNOWN, pause_after=()):
    """Everything the filter writes for these chunks (bytes), with a quiet() after the listed indexes."""
    out = []
    flt = runfilter.StreamFilter(known, out.append)
    for index, chunk in enumerate(chunks):
        flt.feed(chunk)
        if index in pause_after:
            flt.quiet()
    flt.finish()
    return "".join(out)


def split(data, size):
    return [data[i:i + size] for i in range(0, len(data), size)]


class StreamFilterTest(unittest.TestCase):
    def test_a_value_split_across_reads_is_still_redacted(self):
        data = ("line one\nAuthorization: Bearer %s\nline three %s\n" % (SECRET, GH)).encode()
        for size in (1, 2, 3, 5, 7, 11, 64, len(data)):
            text = filtered(split(data, size))
            self.assertNotIn(SECRET, text, size)
            self.assertNotIn(GH, text, size)
            self.assertIn("[securikey:deploy_key]", text, size)
            self.assertIn("[redacted:github]", text, size)
            self.assertTrue(text.startswith("line one\n"), size)

    def test_an_ordinary_stream_comes_out_unchanged(self):
        data = ("plain output\n" * 2000).encode()
        for size in (97, 4096, 70000):
            self.assertEqual(filtered(split(data, size)), data.decode(), size)

    def test_a_private_key_split_across_reads_is_dropped_whole(self):
        body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n"
        data = ("before\n%s\n%s%s\nafter\n" % (PEM_HEAD, body, PEM_END)).encode()
        for size in (1, 3, 10, 41, len(data)):
            text = filtered(split(data, size))
            self.assertNotIn("MIIEvQ", text, size)
            self.assertNotIn("KcwggS", text, size)
            self.assertIn("[redacted:private_key]", text, size)
            self.assertTrue(text.startswith("before\n"), size)
            self.assertTrue(text.endswith("after\n"), size)

    def test_a_key_that_never_ends_is_dropped_to_the_end_of_the_stream(self):
        data = ("%s\nMIIEvQIBADANBgkqhkiG9w0B\nstill key\n" % PEM_HEAD).encode()
        text = filtered(split(data, 5))
        self.assertEqual(text, "[redacted:private_key]")

    def test_a_multibyte_character_split_across_reads_survives(self):
        data = ("café ✓ ok %s\n" % SECRET).encode()
        text = filtered(split(data, 1))
        self.assertTrue(text.startswith("café ✓ ok "))
        self.assertNotIn(SECRET, text)

    def test_a_pause_releases_complete_lines_only(self):
        out = []
        flt = runfilter.StreamFilter(KNOWN, out.append)
        flt.feed(b"first line\nsecond line\nhalf a li")
        self.assertEqual(out, [])  # held back: a value could still be completing
        flt.quiet()
        self.assertEqual("".join(out), "first line\nsecond line\n")
        flt.feed(b"ne\n")
        flt.finish()
        self.assertEqual("".join(out), "first line\nsecond line\nhalf a line\n")

    def test_a_long_line_with_a_secret_in_the_middle_is_redacted(self):
        data = ("x" * 20000 + SECRET + "y" * 20000).encode()
        text = filtered(split(data, 4096))
        self.assertEqual(text, "x" * 20000 + "[securikey:deploy_key]" + "y" * 20000)


class RunTest(unittest.TestCase):
    def run_child(self, code, known=KNOWN):
        out, err = io.BytesIO(), io.BytesIO()
        status = runfilter.run([sys.executable, "-c", code], dict(os.environ), known, out, err)
        return status, out.getvalue().decode(), err.getvalue().decode()

    def test_a_failing_command_exits_with_its_code_and_prints_no_secret(self):
        code = "import sys; print(%r); print(%r, file=sys.stderr); sys.exit(3)" % (SECRET, "token " + GH)
        status, out, err = self.run_child(code)
        self.assertEqual(status, 3)
        self.assertEqual(out, "[securikey:deploy_key]\n")
        self.assertEqual(err, "token [redacted:github]\n")

    def test_success_and_signal_statuses(self):
        self.assertEqual(self.run_child("print('ok')")[0:2], (0, "ok\n"))
        self.assertEqual(self.run_child("import os, signal; os.kill(os.getpid(), signal.SIGTERM)")[0], 128 + 15)

    def test_a_missing_or_unrunnable_command_gets_the_shell_statuses(self):
        with mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(runfilter.run(["/no/such/program-xyz"], dict(os.environ), KNOWN, io.BytesIO(), io.BytesIO()), 127)
            self.assertEqual(runfilter.run([__file__], dict(os.environ), KNOWN, io.BytesIO(), io.BytesIO()), 126)

    def test_output_that_ends_without_a_newline_is_flushed(self):
        status, out, _ = self.run_child("import sys; sys.stdout.write('no newline ' + %r)" % SECRET)
        self.assertEqual((status, out), (0, "no newline [securikey:deploy_key]"))


class WhenItFiltersTest(unittest.TestCase):
    def test_only_when_stdout_is_piped_and_not_opted_out(self):
        with mock.patch.dict(os.environ, {"SECURIKEY_RUN_FILTER": "1"}):
            with mock.patch("sys.stdout.isatty", return_value=False, create=True):
                self.assertTrue(cli._filter_output())
            with mock.patch("sys.stdout.isatty", return_value=True, create=True):
                self.assertFalse(cli._filter_output())
        with mock.patch.dict(os.environ, {"SECURIKEY_RUN_FILTER": "0"}):
            with mock.patch("sys.stdout.isatty", return_value=False, create=True):
                self.assertFalse(cli._filter_output())

    def test_the_redaction_set_holds_stored_and_watched_values(self):
        store = MemoryStore({"deploy_key": SECRET})
        store.add_watch("retired:old", "an-old-Value-0001", 60)
        self.assertEqual(set(cli._redaction_set(store, store.load())), {"deploy_key", "retired:old"})

    def test_an_unreadable_watch_list_still_leaves_the_stored_secrets(self):
        store = MemoryStore({"deploy_key": SECRET})
        with mock.patch.object(store, "load_watch", side_effect=VaultError("locked")):
            self.assertEqual(cli._redaction_set(store, store.load()), {"deploy_key": SECRET})

    def test_cmd_run_returns_the_childs_status_through_the_filter(self):
        store = MemoryStore({"deploy_key": SECRET})
        args = cli.parser().parse_args(["run", "--env", "T=deploy_key", "--", "x"])
        with mock.patch("sys.stdout.isatty", return_value=False, create=True), \
                mock.patch("securikey.cli.runfilter.run", return_value=7) as run:
            self.assertEqual(cli.cmd_run(args, store), 7)
        command, env, known = run.call_args[0]
        self.assertEqual((command, env["T"]), (["x"], SECRET))
        self.assertEqual([name for _, name in known], ["deploy_key"] * len(known))


if __name__ == "__main__":
    unittest.main()
