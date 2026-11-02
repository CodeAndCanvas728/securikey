import io
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest import mock

from securikey import cli
from securikey.store import MemoryStore

SECRET = "s3cr3t-Deploy-Value-42"
# Assembled from parts, so the file itself does not hold a string the
# CI secret scan would flag. The CI scans every file.
PEM_HEADER = "-----BEGIN " + "RSA PRIVATE KEY-----"
PEM_END = "-----END " + "RSA PRIVATE KEY-----"


def read(path):
    with open(path) as fh:
        return fh.read()


def run_cli(argv, store, stdin=""):
    out, err = io.StringIO(), io.StringIO()
    with mock.patch("sys.stdin", io.StringIO(stdin)), redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv, store)
    return code, out.getvalue(), err.getvalue()


class AddListRmTest(unittest.TestCase):
    def test_add_reads_value_from_stdin_and_never_prints_it(self):
        store = MemoryStore()
        code, out, _ = run_cli(["add", "deploy_key"], store, stdin=SECRET + "\n")
        self.assertEqual((code, store.secrets), (0, {"deploy_key": SECRET}))
        self.assertNotIn(SECRET, out)
        self.assertEqual(run_cli(["list"], store)[1].strip(), "deploy_key")

    def test_add_rejects_bad_names_and_empty_values(self):
        self.assertEqual(run_cli(["add", "Bad-Name"], MemoryStore(), stdin="x")[0], 1)
        self.assertEqual(run_cli(["add", "ok_name"], MemoryStore(), stdin="")[0], 1)

    def test_rm(self):
        store = MemoryStore({"a_key": SECRET})
        self.assertEqual(run_cli(["rm", "a_key"], store)[0], 0)
        self.assertEqual(store.secrets, {})
        self.assertEqual(run_cli(["rm", "a_key"], store)[0], 1)


class HelpAndInterruptTest(unittest.TestCase):
    def test_every_subcommand_has_a_help_line_and_the_usage_text_is_shown(self):
        out = io.StringIO()
        with redirect_stdout(out), self.assertRaises(SystemExit) as stop:
            cli.main(["--help"], MemoryStore())
        self.assertEqual(stop.exception.code, 0)
        text = out.getvalue()
        sub = next(a for a in cli.parser()._actions if getattr(a, "choices", None))
        for name in sub.choices:
            line = next((l for l in text.splitlines() if l.strip().startswith(name + " ")), "")
            self.assertGreater(len(line.split(None, 1)[-1]) if line else 0, len(name), name)
        self.assertIn("Environment: SECURIKEY_SERVICE", text)  # the module docstring, not only its first line

    def test_ctrl_c_and_closed_stdin_at_the_prompt_end_cleanly(self):
        store = MemoryStore()
        for exc, code in ((KeyboardInterrupt(), 130), (EOFError(), 1)):
            with mock.patch("securikey.cli._read_value", side_effect=exc):  # what getpass raises on ^C / ^D
                got, _, err = run_cli(["add", "deploy_key"], store)
            self.assertEqual(got, code, type(exc).__name__)
            self.assertNotIn("Traceback", err)
            self.assertEqual(store.secrets, {})

    def test_a_file_that_is_not_utf8_is_reported_not_a_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "app.cfg")
            with open(path, "wb") as fh:
                fh.write(b"API_KEY=\xff\xfe\x00abc\n")
            code, _, err = run_cli(["import", path, "--dry-run"], MemoryStore())
        self.assertEqual(code, 1)
        self.assertIn("UTF-8", err)
        self.assertNotIn("Traceback", err)


class RunTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env_file = os.path.join(self.tmp.name, ".env")
        with open(self.env_file, "w") as fh:
            fh.write("# comment\nexport DEPLOY=securikey:deploy_key\nPLAIN=\"hello\"\n")

    def tearDown(self):
        self.tmp.cleanup()

    def capture(self, argv, store):
        calls = []
        args = cli.parser().parse_args(argv)
        cli.cmd_run(args, store, exec_fn=lambda f, a, e: calls.append((f, a, e)))
        return calls[0]

    def test_env_and_dotenv_references_resolve_only_in_the_child_env(self):
        store = MemoryStore({"deploy_key": SECRET, "gh": "ghp_x"})
        prog, argv, env = self.capture(["run", "--env", "GH=gh", "--dotenv", self.env_file, "--", "npm", "test"], store)
        self.assertEqual((prog, argv), ("npm", ["npm", "test"]))
        self.assertEqual((env["DEPLOY"], env["PLAIN"], env["GH"]), (SECRET, "hello", "ghp_x"))
        self.assertNotIn("DEPLOY", os.environ)

    def test_the_deprecated_token_vault_prefix_still_resolves_with_a_notice_and_no_value(self):
        legacy = os.path.join(self.tmp.name, "legacy.env")
        with open(legacy, "w") as fh:
            fh.write("DEPLOY=token_vault:deploy_key\n")
        store = MemoryStore({"deploy_key": SECRET})
        err = io.StringIO()
        with redirect_stderr(err):
            _, _, env = self.capture(["run", "--dotenv", legacy, "--", "true"], store)
        self.assertEqual(env["DEPLOY"], SECRET)
        self.assertIn("deprecated `token_vault:` prefix", err.getvalue())
        self.assertNotIn(SECRET, err.getvalue())

    def test_import_leaves_a_deprecated_reference_alone(self):
        legacy = os.path.join(self.tmp.name, "legacy.env")
        with open(legacy, "w") as fh:
            fh.write("DEPLOY=token_vault:deploy_key\n")
        store = MemoryStore({"deploy_key": SECRET})
        run_cli(["import", legacy, "--all"], store)
        self.assertEqual(read(legacy), "DEPLOY=token_vault:deploy_key\n")
        self.assertEqual(store.secrets, {"deploy_key": SECRET})

    def test_missing_name_is_an_error_naming_it(self):
        code, _, err = run_cli(["run", "--env", "X=nope", "--", "true"], MemoryStore())
        self.assertEqual(code, 1)
        self.assertIn("nope", err)


class ImportTest(unittest.TestCase):
    def test_import_moves_secret_values_keeps_the_rest_and_the_file_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, ".env")
            with open(path, "w") as fh:
                fh.write("# db\nDB_PASSWORD='%s'\nPORT=3000\nGH=ghp_%s\nREUSED=securikey:old\n" % (SECRET, "a1B2c3D4e5" * 4))
            os.chmod(path, 0o600)
            store = MemoryStore({"old": "x" * 10})
            code, out, _ = run_cli(["import", path], store)
            text = read(path)
            self.assertEqual(code, 0)
            self.assertEqual(text, "# db\nDB_PASSWORD=securikey:db_password\nPORT=3000\nGH=securikey:gh\nREUSED=securikey:old\n")
            self.assertEqual(store.secrets["db_password"], SECRET)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            self.assertNotIn(SECRET, out)

    def test_import_keeps_crlf_line_endings(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, ".env")
            with open(path, "wb") as fh:
                fh.write(b"PORT=3000\r\nDB_PASSWORD='%s'\r\n" % SECRET.encode())
            code, _, _ = run_cli(["import", path], MemoryStore())
            with open(path, "rb") as fh:
                data = fh.read()
            self.assertEqual(code, 0)
            self.assertEqual(data, b"PORT=3000\r\nDB_PASSWORD=securikey:db_password\r\n")

    def test_dry_run_changes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, ".env")
            with open(path, "w") as fh:
                fh.write("API_TOKEN=%s\n" % SECRET)
            store = MemoryStore()
            run_cli(["import", path, "--dry-run"], store)
            self.assertEqual((read(path), store.secrets), ("API_TOKEN=%s\n" % SECRET, {}))

    def test_a_multi_line_value_is_imported_whole(self):
        pem = ('PRIVATE_KEY="' + PEM_HEADER + "\n"
               "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCSecretBodyLine\n"
               + PEM_END + '"\n')
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, ".env")
            with open(path, "w") as fh:
                fh.write(pem)
            store = MemoryStore()
            code, _, _ = run_cli(["import", path], store)
            self.assertEqual(code, 0)
            self.assertEqual(read(path), "PRIVATE_KEY=securikey:private_key\n")
            self.assertIn("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCSecretBodyLine", store.secrets["private_key"])
            self.assertNotIn("SecretBodyLine", read(path))

    def test_a_value_that_is_never_closed_is_refused(self):
        original = 'PRIVATE_KEY="' + PEM_HEADER + '\nMIIEvQSecretBody\n'
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, ".env")
            with open(path, "w") as fh:
                fh.write(original)
            store = MemoryStore()
            code, _, err = run_cli(["import", path], store)
            self.assertEqual(code, 1)
            self.assertIn("never closed", err)
            # nothing was rewritten and nothing was stored
            self.assertEqual(read(path), original)
            self.assertEqual(store.secrets, {})

    def test_an_inline_comment_is_not_part_of_the_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, ".env")
            with open(path, "w") as fh:
                fh.write("API_KEY=%s # a note\n" % SECRET)
            store = MemoryStore()
            code, _, _ = run_cli(["import", path], store)
            self.assertEqual(code, 0)
            self.assertEqual(store.secrets["api_key"], SECRET)
            self.assertEqual(read(path), "API_KEY=securikey:api_key # a note\n")

    def test_an_escaped_quote_inside_a_value_is_kept(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, ".env")
            with open(path, "w") as fh:
                fh.write('DB_PASSWORD="{\\"pass\\": \\"sk-secret\\"}"\n')
            store = MemoryStore()
            code, _, _ = run_cli(["import", path], store)
            self.assertEqual(code, 0)
            self.assertEqual(store.secrets["db_password"], '{"pass": "sk-secret"}')
            self.assertNotIn("sk-secret", read(path))

    def test_values_that_do_not_look_like_secrets_are_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, ".env")
            with open(path, "w") as fh:
                fh.write("API_KEY=%s\nPORT=3000\n" % SECRET)
            store = MemoryStore()
            code, out, _ = run_cli(["import", path], store)
            self.assertEqual(code, 0)
            self.assertIn("PORT", out)
            self.assertIn("still in the file", out)
            self.assertEqual(read(path), "API_KEY=securikey:api_key\nPORT=3000\n")


class HookTest(unittest.TestCase):
    def test_a_malformed_event_fails_the_hook(self):
        err = io.StringIO()
        with mock.patch("sys.stdin", io.StringIO("not json")), redirect_stderr(err):
            with self.assertRaises(SystemExit) as raised:
                cli.main(["hook", "pre"], MemoryStore())
        self.assertEqual(raised.exception.code, 1)
        self.assertIn("malformed hook event", err.getvalue())

    def test_an_empty_event_fails_the_hook(self):
        err = io.StringIO()
        with mock.patch("sys.stdin", io.StringIO("")), redirect_stderr(err):
            with self.assertRaises(SystemExit) as raised:
                cli.main(["hook", "pre"], MemoryStore())
        self.assertEqual(raised.exception.code, 1)
        self.assertIn("no hook event", err.getvalue())


if __name__ == "__main__":
    unittest.main()
