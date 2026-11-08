"""Entries marked as non-secret configuration: not redacted, not blocked; terminal-only; secret by default."""
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from securikey import cli, hooks
from securikey.store import MemoryStore, VaultError, _parse_config, config_names, value_mark

SECRET = "s3cr3t-Deploy-Value-42"
ADDRESS = "http://127.0.0.1:3100/internal-api"  # configuration: a local server address
CWD = tempfile.mkdtemp()


def run_cli(argv, store, stdin="", terminal=True):
    out, err = io.StringIO(), io.StringIO()
    with mock.patch("sys.stdin", io.StringIO(stdin)), redirect_stdout(out), redirect_stderr(err), \
            mock.patch.object(cli, "_at_terminal", return_value=terminal), \
            mock.patch.object(cli.getpass, "getpass", return_value=stdin.rstrip("\n")):
        code = cli.main(argv, store)
    return code, out.getvalue(), err.getvalue()


def bash(command):
    return {"tool_name": "Bash", "cwd": CWD, "tool_input": {"command": command}}


def denied(out):
    return bool(out) and out["hookSpecificOutput"]["permissionDecision"] == "deny"


class MarkedEntryTest(unittest.TestCase):
    def store(self):
        store = MemoryStore({"deploy_key": SECRET})
        code, out, _ = run_cli(["add", "--config", "server_url"], store, stdin=ADDRESS + "\n")
        self.assertEqual(code, 0)
        self.assertNotIn(ADDRESS, out)
        return store

    def test_a_marked_entry_is_neither_blocked_nor_redacted_and_an_unmarked_one_still_is(self):
        store = self.store()
        self.assertFalse(denied(hooks.handle("pre", bash("curl %s" % ADDRESS), store)))
        self.assertTrue(denied(hooks.handle("pre", bash("curl -H 'x: %s' %s" % (SECRET, ADDRESS)), store)))
        shown = hooks.handle("post", {"tool_name": "Bash", "cwd": CWD, "tool_response": {"stdout": ADDRESS}}, store)
        self.assertIsNone(shown)
        hidden = hooks.handle("post", {"tool_name": "Bash", "cwd": CWD, "tool_response": {"stdout": SECRET}}, store)
        self.assertNotIn(SECRET, json.dumps(hidden))

    def test_it_is_not_redacted_from_the_output_of_skey_run(self):
        store = self.store()
        redaction = cli._redaction_set(store, store.load())
        self.assertNotIn(ADDRESS, redaction.values())
        self.assertIn(SECRET, redaction.values())

    def test_the_default_is_secret_and_an_upgrade_marks_nothing(self):
        store = MemoryStore({"server_url": ADDRESS})  # an existing entry: no mark item at all
        self.assertTrue(denied(hooks.handle("pre", bash("curl %s" % ADDRESS), store)))
        self.assertEqual(store.load_config(), {})
        run_cli(["add", "other"], store, stdin="a-plain-value-12345\n")
        self.assertEqual(store.load_config(), {})

    def test_marking_is_refused_without_a_terminal_and_changes_nothing(self):
        store = MemoryStore({"server_url": ADDRESS})
        for argv, stdin in ((["config", "server_url", "on"], ""), (["add", "--config", "other"], ADDRESS + "\n")):
            code, _, err = run_cli(argv, store, stdin=stdin, terminal=False)
            self.assertEqual(code, 1)
            self.assertIn("your own terminal", err)
        self.assertEqual((store.load_config(), sorted(store.secrets)), ({}, ["server_url"]))

    def test_marking_is_refused_in_a_headless_run(self):
        store = MemoryStore({"server_url": ADDRESS})
        with mock.patch.dict("os.environ", {"SECURIKEY_HEADLESS": "1"}):
            code, _, err = run_cli(["config", "server_url", "on"], store)
        self.assertEqual((code, store.load_config()), (1, {}))
        self.assertIn("your own terminal", err)

    def test_config_on_and_off(self):
        store = MemoryStore({"server_url": ADDRESS})
        self.assertEqual(run_cli(["config", "server_url", "on"], store)[0], 0)
        self.assertFalse(denied(hooks.handle("pre", bash("curl %s" % ADDRESS), store)))
        self.assertEqual(run_cli(["config", "server_url", "off"], store)[0], 0)
        self.assertTrue(denied(hooks.handle("pre", bash("curl %s" % ADDRESS), store)))
        self.assertEqual(run_cli(["config", "missing", "on"], store)[0], 1)

    def test_storing_a_new_value_makes_the_entry_a_secret_again(self):
        # An agent can pipe a value into `skey add`; the mark must not carry over to it.
        store = self.store()
        run_cli(["add", "server_url"], store, stdin=SECRET + "-other\n")
        self.assertTrue(denied(hooks.handle("pre", bash("echo %s-other" % SECRET), store)))
        self.assertEqual(config_names(store.load(), store.load_config()), set())

    def test_a_value_rotated_away_does_not_become_config_again_when_it_is_stored_again(self):
        # The person marks V, then rotates to V2. An agent (no terminal) later stores V again: a mark that
        # outlived V would match it and make it non-secret.
        store = self.store()
        self.assertEqual(run_cli(["rotate", "server_url"], store, stdin=ADDRESS + "-v2\n")[0], 0)
        self.assertEqual(store.load_config(), {})
        run_cli(["add", "server_url"], store, stdin=ADDRESS + "\n", terminal=False)
        self.assertEqual(store.load_config(), {})
        self.assertEqual(config_names(store.load(), store.load_config()), set())
        self.assertTrue(denied(hooks.handle("pre", bash("curl %s" % ADDRESS), store)))

    def test_every_write_drops_a_stale_mark_and_keeps_a_current_one(self):
        store = MemoryStore({"a": "one", "b": "two"})
        store.save_config({"a": value_mark("one"), "b": value_mark("two"), "gone": value_mark("x")})
        store.save({"a": "one", "b": "changed"})
        self.assertEqual(store.load_config(), {"a": value_mark("one")})

    def test_rm_clears_the_mark(self):
        store = self.store()
        self.assertEqual(run_cli(["rm", "server_url"], store)[0], 0)
        self.assertEqual(store.load_config(), {})
        run_cli(["add", "server_url"], store, stdin=ADDRESS + "\n")
        self.assertTrue(denied(hooks.handle("pre", bash("curl %s" % ADDRESS), store)))

    def test_list_shows_the_mark_and_never_a_value(self):
        store = self.store()
        out = run_cli(["list"], store)[1]
        self.assertIn("server_url  (config)", out)
        self.assertIn("deploy_key", out)
        self.assertNotIn(ADDRESS, out)
        self.assertNotIn("deploy_key  (config)", out)

    def test_a_rotated_out_value_is_still_redacted(self):
        store = self.store()
        store.add_watch("retired:server_url", ADDRESS, 3600)
        self.assertTrue(denied(hooks.handle("pre", bash("curl %s" % ADDRESS), store)))

    def test_unreadable_marks_leave_every_entry_secret(self):
        class Broken(MemoryStore):
            def load_config(self):
                raise VaultError("keychain unavailable: KeyringError")

        store = Broken({"server_url": ADDRESS})
        self.assertTrue(denied(hooks.handle("pre", bash("curl %s" % ADDRESS), store)))
        self.assertEqual(cli._redaction_set(store, store.load()).get("server_url"), ADDRESS)

    def test_a_corrupt_mark_item_is_empty(self):
        for raw in (None, "", "not json", "[1, 2]", '"x"', '{"a": 1, "b": ["x"]}'):
            self.assertEqual(_parse_config(raw), {}, raw)
        self.assertEqual(_parse_config('{"a": "h"}'), {"a": "h"})

    def test_a_mark_holds_only_for_its_value(self):
        marks = {"a": value_mark("one"), "b": value_mark("two")}
        self.assertEqual(config_names({"a": "one", "b": "changed", "c": "x"}, marks), {"a"})


if __name__ == "__main__":
    unittest.main()
