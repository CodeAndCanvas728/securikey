import contextlib
import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from securikey import cli, migrate
from securikey.store import MemoryStore, VaultError

# Values are made-up and never appear in any assertion about output.
VALUE_A = "old-value-A-0123456789"
VALUE_B = "old-value-B-9876543210"
OTHER = "a-different-value-in-new"


def old_store(items):
    return MemoryStore(items, service="token-vault")


def new_store(items=None):
    return MemoryStore(items, service="securikey")


def run_migrate(argv, new, old):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(["migrate", *argv], new, old)
    return code, out.getvalue(), err.getvalue()


class MigrateTest(unittest.TestCase):
    def test_copies_every_item_and_verifies_by_reading_back(self):
        old, new = old_store({"a": VALUE_A, "b": VALUE_B}), new_store()
        code, out, err = run_migrate([], new, old)
        self.assertEqual((code, new.secrets), (0, {"a": VALUE_A, "b": VALUE_B}))
        self.assertIn("copied 2, already present 0, differing 0", out)

    def test_leaves_the_old_items_unless_purge_old_is_given(self):
        old, new = old_store({"a": VALUE_A}), new_store()
        run_migrate([], new, old)
        self.assertEqual(old.secrets, {"a": VALUE_A})

    def test_never_prints_a_value(self):
        old, new = old_store({"a": VALUE_A, "b": VALUE_B}), new_store({"b": OTHER})
        for argv in ([], ["--dry-run"], ["--purge-old"]):
            _, out, err = run_migrate(argv, new, old)
            for value in (VALUE_A, VALUE_B, OTHER):
                self.assertNotIn(value, out + err)

    def test_a_rerun_is_idempotent(self):
        old, new = old_store({"a": VALUE_A}), new_store()
        run_migrate([], new, old)
        code, out, _ = run_migrate([], new, old)
        self.assertEqual((code, new.secrets), (0, {"a": VALUE_A}))
        self.assertIn("copied 0, already present 1, differing 0", out)

    def test_an_existing_identical_item_is_skipped_and_others_are_still_copied(self):
        old, new = old_store({"a": VALUE_A, "b": VALUE_B}), new_store({"a": VALUE_A})
        code, out, _ = run_migrate([], new, old)
        self.assertEqual((code, new.secrets), (0, {"a": VALUE_A, "b": VALUE_B}))
        self.assertIn("already present, identical: a", out)

    def test_a_differing_existing_item_is_refused_with_next_steps(self):
        old, new = old_store({"a": VALUE_A, "b": VALUE_B}), new_store({"a": OTHER})
        code, out, _ = run_migrate([], new, old)
        self.assertEqual(code, 1)
        self.assertEqual(new.secrets["a"], OTHER)  # not overwritten
        self.assertEqual(new.secrets["b"], VALUE_B)  # the rest still moved
        self.assertIn("differs from the new store, not overwritten: a", out)
        self.assertIn("skey rm <name>", out)

    def test_purge_old_deletes_only_after_every_name_is_verified(self):
        old, new = old_store({"a": VALUE_A, "b": VALUE_B}), new_store()
        code, out, _ = run_migrate(["--purge-old"], new, old)
        self.assertEqual((code, old.secrets, new.secrets), (0, {}, {"a": VALUE_A, "b": VALUE_B}))
        self.assertIn("deleted the old keychain item", out)

    def test_purge_old_keeps_the_old_item_when_a_name_differs(self):
        old, new = old_store({"a": VALUE_A}), new_store({"a": OTHER})
        code, out, _ = run_migrate(["--purge-old"], new, old)
        self.assertEqual((code, old.secrets), (1, {"a": VALUE_A}))
        self.assertIn("old item kept", out)

    def test_purge_old_keeps_the_old_item_when_read_back_does_not_match(self):
        class Lossy(MemoryStore):
            def save(self, secrets):  # a keychain that stores something else
                super().save({k: v + "x" for k, v in secrets.items()})

        old, new = old_store({"a": VALUE_A}), Lossy(service="securikey")
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            code = cli.main(["migrate", "--purge-old"], new, old)
        self.assertEqual((code, old.secrets), (1, {"a": VALUE_A}))
        self.assertIn("verification failed for 1 name(s)", err.getvalue())

    def test_dry_run_changes_nothing(self):
        old, new = old_store({"a": VALUE_A, "b": VALUE_B}), new_store({"b": VALUE_B})
        code, out, _ = run_migrate(["--dry-run", "--purge-old"], new, old)
        self.assertEqual((code, old.secrets, new.secrets), (0, {"a": VALUE_A, "b": VALUE_B}, {"b": VALUE_B}))
        self.assertIn("would copy a", out)
        self.assertIn("would delete the old keychain item", out)

    def test_nothing_to_migrate_is_not_an_error(self):
        code, out, _ = run_migrate([], new_store(), old_store({}))
        self.assertEqual(code, 0)
        self.assertIn("nothing to migrate", out)

    def test_an_old_entry_that_is_not_a_name_and_text_changes_nothing_and_is_not_echoed(self):
        weird = "Not A Name " + VALUE_A
        old, new = old_store({weird: "x", "ok": VALUE_B}), new_store()
        code, out, err = run_migrate([], new, old)
        self.assertEqual((code, new.secrets), (1, {}))
        self.assertNotIn(VALUE_A, out + err)

    def test_the_same_service_on_both_sides_is_refused(self):
        with self.assertRaises(VaultError):
            migrate.migrate(MemoryStore(service="x"), MemoryStore({"a": VALUE_A}, service="x"))

    def test_both_stores_are_locked_for_the_whole_copy(self):
        events = []

        def tracked(store, label):
            @contextlib.contextmanager
            def transaction():
                events.append("lock " + label)
                yield
                events.append("unlock " + label)
            store.transaction = transaction
            return store

        old = tracked(old_store({"a": VALUE_A}), "old")
        new = tracked(new_store(), "new")
        migrate.migrate(new, old, out=lambda line: None)
        self.assertEqual(events, ["lock new", "lock old", "unlock old", "unlock new"])


class HintTest(unittest.TestCase):
    def test_other_commands_hint_when_only_the_old_store_has_items(self):
        for argv in (["list"], ["warm"]):
            _, _, err = self._run(argv, new_store(), old_store({"a": VALUE_A}))
            self.assertIn("run `skey migrate`", err)

    def _run(self, argv, new, old):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(argv, new, old)
        return code, out.getvalue(), err.getvalue()

    def test_no_hint_once_the_new_store_has_items(self):
        _, _, err = self._run(["list"], new_store({"b": VALUE_B}), old_store({"a": VALUE_A}))
        self.assertNotIn("skey migrate", err)

    def test_no_hint_when_the_old_store_is_empty(self):
        _, _, err = self._run(["list"], new_store(), old_store({}))
        self.assertNotIn("skey migrate", err)

    def test_no_hint_from_the_hook_command(self):
        with mock.patch("sys.stdin", io.StringIO('{"tool_name": "Bash", "tool_input": {"command": "true"}}')):
            _, _, err = self._run(["hook", "pre"], new_store(), old_store({"a": VALUE_A}))
        self.assertNotIn("skey migrate", err)

    def test_a_failing_old_store_never_breaks_the_command(self):
        class Broken(MemoryStore):
            def load(self):
                raise VaultError("keychain unavailable: X")

        code, out, _ = self._run(["list"], new_store(), Broken(service="token-vault"))
        self.assertEqual((code, out.strip()), (0, "(no secrets stored)"))


class HookStoreTest(unittest.TestCase):
    def test_hooks_redact_values_that_are_still_only_in_the_old_item(self):
        hook = cli._HookStore(new_store({"b": VALUE_B}), old_store({"a": VALUE_A, "b": OTHER}))
        loaded = hook.load()
        self.assertEqual(loaded["b"], VALUE_B)
        self.assertEqual(loaded["a"], VALUE_A)
        # An old value under a name that was stored again is still checked, under its own key.
        self.assertIn(OTHER, loaded.values())
        self.assertIn("b (old keychain item)", loaded)

    def test_a_broken_old_item_does_not_stop_the_hook(self):
        class Broken(MemoryStore):
            def load(self):
                raise VaultError("keychain unavailable: X")

        hook = cli._HookStore(new_store({"b": VALUE_B}), Broken())
        self.assertEqual(hook.load(), {"b": VALUE_B})
        self.assertIn("old keychain item could not be read", hook.warning)

    def test_the_hook_command_reports_an_unreadable_old_item_as_a_system_message_once(self):
        class Broken(MemoryStore):
            def load(self):
                raise VaultError("keychain unavailable: X")

        event = {"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {"command": "x"},
                 "tool_response": {"stdout": "fine"}}
        import json
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("sys.stdin", io.StringIO(json.dumps(event))), redirect_stdout(out), redirect_stderr(err):
            cli.main(["hook", "post"], new_store({"b": VALUE_B}), Broken(service="token-vault"))
        message = json.loads(out.getvalue())["systemMessage"]
        self.assertEqual(message.count("old keychain item could not be read"), 1)
        self.assertEqual(err.getvalue(), "")

    def test_the_hook_command_redacts_a_value_that_is_only_in_the_old_item(self):
        event = {"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {"command": "x"},
                 "tool_response": {"stdout": "out %s and %s" % (VALUE_A, OTHER)}}
        import json
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("sys.stdin", io.StringIO(json.dumps(event))), redirect_stdout(out), redirect_stderr(err):
            cli.main(["hook", "post"], new_store({"b": OTHER + "-new"}), old_store({"a": VALUE_A, "b": OTHER}))
        printed = out.getvalue()
        self.assertNotIn(VALUE_A, printed)
        self.assertNotIn(OTHER, printed)
        self.assertIn("[securikey:a]", printed)

    def test_a_failing_current_store_still_fails_the_hook(self):
        class Broken(MemoryStore):
            def load(self):
                raise VaultError("keychain unavailable: X")

        with self.assertRaises(VaultError):
            cli._HookStore(Broken(), old_store({})).load()


class RefShapeTest(unittest.TestCase):
    def test_only_a_prefix_followed_by_a_valid_name_is_a_reference(self):
        from securikey import dotenv
        self.assertEqual(dotenv.parse_ref("securikey:api_key"), ("api_key", False))
        self.assertEqual(dotenv.parse_ref("token_vault:api_key"), ("api_key", True))
        for value in ("securikey:Not A Name", "securikey:", "securikey:abc def", "token_vault:UPPER", "xsecurikey:a"):
            self.assertIsNone(dotenv.parse_ref(value), value)


if __name__ == "__main__":
    unittest.main()
