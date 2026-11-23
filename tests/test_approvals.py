import json
import os
import tempfile
import unittest
from unittest import mock

from securikey import approvals, cli, hooks
from securikey.store import MemoryStore
from tests.test_cli import run_cli

OLD = "0ld-Deploy-Value-1234567890"


class ApprovalCase(unittest.TestCase):
    def setUp(self):
        self.cache = tempfile.mkdtemp()
        env = mock.patch.dict(os.environ, {"XDG_CACHE_HOME": self.cache})
        env.start()
        self.addCleanup(env.stop)
        self.store = MemoryStore({"api_key": OLD})
        self.service = self.store.service

    def at_terminal(self, answers):
        """Patch in a person at a terminal who gives these answers, one per request."""
        for target in (mock.patch.object(cli, "_at_terminal", return_value=True),
                       mock.patch("builtins.input", side_effect=list(answers))):
            target.start()
            self.addCleanup(target.stop)

    def request(self, *argv):
        return run_cli(["request", *argv], self.store)

    def file_entries(self):
        return json.loads(approvals.path(self.service).read_text())


class RequestTest(ApprovalCase):
    def test_an_agent_without_a_terminal_can_file_a_request_that_holds_no_value(self):
        with mock.patch.object(cli, "_at_terminal", return_value=False):
            code, out, err = self.request("rotate", "api_key", "--generate", "--reason", "leaked in a log")
        self.assertEqual(code, 0, err)
        self.assertIn("skey approve", out)
        (entry,) = approvals.load(self.service)
        self.assertEqual((entry["op"], entry["name"], entry["status"]), ("rotate", "api_key", "pending"))
        self.assertNotIn(OLD, approvals.path(self.service).read_text())
        self.assertEqual(self.store.secrets, {"api_key": OLD})

    def test_the_file_and_folder_are_private(self):
        self.request("rotate", "api_key")
        self.assertEqual(os.stat(approvals.path(self.service)).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(approvals.path(self.service).parent).st_mode & 0o777, 0o700)

    def test_an_identical_request_is_not_filed_twice(self):
        self.request("rotate", "api_key")
        code, out, _ = self.request("rotate", "api_key")
        self.assertEqual(code, 0)
        self.assertIn("already queued", out)
        self.assertEqual(len(approvals.load(self.service)), 1)

    def test_rotate_and_config_need_an_existing_name_and_a_valid_one(self):
        self.assertEqual(self.request("rotate", "missing")[0], 1)
        self.assertEqual(self.request("config", "missing", "on")[0], 1)
        self.assertEqual(self.request("rotate", "Bad-Name")[0], 1)
        self.assertEqual(approvals.load(self.service), [])

    def test_sync_only_names_are_checked(self):
        self.assertEqual(self.request("sync", "paperclip", "--only", "api_key,Bad Name")[0], 1)
        self.assertEqual(self.request("sync", "paperclip", "--only", "ok_name")[0], 1)  # not stored
        self.assertEqual(self.request("sync", "paperclip", "--only", "api_key")[0], 0)

    def test_the_queue_is_capped(self):
        for i in range(approvals.MAX_PENDING):
            approvals.add(self.service, "rotate", "api_key", {"keep_days": i, "generate": False})
        self.assertEqual(self.request("rotate", "api_key", "--keep-days", "99")[0], 1)

    def test_the_reason_is_one_clean_short_line(self):
        reason = "line one\n\x1b[31mred\x1b[0m\N{RIGHT-TO-LEFT OVERRIDE}" + "x" * 500
        approvals.add(self.service, "rotate", "api_key", {"keep_days": 7, "generate": True}, reason)
        (entry,) = approvals.load(self.service)
        self.assertLessEqual(len(entry["reason"]), approvals.MAX_REASON)
        self.assertTrue(entry["reason"].isprintable())
        self.assertNotIn("\n", entry["reason"])

    def test_old_requests_expire(self):
        approvals.add(self.service, "rotate", "api_key", {"keep_days": 7, "generate": True}, now=1000)
        self.assertEqual(approvals.load(self.service, now=1000 + approvals.PENDING_TTL + 1), [])

    def test_pending_lists_requests_and_never_a_value(self):
        self.request("rotate", "api_key", "--generate")
        code, out, _ = run_cli(["pending"], self.store)
        self.assertEqual(code, 0)
        self.assertIn("api_key", out)
        self.assertNotIn(OLD, out)


class ForgedFileTest(ApprovalCase):
    def test_entries_the_agent_wrote_by_hand_are_dropped_unless_valid(self):
        good = {"id": "r000001", "op": "rotate", "name": "api_key", "options": {"keep_days": 7, "generate": True},
                "reason": "", "ts": 2 ** 31, "status": "pending"}
        bad = [dict(good, id="r000002", op="rm"), dict(good, id="r000003", name="../x"),
               dict(good, id="r000004", options={"keep_days": "7", "generate": True}),
               dict(good, id="r000005", options={"keep_days": True, "generate": True}),
               dict(good, id="nope"), dict(good, id="r000006", status="done"), "text", 7, None,
               dict(good, id="r000007", op="sync", name="paperclip", options={"only": "Bad Name", "update": False})]
        approvals.path(self.service).parent.mkdir(parents=True, exist_ok=True)
        approvals.path(self.service).write_text(json.dumps(bad + [good]))
        with mock.patch("time.time", return_value=2 ** 31 + 5):
            self.assertEqual([e["id"] for e in approvals.load(self.service)], ["r000001"])

    def test_a_file_that_is_not_json_is_no_requests(self):
        approvals.path(self.service).parent.mkdir(parents=True, exist_ok=True)
        approvals.path(self.service).write_text("{not json")
        self.assertEqual(approvals.load(self.service), [])

    def test_a_forged_approved_status_runs_nothing(self):
        approvals.add(self.service, "rotate", "api_key", {"keep_days": 7, "generate": True})
        entries = self.file_entries()
        entries[0]["status"] = "approved"
        approvals.path(self.service).write_text(json.dumps(entries))
        self.assertEqual(self.store.secrets, {"api_key": OLD})


class UntrustedTextTest(ApprovalCase):
    def test_a_sync_request_for_a_name_that_is_not_stored_is_refused_without_echoing_it(self):
        pasted = "pastedtokenthatisnotanamepastedtoken"
        code, out, err = self.request("sync", "paperclip", "--only", pasted)
        self.assertEqual(code, 1)
        self.assertNotIn(pasted, out + err)
        self.assertEqual(approvals.load(self.service), [])

    def test_a_reason_that_holds_a_stored_value_is_refused(self):
        code, out, err = self.request("rotate", "api_key", "--reason", "it is " + OLD)
        self.assertEqual(code, 1)
        self.assertNotIn(OLD, out + err)
        self.assertEqual(approvals.load(self.service), [])

    def test_a_name_the_agent_wrote_into_the_file_is_never_printed_or_run(self):
        pasted = "pastedtokenthatisnotanamepastedtoken"
        approvals.add(self.service, "sync", "paperclip", {"only": pasted, "update": False})
        _, out, err = run_cli(["pending"], self.store)
        self.assertNotIn(pasted, out + err)
        self.at_terminal(["y"])
        code, out, err = run_cli(["approve"], self.store)
        self.assertEqual(code, 1)
        self.assertNotIn(pasted, out + err)
        self.assertEqual(approvals.load(self.service)[0]["status"], "failed")

    def test_an_entry_dated_in_the_future_is_dropped_not_kept_forever(self):
        approvals.path(self.service).parent.mkdir(parents=True, exist_ok=True)
        entry = {"id": "r000001", "op": "rotate", "name": "api_key", "options": {"keep_days": 7, "generate": True},
                 "reason": "", "ts": 10 ** 10, "status": "pending"}
        approvals.path(self.service).write_text(json.dumps([entry]))
        self.assertEqual(approvals.load(self.service, now=1000), [])
        self.assertEqual(len(approvals.load(self.service, now=10 ** 10 - 10)), 1)


class ApproveTest(ApprovalCase):
    def test_approve_refuses_without_a_terminal_and_changes_nothing(self):
        self.request("rotate", "api_key", "--generate")
        with mock.patch.object(cli, "_at_terminal", return_value=False):
            code, _, err = run_cli(["approve"], self.store)
        self.assertEqual(code, 1)
        self.assertIn("your own terminal", err)
        self.assertEqual(self.store.secrets, {"api_key": OLD})
        self.assertEqual(approvals.load(self.service)[0]["status"], "pending")

    def test_approve_is_refused_when_headless_even_at_a_terminal(self):
        self.request("rotate", "api_key", "--generate")
        with mock.patch.object(cli, "_at_terminal", return_value=True), \
                mock.patch.dict(os.environ, {"SECURIKEY_HEADLESS": "1"}):
            self.assertEqual(run_cli(["approve"], self.store)[0], 1)
        self.assertEqual(self.store.secrets, {"api_key": OLD})

    def test_yes_rotates_with_a_generated_value_nobody_sees(self):
        self.request("rotate", "api_key", "--generate", "--reason", "leaked")
        self.at_terminal(["y"])
        code, out, err = run_cli(["approve"], self.store)
        new = self.store.secrets["api_key"]
        self.assertEqual(code, 0, err)
        self.assertNotEqual(new, OLD)
        self.assertNotIn(new, out + err)
        self.assertNotIn(OLD, out + err)
        self.assertIn("leaked", out)
        self.assertIn("retired:api_key", self.store.load_watch())
        self.assertEqual(approvals.load(self.service)[0]["status"], "approved")

    def test_yes_to_a_typed_rotation_reads_the_value_from_stdin(self):
        self.request("rotate", "api_key")
        self.at_terminal(["y"])
        code, out, _ = run_cli(["approve"], self.store, stdin="n3w-Typed-Value-0987654321\n")
        self.assertEqual((code, self.store.secrets["api_key"]), (0, "n3w-Typed-Value-0987654321"))
        self.assertNotIn("n3w-Typed", out)

    def test_no_discards_and_changes_nothing(self):
        self.request("rotate", "api_key", "--generate")
        self.at_terminal(["n"])
        run_cli(["approve"], self.store)
        self.assertEqual(self.store.secrets, {"api_key": OLD})
        self.assertEqual(approvals.load(self.service)[0]["status"], "denied")

    def test_skip_and_end_of_input_leave_it_waiting(self):
        self.request("rotate", "api_key", "--generate")
        self.at_terminal(["s"])
        run_cli(["approve"], self.store)
        self.assertEqual(approvals.load(self.service)[0]["status"], "pending")
        with mock.patch("builtins.input", side_effect=EOFError):
            run_cli(["approve"], self.store)
        self.assertEqual((self.store.secrets, approvals.load(self.service)[0]["status"]), ({"api_key": OLD}, "pending"))

    def test_config_is_described_with_what_it_unprotects(self):
        self.request("config", "api_key", "on")
        self.at_terminal(["s"])
        _, out, _ = run_cli(["approve"], self.store)
        self.assertIn("no longer redacted", out)

    def test_yes_marks_configuration(self):
        self.request("config", "api_key", "on")
        self.at_terminal(["y"])
        self.assertEqual(run_cli(["approve"], self.store)[0], 0)
        self.assertIn("api_key", self.store.load_config())

    def test_sync_runs_with_the_recorded_options_and_shows_the_target(self):
        self.request("sync", "paperclip", "--only", "api_key", "--update")
        seen = []
        self.at_terminal(["y"])
        with mock.patch.dict(os.environ, {"SECURIKEY_PAPERCLIP_URL": "https://paperclip.example"}), \
                mock.patch.dict(cli.COMMANDS, {"sync": lambda a, s: seen.append((a.target, a.only, a.update))}):
            _, out, _ = run_cli(["approve"], self.store)
        self.assertEqual(seen, [("paperclip", "api_key", True)])
        self.assertIn("https://paperclip.example", out)

    def test_the_person_is_shown_a_copy_and_that_copy_is_what_runs(self):
        """The agent rewrites the file while the person is at the prompt: the shown request still decides."""
        self.store.secrets["other_key"] = "0ther-Value-1234567890-xx"
        self.request("rotate", "api_key", "--generate")
        entries = self.file_entries()

        def swap(_prompt):
            tampered = [dict(entries[0], name="other_key")]
            approvals.path(self.service).write_text(json.dumps(tampered))
            return "y"

        for target in (mock.patch.object(cli, "_at_terminal", return_value=True),
                       mock.patch("builtins.input", side_effect=swap)):
            target.start()
            self.addCleanup(target.stop)
        run_cli(["approve"], self.store)
        self.assertEqual(self.store.secrets["other_key"], "0ther-Value-1234567890-xx")
        self.assertNotEqual(self.store.secrets["api_key"], OLD)

    def test_a_failing_command_is_recorded_as_failed(self):
        self.request("rotate", "api_key", "--generate")
        del self.store.secrets["api_key"]  # gone before the person got to it
        self.at_terminal(["y"])
        code, _, err = run_cli(["approve"], self.store)
        self.assertEqual(code, 1)
        self.assertIn("not in the keychain", err)
        self.assertEqual(approvals.load(self.service)[0]["status"], "failed")

    def test_approve_by_id_and_an_unknown_id(self):
        self.request("rotate", "api_key", "--generate")
        self.at_terminal(["y"])
        self.assertEqual(run_cli(["approve", "r999999"], self.store)[0], 1)
        self.assertEqual(self.store.secrets, {"api_key": OLD})
        entry = approvals.load(self.service)[0]
        self.assertEqual(run_cli(["approve", entry["id"]], self.store)[0], 0)


class RotateGenerateTest(unittest.TestCase):
    def test_generate_replaces_the_value_without_printing_it(self):
        store = MemoryStore({"api_key": OLD})
        with mock.patch.object(cli, "_at_terminal", return_value=True), \
                mock.patch.dict(os.environ, {"XDG_CACHE_HOME": tempfile.mkdtemp()}):
            code, out, err = run_cli(["rotate", "api_key", "--generate"], store)
        self.assertEqual(code, 0, err)
        self.assertNotIn(store.secrets["api_key"], out + err)
        self.assertNotEqual(store.secrets["api_key"], OLD)


class HookTest(unittest.TestCase):
    def test_the_queue_commands_are_not_human_only(self):
        for command in ("skey request rotate api_key --generate --reason leaked", "skey request sync paperclip",
                        "skey request config api_key on", "skey pending", "skey approve"):
            self.assertIsNone(hooks._runs_human_only(command), command)

    def test_the_deny_message_names_the_way_out(self):
        out = hooks.handle("pre", {"tool_name": "Bash", "tool_input": {"command": "skey rotate api_key"}},
                           MemoryStore())
        self.assertIn("skey request", json.dumps(out))
