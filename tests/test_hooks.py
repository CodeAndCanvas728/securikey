import time
import threading
from pathlib import Path
import json
import os
import tempfile
import unittest
from unittest import mock

from securikey import dotenv, hooks
from securikey.store import MemoryStore, VaultError

SECRET = "s3cr3t-Deploy-Value-42"
STORE = MemoryStore({"deploy_key": SECRET})


# A real folder with no dotenv files in it: a cwd that doesn't exist is reported by the hook.
_EMPTY_PROJECT = tempfile.TemporaryDirectory()
CWD = _EMPTY_PROJECT.name


def bash(command):
    return {"hook_event_name": "PreToolUse", "session_id": "396af541-9e08-45d2-a870-3f8162901d4a",
            "cwd": CWD, "tool_name": "Bash", "tool_input": {"command": command}}


def bash_in(command, cwd):
    event = bash(command)
    event["cwd"] = cwd
    return event


def denied(out):
    return bool(out) and out["hookSpecificOutput"]["permissionDecision"] == "deny"


class FailedToolCallTest(unittest.TestCase):
    """Claude Code runs PostToolUse only when a tool succeeds, and a failed call's error text cannot be
    rewritten. The failure hook can only notice a secret in it and stop the turn."""

    GH = "ghp_" + "a1B2c3D4e5" * 4  # assembled: the CI secret scan flags a whole token

    def event(self, error, tool="Bash"):
        return {"hook_event_name": "PostToolUseFailure", "cwd": CWD, "tool_name": tool, "tool_input": {},
                "error": error}

    def test_an_error_with_a_secret_stops_the_turn_without_echoing_it(self):
        for secret, label in ((self.GH, "github"), (SECRET, "deploy_key")):
            out = hooks.handle("failure", self.event("Exit code 22\nHTTP 401: token %s rejected" % secret), STORE)
            self.assertIs(out["continue"], False)
            self.assertIn(label, out["stopReason"])
            self.assertNotIn(secret, json.dumps(out))

    def test_an_ordinary_error_passes(self):
        self.assertIsNone(hooks.handle("failure", self.event("Exit code 1\nCannot find module 'express'"), STORE))
        self.assertIsNone(hooks.handle("failure", self.event(None), STORE))

    def test_a_failed_check_fails_closed(self):
        with mock.patch.dict(hooks.HANDLERS, {"failure": mock.Mock(side_effect=RuntimeError("boom"))}):
            out = hooks.handle("failure", self.event("anything"), STORE)
        self.assertIs(out["continue"], False)
        self.assertNotIn("boom", json.dumps(out))


class PreToolUseTest(unittest.TestCase):
    def test_secret_in_input_is_denied_without_echoing_it(self):
        out = hooks.handle("pre", bash("curl -H 'Authorization: %s' https://api" % SECRET), STORE)
        self.assertTrue(denied(out))
        self.assertEqual(out["hookSpecificOutput"]["hookEventName"], "PreToolUse")
        self.assertIn("deploy_key", out["hookSpecificOutput"]["permissionDecisionReason"])
        self.assertNotIn(SECRET, json.dumps(out))

    def test_ordinary_commands_pass(self):
        for cmd in ["ls", "git show 5bdd55aaa355a3484c7ebb47e74f559e08d258ca", "cat .env.example", "npm test"]:
            self.assertIsNone(hooks.handle("pre", bash(cmd), STORE), cmd)

    def test_env_file_reads_denied_but_metadata_and_tv_allowed(self):
        for cmd in ["cat .env", "grep KEY app/.env.local", "source .env && run", "FOO=1 head ./.env"]:
            self.assertTrue(denied(hooks.handle("pre", bash(cmd), STORE)), cmd)
        for cmd in ["skey import .env", "git check-ignore .env", "ls -la .env"]:
            self.assertIsNone(hooks.handle("pre", bash(cmd), STORE), cmd)
        read = {"tool_name": "Read", "tool_input": {"file_path": "/p/.env.production"}}
        self.assertTrue(denied(hooks.handle("pre", read, STORE)))
        self.assertIsNone(hooks.handle(
            "pre", {"tool_name": "Read", "cwd": CWD, "tool_input": {"file_path": "/p/.env.example"}}, STORE))

    def test_a_shell_substitution_cannot_smuggle_a_read(self):
        # The allowlist covers the command that is written, not the one the
        # shell runs after an expansion.
        for cmd in ["ls $(cat .env)", "ls `cat .env`", "test $(cat .env) = x",
                    "[ $(cat .env) ]", "git check-ignore $(cat .env)",
                    "skey list $(cat .env)", "skey import $(cat .env)", "skey patterns $(cat .env)",
                    "ls $(echo $(echo .env))", "cat $(echo $(echo .env))",
                    "cat ${X}.env", "cat $(echo .env)"]:
            self.assertTrue(denied(hooks.handle("pre", bash(cmd), STORE)), cmd)

    def test_ls_cannot_read_a_file_of_names(self):
        # ls --from-file=.env prints the names in the file.
        for cmd in ["ls --from-file=.env", "ls --from-file .env"]:
            self.assertTrue(denied(hooks.handle("pre", bash(cmd), STORE)), cmd)
        for cmd in ["ls .env", "ls -la .env"]:
            self.assertIsNone(hooks.handle("pre", bash(cmd), STORE), cmd)

    def test_other_common_env_file_names_are_checked(self):
        for cmd in ["cat .envrc", "cat .env-prod", "cat .env_local", "cat prod.env", "cat config/secrets.env",
                    "head -5 production.env"]:
            self.assertTrue(denied(hooks.handle("pre", bash(cmd), STORE)), cmd)
        for cmd in ["cat .envrc.example", "cat prod.env.example", "cat .env-prod.sample"]:
            self.assertIsNone(hooks.handle("pre", bash(cmd), STORE), cmd)
        # code that reads the process environment, and words that only start like the name
        for cmd in ["grep -rn process.env src", "node -e 'console.log(process.env.HOME)'", "cat .environment",
                    "cat docs/environment.md"]:
            self.assertIsNone(hooks.handle("pre", bash(cmd), STORE), cmd)

    def test_the_content_scan_reads_the_same_names(self):
        for name in [".env", ".envrc", ".env.local", ".env-prod", ".env_local", "prod.env", "secrets.env"]:
            self.assertTrue(hooks.DOTENV_NAME_RE.match(name), name)
        for name in [".environment", "environment.md", "config.json", ".envrc.example"]:
            self.assertFalse(hooks.DOTENV_NAME_RE.match(name) and not hooks.SAFE_ENV_RE.fullmatch(name), name)

    def test_the_env_name_patterns_are_linear_on_long_names(self):
        # A body class that also holds `_` and `-` made `.env_a_a_a...!` exponential: 55 characters took 7 s.
        for text in (".env" + "_a" * 5000 + "!", "cat /x/.env" + "-a" * 5000 + "!", ".envrc" + "_-" * 5000 + "!"):
            start = time.monotonic()
            hooks.ENV_FILE_RE.search(text)
            hooks._env_names(text)
            self.assertLess(time.monotonic() - start, 1, text[:20])
        for name in (".env" + "_a" * 5000 + ".example", ".env" + "_a" * 5000 + "!"):
            start = time.monotonic()
            hooks.SAFE_ENV_RE.fullmatch(name)
            self.assertLess(time.monotonic() - start, 1)
        self.assertTrue(denied(hooks.handle("pre", bash("cat .env_local_backup"), STORE)))

    def test_a_very_long_command_does_not_stall_the_sync_gate(self):
        start = time.monotonic()
        self.assertFalse(hooks._runs_human_only("echo " + "{" * 100000))
        self.assertLess(time.monotonic() - start, 2)
        self.assertTrue(hooks._runs_human_only("echo " + "{" * 100000 + " skey " + "sync"))

    def test_a_name_with_more_than_one_dot_is_checked(self):
        for cmd in ["cat .env.local.bak", "cat .env.production.2024-01-01", "cp .env.backup.1 x"]:
            self.assertTrue(denied(hooks.handle("pre", bash(cmd), STORE)), cmd)
        read = {"tool_name": "Read", "tool_input": {"file_path": "/p/.env.production.2024-01-01"}}
        self.assertTrue(denied(hooks.handle("pre", read, STORE)))
        glob = {"tool_name": "Glob", "tool_input": {"pattern": "**/.env.*.*"}}
        self.assertTrue(denied(hooks.handle("pre", glob, STORE)))

    def test_tv_run_needs_a_dotenv_whose_values_are_all_names(self):
        # A file that still holds a plaintext value would put it into the
        # child's environment, where no command can be trusted to keep it out
        # of the transcript. The check is structural, so a value the plugin
        # did not recognise counts too.
        with tempfile.TemporaryDirectory() as tmp:
            dsn = os.path.join(tmp, ".env")
            with open(dsn, "w") as fh:
                fh.write("CONNECTION=postgres://user:hunter2@db/prod\n")
            other = os.path.join(tmp, "settings.ini")
            with open(other, "w") as fh:
                fh.write("PASSWORD=hunter2\n")
            imported = os.path.join(tmp, "ok.env")
            with open(imported, "w") as fh:
                fh.write("API_KEY=securikey:api_key\n")
            for cmd in ["skey run --dotenv %s -- npm start" % dsn,
                        "skey run --dotenv %s -- printenv" % dsn,
                        "skey run --dotenv %s -- env" % other,
                        "skey run --dotenv %s -- node -e 'x'" % other]:
                self.assertTrue(denied(hooks.handle("pre", bash_in(cmd, tmp), STORE)), cmd)
            cmd = "skey run --dotenv %s -- npm start" % imported
            self.assertIsNone(hooks.handle("pre", bash_in(cmd, tmp), STORE), cmd)
            deprecated = os.path.join(tmp, "old.env")
            with open(deprecated, "w") as fh:
                fh.write("API_KEY=token_vault:api_key\n")
            cmd = "skey run --dotenv %s -- npm start" % deprecated
            self.assertIsNone(hooks.handle("pre", bash_in(cmd, tmp), STORE), cmd)

    def test_a_relative_dotenv_is_refused_when_the_command_changes_directory(self):
        # The hook reads the file relative to the session's directory, and the
        # command may have moved somewhere else.
        cmd = "cd /srv && skey run --dotenv .env -- printenv"
        self.assertTrue(denied(hooks.handle("pre", bash_in(cmd, "/tmp"), STORE)), cmd)

    def test_a_hook_that_fails_denies_rather_than_allowing(self):
        with mock.patch.object(hooks, "known_forms", side_effect=RuntimeError("boom")):
            out = hooks.handle("pre", bash("ls"), STORE)
        self.assertTrue(denied(out), out)
        with mock.patch.object(hooks, "known_forms", side_effect=RuntimeError("boom")):
            out = hooks.handle("prompt", {"prompt": "hello"}, STORE)
        self.assertEqual(out["decision"], "block")
        # The output must not reach the model unredacted.
        with mock.patch.object(hooks, "known_forms", side_effect=RuntimeError("boom")):
            out = hooks.handle("post", {"tool_name": "Bash", "tool_response": {"stdout": "a secret"}}, STORE)
        self.assertNotIn("a secret", repr(out))
        self.assertEqual(out["hookSpecificOutput"]["updatedToolOutput"]["stdout"],
                         "securikey: the output was not checked for secrets.")

    def test_plain_dotenv_names_are_denied_in_any_case_and_simple_quoting(self):
        for cmd in ["cat .ENV", "cat .'env'", 'cat ."env"', "cat \\.env", "grep KEY app/.Env.local"]:
            self.assertTrue(denied(hooks.handle("pre", bash(cmd), STORE)), cmd)
        for cmd in ["ls -la", "cat notes.md", "echo *.py", "echo {a,b}.txt"]:
            self.assertIsNone(hooks.handle("pre", bash(cmd), STORE), cmd)

    def test_the_failure_fallback_replaces_nested_strings_and_keeps_the_shape(self):
        response = {"type": "text", "file": {"content": "a secret", "lines": ["a secret too"], "type": "a secret 3"},
                    "x": {"type": {"v": "a secret 4"}}, "n": 3}
        with mock.patch.object(hooks, "known_forms", side_effect=RuntimeError("boom")):
            out = hooks.handle("post", {"tool_name": "Read", "tool_response": response}, STORE)
        updated = out["hookSpecificOutput"]["updatedToolOutput"]
        self.assertNotIn("a secret", repr(out))
        self.assertEqual((updated["type"], updated["n"]), ("text", 3))
        keyed = {"stdout": "ok", "sk-ant-" + "S" * 30: "harmless", "file": {"filePath": "/x", "ghp_" + "k" * 36: 1}}
        with mock.patch.object(hooks, "known_forms", side_effect=RuntimeError("boom")):
            out = hooks.handle("post", {"tool_name": "X", "tool_response": keyed}, STORE)
        updated = out["hookSpecificOutput"]["updatedToolOutput"]
        self.assertNotIn("sk-ant-", repr(out))
        self.assertNotIn("ghp_", repr(out))
        self.assertIn("stdout", updated)
        self.assertIn("filePath", updated["file"])  # field names stay, so the shape is kept
        with mock.patch.object(hooks, "known_forms", side_effect=RuntimeError("boom")):
            listed = hooks.handle("post", {"tool_name": "X", "tool_response": ["a secret", 1]}, STORE)
        self.assertEqual(listed["hookSpecificOutput"]["updatedToolOutput"],
                         ["securikey: the output was not checked for secrets.", 1])  # the list shape is kept

    def test_a_long_field_name_is_kept_in_the_failure_fallback(self):
        # A field name longer than 24 characters is a field name, not a secret: rewriting
        # it would change the shape Claude Code recognises.
        name = "aVeryLongFieldNameThatKeepsGoingOnAndOn"
        response = {name: "a value", "ghp_" + "k" * 36: "a value"}
        with mock.patch.object(hooks, "known_forms", side_effect=RuntimeError("boom")):
            out = hooks.handle("post", {"tool_name": "X", "tool_response": response}, STORE)
        updated = out["hookSpecificOutput"]["updatedToolOutput"]
        self.assertIn(name, updated)
        self.assertNotIn("ghp_", repr(out))  # a token is not a field name, however long it is

    def test_an_unexpected_store_failure_is_not_waved_through(self):
        class Broken:
            def load(self):
                raise RuntimeError("disk on fire")
        self.assertTrue(denied(hooks.handle("pre", bash("ls"), Broken())))
        self.assertEqual(hooks.handle("prompt", {"prompt": "hello"}, Broken())["decision"], "block")
        out = hooks.handle("post", {"tool_name": "Bash", "tool_response": {"stdout": "a secret"}}, Broken())
        self.assertNotIn("a secret", repr(out))

    def test_a_corrupt_keychain_entry_degrades(self):
        class Corrupt(MemoryStore):
            def load(self):
                return {"deploy_key": 42}  # not a string

        # The bad entry is skipped and the hook still works.
        out = hooks.handle("pre", bash("cat .env"), Corrupt())
        self.assertTrue(denied(out), out)

    def test_a_safe_env_name_does_not_vouch_for_an_unsafe_one(self):
        for cmd in ["cat .env.example .env", "diff .env.example .env",
                    "grep KEY .env.example .env", "cat .env.example .env.local"]:
            self.assertTrue(denied(hooks.handle("pre", bash(cmd), STORE)), cmd)
        read = {"tool_name": "Read", "tool_input": {"file_path": "/p/.env.example /p/.env"}}
        self.assertTrue(denied(hooks.handle("pre", read, STORE)))
        grep = {"tool_name": "Grep", "tool_input": {"pattern": "KEY", "path": ".env"}}
        self.assertTrue(denied(hooks.handle("pre", grep, STORE)))

    def test_only_safe_env_names_are_allowed(self):
        for cmd in ["cat .env.example", "cat .env.sample", "cat .env.template", "cat .env.dist"]:
            self.assertIsNone(hooks.handle("pre", bash(cmd), STORE), cmd)
        for name in [".env.example", ".env.sample", ".env.template", ".env.dist"]:
            read = {"tool_name": "Read", "cwd": CWD, "tool_input": {"file_path": "/p/" + name}}
            self.assertIsNone(hooks.handle("pre", read, STORE), name)

    def test_git_cannot_print_a_file(self):
        for cmd in ["git show HEAD:.env", "git log -p -- .env", "git diff -- .env",
                    "git cat-file -p abc123:.env", "git grep SECRET -- .env",
                    "git -C /repo show HEAD:.env"]:
            self.assertTrue(denied(hooks.handle("pre", bash(cmd), STORE)), cmd)
        for cmd in ["git check-ignore .env", "git status", "git ls-files", "git rev-parse HEAD"]:
            self.assertIsNone(hooks.handle("pre", bash(cmd), STORE), cmd)

    def test_glob_is_checked_and_a_grep_pattern_is_not_a_path(self):
        glob = {"tool_name": "Glob", "tool_input": {"pattern": "**/.env"}}
        self.assertTrue(denied(hooks.handle("pre", glob, STORE)))
        # A Grep pattern is a regex, so a .env in it is not a .env path.
        grep = {"tool_name": "Grep", "cwd": CWD, "tool_input": {"pattern": ".env", "path": "src"}}
        self.assertIsNone(hooks.handle("pre", grep, STORE))

    def test_tv_run_cannot_run_something_that_prints_an_env(self):
        for cmd in ["skey run --dotenv .env -- cat .env", "skey run -- cat .env",
                    "skey run --env X=1 -- cat .env", "skey run --dotenv .env -- cat .env.local",
                    # the separator is optional in the CLI
                    "skey run cat .env", "skey run --dotenv .env cat .env"]:
            self.assertTrue(denied(hooks.handle("pre", bash(cmd), STORE)), cmd)
        for cmd in ["skey import .env", "skey list", "skey run npm start"]:
            self.assertIsNone(hooks.handle("pre", bash(cmd), STORE), cmd)

    def test_an_assignment_that_names_an_env_is_not_skipped(self):
        for cmd in ["ENV_FILE=.env && cat $ENV_FILE", "F=.env; cat $F",
                    "ENV_FILE=.env && cat .env"]:
            self.assertTrue(denied(hooks.handle("pre", bash(cmd), STORE)), cmd)

    def test_a_wildcard_glob_is_checked(self):
        for tool_input in [{"tool_name": "Glob", "tool_input": {"pattern": "**/.env"}},
                           {"tool_name": "Glob", "tool_input": {"pattern": "*.env"}},
                           {"tool_name": "Glob", "tool_input": {"pattern": ".env.*"}},
                           {"tool_name": "Glob", "tool_input": {"pattern": "**/.env*"}},
                           {"tool_name": "Grep", "tool_input": {"pattern": "KEY", "glob": "*.env"}},
                           {"tool_name": "Grep", "tool_input": {"pattern": "KEY", "glob": ".env*"}}]:
            self.assertTrue(denied(hooks.handle("pre", tool_input, STORE)), tool_input)
        for cmd in ["cat *.env", "cat .env.*", "cat .env*"]:
            self.assertTrue(denied(hooks.handle("pre", bash(cmd), STORE)), cmd)


class PostToolUseTest(unittest.TestCase):
    def test_bash_output_is_replaced_in_the_tool_shape(self):
        response = {"stdout": "DEPLOY=%s\nok" % SECRET, "stderr": "", "interrupted": False, "isImage": False}
        out = hooks.handle("post", {"tool_name": "Bash", "tool_response": response}, STORE)
        updated = out["hookSpecificOutput"]["updatedToolOutput"]
        self.assertEqual(set(updated), set(response))
        self.assertEqual(updated["stdout"], "DEPLOY=[securikey:deploy_key]\nok")
        self.assertNotIn(SECRET, json.dumps(out))

    def test_clean_output_is_left_alone(self):
        self.assertIsNone(hooks.handle("post", {"tool_name": "Bash", "cwd": CWD, "tool_response": {"stdout": "ok"}}, STORE))


class KnownFormFilterTest(unittest.TestCase):
    """A hook call searches for the forms that can be in the payload, not for every form."""

    SECRET = "Sec-Ab3dEf9GhIjKlMnOpQrStUv"

    def test_the_forms_that_cannot_be_in_the_payload_are_dropped(self):
        secrets = {"deploy_key": self.SECRET}
        self.assertEqual(hooks._known_for(secrets, {"stdout": "ordinary output"}), [])
        self.assertTrue(hooks._known_for(secrets, {"stdout": "a - in it"}))

    def test_a_secret_in_the_output_is_still_redacted(self):
        response = {"stdout": "DEPLOY=%s\nok" % self.SECRET, "stderr": ""}
        out = hooks.handle("post", {"tool_name": "Bash", "tool_response": response},
                           MemoryStore({"deploy_key": self.SECRET}))
        self.assertEqual(out["hookSpecificOutput"]["updatedToolOutput"]["stdout"],
                         "DEPLOY=[securikey:deploy_key]\nok")


class PromptTest(unittest.TestCase):
    def test_prompt_with_token_is_blocked_and_clean_prompt_passes(self):
        out = hooks.handle("prompt", {"prompt": "use ghp_" + "a1B2c3D4e5" * 4}, STORE)
        self.assertEqual(out["decision"], "block")
        self.assertIn("github", out["reason"])
        self.assertNotIn("a1B2c3D4e5", out["reason"])
        self.assertIsNone(hooks.handle("prompt", {"session_id": "396af541-9e08-45d2-a870-3f8162901d4a",
                                                  "cwd": CWD, "prompt": "fix the login bug"}, STORE))


class KeychainDownTest(unittest.TestCase):
    def test_unreadable_keychain_degrades_to_patterns_and_says_so(self):
        class Down:
            def load(self):
                raise VaultError("keychain unavailable: KeyringLocked")
        out = hooks.handle("pre", bash("ls"), Down())
        self.assertIn("patterns only", out["systemMessage"])
        self.assertNotIn("hookSpecificOutput", out)
        self.assertTrue(denied(hooks.handle("pre", bash("echo AKIA" + "IOSFODNN7EXAMPLE"), Down())))


class DotenvContentTest(unittest.TestCase):
    """Values from the project's .env files are secrets however the file was read: the shell
    can spell a file name in more ways than any name check can follow."""

    VALUE = "s3cr3t-" + "Api-Token-0042"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        (root / ".env").write_text("API_TOKEN=%s\nNODE_ENV=production\nPORT=3000\nREF=securikey:x\n" % self.VALUE)
        (root / "app").mkdir()
        (root / "app" / ".env.local").write_text("DB_PASSWORD=another-" + "Secret-Value-77\n")
        (root / ".env.example").write_text("EXAMPLE_TOKEN=not-a-real-" + "token-value\n")

    def tearDown(self):
        self.tmp.cleanup()

    def post(self, command, stdout):
        event = {"tool_name": "Bash", "cwd": self.tmp.name, "tool_input": {"command": command},
                 "tool_response": {"stdout": stdout, "stderr": "", "interrupted": False, "isImage": False}}
        return hooks.handle("post", event, MemoryStore({}))

    def test_padding_around_a_value_does_not_hide_it_but_inner_spaces_still_do(self):
        padded = "Pad-Token-" + "Ab12Cd34Ef56"
        phrase = "Correct horse 9 battery"
        (Path(self.tmp.name) / "app" / ".env.staging").write_text(
            'PAD_TOKEN=" %s "\nTRAIL_SECRET=%s \nPHRASE_PASSWORD="%s"\n' % (padded, padded + "-2", phrase))
        out = self.post("cat app/.env.staging", "%s | %s | %s" % (padded, padded + "-2", phrase))
        shown = repr(out)
        self.assertNotIn(padded, shown)  # the padded value and the one with a trailing space
        self.assertNotIn(padded + "-2", shown)
        self.assertIsNotNone(out)
        self.assertNotIn("[securikey:dotenv:PHRASE_PASSWORD]", shown)  # a phrase is not registered

    def test_values_are_redacted_whatever_command_read_the_file(self):
        for cmd in ["cat .{e..e}nv", "cat .[E]nv", "cat $(echo .env)", "python3 -c 'print(open(x).read())'"]:
            out = self.post(cmd, "API_TOKEN=%s" % self.VALUE)
            self.assertNotIn(self.VALUE, repr(out), cmd)
            self.assertIn("dotenv:API_TOKEN", out["hookSpecificOutput"]["updatedToolOutput"]["stdout"], cmd)

    def test_nested_files_count_but_examples_and_ordinary_values_do_not(self):
        out = self.post("cat app/x", "DB_PASSWORD=another-" + "Secret-Value-77")
        self.assertNotIn("Secret-Value-77", repr(out))
        self.assertIsNone(self.post("env", "NODE_ENV=production PORT=3000 EXAMPLE_TOKEN=not-a-real-" + "token-value"))

    def assertRedacted(self, out, secret, label):
        self.assertIsNotNone(out, "nothing was redacted")
        self.assertNotIn(secret, repr(out))
        self.assertIn(label, out["hookSpecificOutput"]["updatedToolOutput"]["stdout"])

    def write(self, name, text):
        (Path(self.tmp.name) / name).write_text(text)

    def test_a_malformed_file_is_read_line_by_line(self):
        self.write(".env.broken", 'BROKEN="oops\nDB_PASSWORD=Zk83vLqP2' + 'mRw9Xa\n')
        self.assertRedacted(self.post("cat x", "Zk83vLqP2" + "mRw9Xa"), "Zk83vLqP2mRw9Xa", "dotenv:DB_PASSWORD")

    def test_the_raw_form_of_an_escaped_value_is_redacted_too(self):
        self.write(".env.esc", 'DB_PASSWORD="Qz\\\\Lm9' + 'Rt4Vw8Xc"\n')
        for shown in ("Qz\\\\Lm9" + "Rt4Vw8Xc", "Qz\\Lm9" + "Rt4Vw8Xc"):  # as written, and decoded
            self.assertRedacted(self.post("cat x", "pw " + shown), "Rt4Vw8Xc", "dotenv:DB_PASSWORD")

    def test_the_password_in_a_credential_url_is_redacted(self):
        self.write(".env.db", "DATABASE_URL=postgres://app:Xq7rPz9" + "LmW2kTn@db.internal:5432/app\n")
        out = self.post("cat x", "postgres://app:Xq7rPz9" + "LmW2kTn@db.internal:5432/app")
        self.assertRedacted(out, "LmW2kTn", "dotenv:DATABASE_URL")

    def test_ordinary_values_under_secret_sounding_keys_are_left_alone(self):
        self.write(".env.ops", "SECRET_MODE=production\nAUTH_CALLBACK_URL=http://localhost:3000/callback\n"
                              "API_KEY_NAME=my-key-name\nAUTH_PORT=localhost:8080\n")
        self.assertIsNone(self.post("env", "production http://localhost:3000/callback my-key-name localhost:8080"))
        prompt = {"prompt": "Deploy to production now", "cwd": self.tmp.name}
        self.assertIsNone(hooks.handle("prompt", prompt, MemoryStore({})))

    def test_files_that_cant_be_read_are_reported_not_hung_on(self):
        os.mkfifo(Path(self.tmp.name) / ".env.pipe")
        result = []
        worker = threading.Thread(target=lambda: result.append(self.post("cat x", "API_TOKEN=%s" % self.VALUE)))
        worker.start()
        worker.join(10)
        self.assertFalse(worker.is_alive(), "the hook blocked on a FIFO")
        self.assertNotIn(self.VALUE, repr(result[0]))
        self.assertIn("not a regular file", result[0]["systemMessage"])

    def test_a_file_swapped_for_a_fifo_while_it_is_read_is_reported_not_hung_on(self):
        # The file is a regular file when it is found and a FIFO when it is opened: the race
        # a stat-then-open leaves open. The read must not block on it.
        path = Path(self.tmp.name) / ".env.swap"
        path.write_text("API_TOKEN=%s\n" % self.VALUE)
        real_open = os.open
        swapped = []

        def swap_then_open(target, flags, *args, **kwargs):
            if str(target).endswith(".env.swap") and not swapped:
                swapped.append(True)
                path.unlink()
                os.mkfifo(path)
            return real_open(target, flags, *args, **kwargs)

        result = []
        worker = threading.Thread(target=lambda: result.append(self.post("cat x", "API_TOKEN=%s" % self.VALUE)))
        with mock.patch.object(hooks.os, "open", swap_then_open):
            worker.start()
            worker.join(10)
        self.assertFalse(worker.is_alive(), "the hook blocked on a FIFO")
        self.assertNotIn(self.VALUE, repr(result[0]))
        self.assertIn("not a regular file", result[0]["systemMessage"])

    def test_a_link_to_a_fifo_is_reported_not_hung_on(self):
        fifo = Path(self.tmp.name) / "pipe"
        os.mkfifo(fifo)
        os.symlink(fifo, Path(self.tmp.name) / ".env.link")
        result = []
        worker = threading.Thread(target=lambda: result.append(self.post("cat x", "API_TOKEN=%s" % self.VALUE)))
        worker.start()
        worker.join(10)
        self.assertFalse(worker.is_alive(), "the hook blocked on a FIFO")
        self.assertIn("not a regular file", result[0]["systemMessage"])

    def test_a_url_with_a_port_and_a_path_is_not_a_credential_url(self):
        # `postgres://replica:6333/db/admin@team-db` has no password: the password of a
        # credential URL can't hold a slash (RFC 3986 keeps it out of the userinfo).
        self.write(".env.db", "DATABASE_URL=postgres://replica:6333/db/admin@team-db\n")
        self.assertIsNone(self.post("env", "postgres://replica:6333/db/admin@team-db"))

    def test_a_plain_word_password_in_a_credential_url_is_not_a_secret(self):
        # `password` is a word, not a secret: registering it would deny every call that
        # mentions a password field and block every prompt about changing a password.
        self.write(".env.db", "DATABASE_URL=postgres://app:password@localhost:5432/app\n")
        self.assertIsNone(self.post("env", "postgres://app:password@localhost:5432/app"))
        prompt = {"prompt": "change the password field on the login form", "cwd": self.tmp.name}
        self.assertIsNone(hooks.handle("prompt", prompt, MemoryStore({})))
        event = {"tool_name": "Bash", "cwd": self.tmp.name,
                 "tool_input": {"command": "grep -rn password src/"}}
        self.assertIsNone(hooks.handle("pre", event, MemoryStore({})))

    def test_a_read_error_is_reported_not_treated_as_a_failure(self):
        # An error after the open (a dying mount) is a warning: it must not fail the hook
        # closed, which would deny every later call.
        with mock.patch.object(hooks.os, "read", side_effect=OSError(5, "Input/output error")):
            out = self.post("cat x", "API_TOKEN=%s" % self.VALUE)
        self.assertNotIn("hookSpecificOutput", out)  # the output was not replaced
        self.assertIn("can't be read", out["systemMessage"])

    def test_a_link_out_of_the_session_directory_is_not_read(self):
        with tempfile.TemporaryDirectory() as outside:
            target = Path(outside) / "credentials"
            target.write_text("API_TOKEN=%s\n" % self.VALUE)
            os.symlink(target, Path(self.tmp.name) / ".env.link")
            out = self.post("cat x", "API_TOKEN=%s" % self.VALUE)
        self.assertNotIn(self.VALUE, repr(out))
        self.assertIn("link out of the session's directory", out["systemMessage"])

    def test_the_budget_warning_is_reported_once(self):
        self.write(".env.big", "API_SECRET=Big7" + "Secret9Value\n" + "#" * 400)
        with mock.patch.object(hooks, "MAX_DOTENV_BYTES", 100), mock.patch.object(hooks, "DOTENV_MAX_TOTAL_BYTES", 100):
            out = self.post("cat x", "Big7" + "Secret9Value")
        self.assertEqual(out["systemMessage"].count("only the first"), 1)
        self.assertIn("only the first 100 bytes", out["systemMessage"])

    def test_a_name_the_plain_pattern_misses_is_still_read(self):
        self.write(".env.prod~", "DB_PASSWORD=Mi55" + "ingValue77\n")
        self.assertRedacted(self.post("cat x", "Mi55" + "ingValue77"), "Mi55" + "ingValue77", "dotenv:DB_PASSWORD")

    def test_the_number_of_registered_secrets_is_bounded(self):
        # A file full of small secret-shaped values would register hundreds of thousands of
        # secrets, and the forms built from them would blow the hook's timeout: the count is
        # capped, shared between the files, and the cap is said. Only the first 1000 lines of a
        # file are parsed, so the 20000 lines here count as 1000.
        lines = "".join("KEY%05d_SECRET=Ab%05dValue1\n" % (n, n) for n in range(20000))
        self.write(".env.local", lines)  # a usual name: an unusual one is held to a quarter of the cap
        secrets, problems = hooks.project_dotenv_secrets({"cwd": self.tmp.name})
        self.assertEqual(len(secrets), hooks.DOTENV_MAX_SECRETS)
        self.assertIn("of 1000 secrets from .env.local were checked", " | ".join(problems))
        out = self.post("cat x", "Ab00000Value1")  # the values that were registered still count
        self.assertIn("dotenv:KEY00000_SECRET", out["hookSpecificOutput"]["updatedToolOutput"]["stdout"])

    def test_the_forms_built_from_dotenv_secrets_are_bounded(self):
        # The hook's cost per call is the forms it builds from the registered secrets: the
        # cap on the secrets is what bounds the forms, and with them every later search.
        lines = "".join("KEY%05d_SECRET=Ab%05dValue1\n" % (n, n) for n in range(20000))
        self.write(".env.local", lines)
        payload = {"stdout": "some ordinary output"}
        secrets, _ = hooks.project_dotenv_secrets({"cwd": self.tmp.name})
        self.assertEqual(len(secrets), hooks.DOTENV_MAX_SECRETS)
        self.assertLessEqual(len(hooks._known_for(secrets, payload)), 3 * hooks.DOTENV_MAX_SECRETS)

    def test_a_file_swapped_for_a_link_while_it_is_read_is_not_followed(self):
        # The link is resolved and judged (it points inside the session's directory), and the
        # resolved file is then swapped for a link out of it before the open: the open does not
        # follow a link in the final name, so the outside file is not read.
        inside = Path(self.tmp.name) / "inside.env"
        inside.write_text("API_TOKEN=%s\n" % self.VALUE)
        with tempfile.TemporaryDirectory() as outside:
            target = Path(outside) / "credentials"
            target.write_text("OUTSIDE_TOKEN=Ab3dEf9GhIjKlMnOpQrStUvWx\n")
            os.symlink(inside, Path(self.tmp.name) / ".env.link")
            real_open = os.open
            swapped = []

            def swap(target_, flags, *args, **kwargs):
                if str(target_).endswith("inside.env") and not swapped:
                    swapped.append(True)
                    inside.unlink()
                    os.symlink(target, inside)
                return real_open(target_, flags, *args, **kwargs)

            with mock.patch.object(hooks.os, "open", swap):
                secrets, problems = hooks.project_dotenv_secrets({"cwd": self.tmp.name})
        self.assertNotIn("OUTSIDE_TOKEN", repr(secrets))
        self.assertTrue(any(".env.link can't be read" in p for p in problems), problems)

    def test_a_file_that_cannot_be_inspected_is_skipped_not_trusted(self):
        real_stat = os.stat

        def no_stat(path, *args, **kwargs):
            if str(path).endswith(".env.flaky"):
                raise OSError("gone")
            return real_stat(path, *args, **kwargs)

        self.write(".env.flaky", "OTHER_TOKEN=Fl4k" + "yValue9988\n")
        with mock.patch.object(hooks.os, "stat", no_stat):
            secrets, problems = hooks.project_dotenv_secrets({"cwd": self.tmp.name})
        self.assertNotIn("Fl4kyValue9988", repr(secrets))
        self.assertTrue(any(".env.flaky can't be read" in p for p in problems), problems)
        self.assertIn(self.VALUE, secrets.values())  # the other files are still read

    def test_a_file_separated_by_carriage_returns_is_bounded_by_lines_too(self):
        lines = "\r".join("A%d=1" % n for n in range(10)) + "\rLATE_SECRET=La7e" + "Secret4455"
        self.write(".env.cr", lines)
        with mock.patch.object(hooks, "DOTENV_MAX_LINES", 10):
            secrets, problems = hooks.project_dotenv_secrets({"cwd": self.tmp.name})
        self.assertNotIn("La7eSecret4455", secrets.values())
        self.assertIn(".env.cr has over 10 lines", " | ".join(problems))

    def test_a_file_with_many_lines_is_parsed_only_to_the_line_limit(self):
        lines = "".join("A%d=1\n" % n for n in range(10)) + "LATE_SECRET=La7e" + "Secret4455\n"
        self.write(".env.long", lines)
        with mock.patch.object(hooks, "DOTENV_MAX_LINES", 10):
            secrets, problems = hooks.project_dotenv_secrets({"cwd": self.tmp.name})
        self.assertNotIn("La7eSecret4455", secrets.values())
        self.assertIn(".env.long has over 10 lines", " | ".join(problems))

    def test_a_full_root_env_cannot_crowd_out_a_deeper_file(self):
        # A planted root file with hundreds of secret-shaped values used to fill the cap
        # and stop the scan before the user's own app/.env.local was read.
        (Path(self.tmp.name) / ".env").write_text(
            "".join("KEY%04d_SECRET=Ab%04dValue1\n" % (n, n) for n in range(hooks.DOTENV_MAX_SECRETS + 10)))
        self.write("app/.env.local", "REAL_TOKEN=Re4l" + "Token9Value\n")
        secrets, problems = hooks.project_dotenv_secrets({"cwd": self.tmp.name})
        self.assertIn("Re4lToken9Value", secrets.values())
        self.assertLessEqual(len(secrets), hooks.DOTENV_MAX_SECRETS)
        self.assertIn("secrets from .env were checked", " | ".join(problems))

    def test_fair_shares_split_the_cap_and_hand_on_what_a_small_file_leaves(self):
        self.assertEqual(hooks._fair_shares([1000, 3, 1000], 100), [48, 3, 49])
        self.assertEqual(hooks._fair_shares([5, 5], 100), [5, 5])
        self.assertEqual(hooks._fair_shares([], 100), [])

    def test_unusual_names_are_held_to_a_quarter_of_the_cap(self):
        self.assertEqual(hooks._ranked_shares([True, False, False], [40, 40, 40], 60), [40, 7, 8])
        # The ceiling holds even when the usual names ask for little: decoys can't soak up the rest.
        self.assertEqual(hooks._ranked_shares([True, False, False], [10, 1000, 1000], 500), [10, 62, 63])
        self.assertEqual(hooks._ranked_shares([True, True, False], [100, 100, 5], 100), [47, 48, 5])
        self.assertEqual(hooks._ranked_shares([False, False], [3, 3], 100), [3, 3])
        self.assertEqual(hooks._ranked_shares([], [], 100), [])

    def test_many_usual_names_cannot_starve_an_unusual_one(self):
        # Nested `.env.local` files with many values beside a root `.env.prod` with a few.
        for n in range(10):
            (Path(self.tmp.name) / ("d%d" % n)).mkdir()
            self.write("d%d/.env.local" % n, "".join("N%d_%03d_SECRET=Ab%dVal%03dX\n" % (n, i, n, i) for i in range(100)))
        self.write(".env.prod", "PROD_SECRET=Pr0d" + "Secret9Value\n")
        secrets, _ = hooks.project_dotenv_secrets({"cwd": self.tmp.name})
        self.assertIn("Pr0dSecret9Value", secrets.values())
        self.assertLessEqual(len(secrets), hooks.DOTENV_MAX_SECRETS)

    def test_decoy_floors_leave_a_big_usual_name_three_quarters_of_the_cap(self):
        self.write(".env", "".join("B%03d_SECRET=Qx%03dValue7\n" % (i, i) for i in range(400)))
        for n in range(40):
            self.write(".env.a%02d" % n, "".join("K%d_SECRET=Ab%dVal%02dX\n" % (i, i, n) for i in range(20)))
        secrets, _ = hooks.project_dotenv_secrets({"cwd": self.tmp.name})
        # The other usual file (app/.env.local) holds one value, which is the one that is left over.
        self.assertGreaterEqual(sum(1 for k in secrets if k.startswith("dotenv:B")), hooks.DOTENV_MAX_SECRETS * 3 // 4 - 1)

    def test_decoys_cannot_cut_the_coverage_of_a_usual_name(self):
        for n in range(hooks.DOTENV_MAX_FILES - 2):
            self.write(".env.a%02d" % n, "".join("K%d_SECRET=Ab%dVal%02dX\n" % (i, i, n) for i in range(20)))
        self.write(".env.local", "".join("L%02d_SECRET=Lo%02dValue7\n" % (i, i) for i in range(40)))
        secrets, _ = hooks.project_dotenv_secrets({"cwd": self.tmp.name})
        self.assertEqual(sum(1 for k in secrets if k.startswith("dotenv:L")), 40)

    def test_the_walk_keeps_only_the_top_ranked_files(self):
        for n in range(hooks.DOTENV_MAX_FILES + 20):
            self.write(".env.a%03d" % n, "NOTE=decoy\n")
        problems = []
        found = hooks._dotenv_files(self.tmp.name, problems)
        self.assertEqual(len(found), hooks.DOTENV_MAX_FILES)
        self.assertEqual(found[0], Path(self.tmp.name) / ".env")
        self.assertIn("only the first %d of " % hooks.DOTENV_MAX_FILES, " | ".join(problems))

    def test_a_placeholder_password_in_a_credential_url_is_not_a_secret(self):
        # These pass the shape gate (a digit, or mixed case), but they are the placeholders
        # every tutorial uses: registering one would deny every call that mentions it.
        for password in ("passw0rd", "admin123", "ChangeMe"):
            self.write(".env.db", "DATABASE_URL=postgres://app:%s@localhost:5432/app\n" % password)
            prompt = {"prompt": "the %s login does not work" % password, "cwd": self.tmp.name}
            self.assertIsNone(hooks.handle("prompt", prompt, MemoryStore({})), password)

    def test_the_byte_budget_stops_the_read_instead_of_overshooting_it(self):
        budget = 100
        root = Path(self.tmp.name) / ".env"
        spent = root.stat().st_size
        value = "Past9" + "TheBudget"
        self.write(".env.zzz", "NOTE=" + "x" * (budget - spent + 50) + "\nAPI_SECRET=%s\n" % value)
        with mock.patch.object(hooks, "DOTENV_MAX_TOTAL_BYTES", budget):
            out = self.post("cat x", value)
        # The value is past the budget, so it was not read: the read stops at the budget
        # instead of overshooting it by a whole file.
        self.assertNotIn("hookSpecificOutput", out)  # nothing was redacted
        self.assertIn("only the first", out["systemMessage"])

    def test_a_big_file_and_the_walk_limit_are_reported(self):
        self.write(".env.big", "API_SECRET=Big7" + "Secret9Value\n" + "#" * 400)
        for d in range(4):
            (Path(self.tmp.name) / ("d%d" % d)).mkdir()
        with mock.patch.object(hooks, "MAX_DOTENV_BYTES", 100), mock.patch.object(hooks, "DOTENV_MAX_DIRS", 2):
            out = self.post("cat x", "Big7" + "Secret9Value")
        self.assertNotIn("Secret9Value", repr(out))  # the start of the file was still read
        self.assertIn("only its start was read", out["systemMessage"])
        self.assertIn("stopped after 2 folders", out["systemMessage"])

    def test_an_unclosed_quote_costs_one_pass_not_one_per_line(self):
        # The hook cuts a file at DOTENV_MAX_LINES before parsing, so the parser is timed directly.
        text = 'NOTE="\n' + "line text\n" * 20000
        started = time.monotonic()
        dotenv.parse_dotenv(text)
        self.assertLess(time.monotonic() - started, 3.0)

    def test_a_quoted_value_cut_at_the_line_limit_keeps_the_lines_before_it(self):
        first = "Ea7ly" + "Secret4455"
        text = "EARLY_SECRET=%s\n" % first + "A=1\n" * 3 + 'QUOTED="line one\nLATE_TOKEN=La7e' + 'Value9988\nend"\n'
        self.write(".env.cut", text)
        with mock.patch.object(hooks, "DOTENV_MAX_LINES", 5):
            out = self.post("cat x", first)
        self.assertRedacted(out, first, "dotenv:EARLY_SECRET")
        self.assertIn(".env.cut has over 5 lines", out["systemMessage"])

    def test_tv_run_on_a_fifo_is_denied_not_hung_on(self):
        fifo = Path(self.tmp.name) / "pipe"
        os.mkfifo(fifo)
        result = []
        event = {"tool_name": "Bash", "cwd": self.tmp.name, "tool_input": {"command": "skey run --dotenv %s -- true" % fifo}}
        worker = threading.Thread(target=lambda: result.append(hooks.handle("pre", event, MemoryStore({}))))
        worker.start()
        worker.join(10)
        self.assertFalse(worker.is_alive(), "the hook blocked on a FIFO")
        self.assertTrue(denied(result[0]))

    def test_paths_and_lowercase_identifiers_are_not_secrets(self):
        self.write(".env.paths", "AUTH_CALLBACK=/api/v1/callback\nSECRET_DIR=./certs/dev\nAPI_TOKEN_KIND=my_secret_value\n")
        prompt = {"prompt": "callback is /api/v1/callback, certs in ./certs/dev, kind my_secret_value", "cwd": self.tmp.name}
        self.assertIsNone(hooks.handle("prompt", prompt, MemoryStore({})))

    def test_a_multi_line_quoted_value_is_redacted_in_its_raw_form(self):
        # A multi-line value counts when it matches a token pattern (a key with a note
        # after it, say); its raw form, escapes and all, must be matched as written.
        key = "sk-ant-" + "Ab1cd" * 6
        self.write(".env.multi", 'API_SECRET="%s\\"note\nEf2gh-Zq9"\n' % key)
        self.assertRedacted(self.post("cat x", '%s\\"note\nEf2gh-Zq9' % key), "Ef2gh-Zq9", "dotenv:API_SECRET")

    def test_a_slash_led_one_segment_value_is_still_a_secret(self):
        value = "/Ab3dEf9Gh" + "IjKlMnOpQrStUvWxYz0123"
        self.write(".env.slash", "SESSION_SECRET=%s\n" % value)
        self.assertRedacted(self.post("cat x", "secret " + value), value, "dotenv:SESSION_SECRET")
        trailing = "/Qz7xWv" + "Mn3KpL9Rt2Ys8/"  # one segment and a trailing slash is still not a path
        self.write(".env.slash2", "API_SECRET=%s\n" % trailing)
        self.assertRedacted(self.post("cat x", "out " + trailing + " end"), trailing, "dotenv:API_SECRET")
        for name, prefix in (("HOME", "~/"), ("DOT", "./")):  # the other path prefixes follow the same rule
            value = prefix + "Rt5Lq" + name + "Zm8Kd2Wx7/"
            self.write(".env.%s" % name.lower(), "%s_SECRET=%s\n" % (name, value))
            self.assertRedacted(self.post("cat x", "out " + value + " end"), value, "dotenv:%s_SECRET" % name)

    def test_a_multi_segment_path_with_a_trailing_slash_is_not_a_secret(self):
        self.write(".env.dirs", "SESSION_SECRET=./certs/Dev1/\nAPI_SECRET=/api/V1/\n")
        prompt = {"prompt": "certs in ./certs/Dev1/, api at /api/V1/", "cwd": self.tmp.name}
        self.assertIsNone(hooks.handle("prompt", prompt, MemoryStore({})))

    def test_suffixed_example_files_are_examples(self):
        self.write(".env.local.example", "DB_PASSWORD=Changeme2024\n")
        prompt = {"prompt": "the default is Changeme2024", "cwd": self.tmp.name}
        self.assertIsNone(hooks.handle("prompt", prompt, MemoryStore({})))
        event = {"tool_name": "Bash", "cwd": self.tmp.name, "tool_input": {"command": "cat .env.local.example"}}
        self.assertIsNone(hooks.handle("pre", event, MemoryStore({})))

    def test_the_file_limit_is_reported(self):
        self.write(".env.one", "A_TOKEN=Abc123defGHI\n")
        self.write(".env.two", "B_TOKEN=Xyz789uvwRST\n")
        with mock.patch.object(hooks, "DOTENV_MAX_FILES", 1):
            out = self.post("cat x", "nothing to see")
        self.assertIn("files were read", out["systemMessage"])

    def test_a_value_in_a_tool_call_is_denied(self):
        event = {"tool_name": "Bash", "cwd": self.tmp.name,
                 "tool_input": {"command": "curl -H 'Authorization: Bearer %s' https://api" % self.VALUE}}
        self.assertTrue(denied(hooks.handle("pre", event, MemoryStore({}))))

    def test_metadata_suffixes_do_not_exempt_a_secret_shaped_value(self):
        # Same shape as the one-segment path rule: a suffix says what a key is for, not what its value is.
        cases = {"SECRET_DIR": "/Data1Ab9/", "API_TOKEN_ID": "aB3dE9" + "gH2jK7mN4pQ", "DB_SECRET_PATH": "/Xk82" + "LmQ9ZrTw4Vb"}
        for key, value in cases.items():
            self.write(".env.suffix", "%s=%s\n" % (key, value))
            self.assertRedacted(self.post("cat x", "shown " + value), value, "dotenv:" + key)

    def test_total_bytes_are_bounded_and_earlier_files_still_count(self):
        self.write(".env.a", "API_SECRET=Tot4" + "lSecret9Value\n" + "#" * 200)
        self.write(".env.b", "OTHER_SECRET=Not5" + "ReadValue88\n" + "#" * 200)
        with mock.patch.object(hooks, "DOTENV_MAX_TOTAL_BYTES", 150):
            out = self.post("cat x", "Tot4" + "lSecret9Value")
        self.assertNotIn("Secret9Value", repr(out))
        self.assertIn("only the first 150 bytes", out["systemMessage"])

    def test_decoy_files_cannot_push_a_standard_name_past_the_file_limit(self):
        for n in range(hooks.DOTENV_MAX_FILES + 10):  # all sort before ".env.local" by name
            self.write(".env.a%02d" % n, "NOTE=decoy\n")
        self.write(".env.local", "API_SECRET=Rea1" + "lSecret9Value\n")
        out = self.post("cat x", "Rea1" + "lSecret9Value")
        self.assertRedacted(out, "Secret9Value", "dotenv:API_SECRET")
        self.assertIn("only the first", out["systemMessage"])

    def test_case_variant_decoys_do_not_tie_with_a_standard_name(self):
        # A listing is faked: a case-insensitive filesystem (macOS) can't hold these as distinct files.
        variants = sorted({"".join(c.upper() if mask >> i & 1 else c for i, c in enumerate(".env.local"))
                           for mask in range(1, 1 << 9)})[:hooks.DOTENV_MAX_FILES + 10]
        listing = [(self.tmp.name, [], variants + [".env.production"])]
        with mock.patch.object(hooks.os, "walk", return_value=iter(listing)):
            found = hooks._dotenv_files(self.tmp.name, [])
        self.assertIn(Path(self.tmp.name) / ".env.production", found)
        self.assertEqual(len(found), hooks.DOTENV_MAX_FILES)

    def test_a_big_decoy_cannot_use_up_the_byte_budget_before_a_standard_name(self):
        self.write(".env.a-decoy", "NOTE=" + "x" * 300 + "\n")  # sorts before .env.local by name
        self.write(".env.local", "API_SECRET=Loc1" + "alSecret9Value\n")
        with mock.patch.object(hooks, "DOTENV_MAX_TOTAL_BYTES", 100):
            out = self.post("cat x", "Loc1" + "alSecret9Value")
        self.assertRedacted(out, "Secret9Value", "dotenv:API_SECRET")

    def test_the_byte_limit_drops_the_deepest_files_first(self):
        with mock.patch.object(hooks, "DOTENV_MAX_TOTAL_BYTES", 50):
            out = self.post("cat x", "API_TOKEN=%s" % self.VALUE)  # the root file is read first
        self.assertRedacted(out, self.VALUE, "dotenv:API_TOKEN")
        self.assertNotIn("Secret-Value-77", out["systemMessage"])
        self.assertIn("only the first", out["systemMessage"])


class WarningMergeTest(unittest.TestCase):
    def test_a_store_warning_does_not_replace_the_failure_message(self):
        class Down:
            def load(self):
                raise VaultError("keychain unavailable: KeyringLocked")

        def broken(event, secrets):
            raise RuntimeError("boom")

        event = {"tool_name": "Bash", "tool_input": {"command": "ls"}, "tool_response": {"stdout": "x"}}
        with mock.patch.dict(hooks.HANDLERS, {"post": broken}):
            out = hooks.handle("post", event, Down())
        self.assertIn("replaced rather than redacted", out["systemMessage"])
        self.assertIn("patterns only", out["systemMessage"])

    def test_a_missing_or_unusable_cwd_is_reported_not_silent(self):
        for event in ({}, {"cwd": ""}, {"cwd": "/no/such/folder/for/the/scan"}):
            secrets, problems = hooks.project_dotenv_secrets(event)
            self.assertEqual(secrets, {})
            self.assertIn("no readable working directory", " ".join(problems), event)
        with mock.patch.object(Path, "resolve", side_effect=OSError):
            _, problems = hooks.project_dotenv_secrets({"cwd": CWD})
        self.assertIn("can't be resolved", " ".join(problems))
        out = hooks.handle("post", {"tool_name": "Bash", "tool_response": {"stdout": "ok"}}, STORE)
        self.assertIn("no .env file was searched", out["systemMessage"])

    def test_problems_past_the_shown_limit_are_counted(self):
        def seven(event):
            return {}, ["problem %d" % n for n in range(7)]

        event = {"tool_name": "Bash", "tool_input": {"command": "ls"}, "tool_response": {"stdout": "x"}}
        with mock.patch.object(hooks, "project_dotenv_secrets", seven):
            out = hooks.handle("post", event, MemoryStore({}))
        self.assertIn("problem 4; and 2 more", out["systemMessage"])
        self.assertNotIn("problem 5", out["systemMessage"])


if __name__ == "__main__":
    unittest.main()
