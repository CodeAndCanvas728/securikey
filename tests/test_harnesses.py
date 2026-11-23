import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

try:
    import tomllib
except ImportError:  # Python 3.10
    tomllib = None

from securikey import cli, harnesses
from securikey.store import MemoryStore, VaultError

UV = "/opt/bin/uv"
SKEY = "/home/me/.local/bin/skey"


class SetupTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.env = {"HOME": str(root), "VIBE_HOME": str(root / "vibe"), "PI_CODING_AGENT_DIR": str(root / "pi"),
                    "OPENCODE_CONFIG_DIR": str(root / "oc")}
        patcher = mock.patch.multiple(harnesses, uv_path=lambda: UV, skey_path=lambda: SKEY)
        patcher.start()
        self.addCleanup(patcher.stop)

    def install(self, harness):
        return harnesses.install(harness, self.env)

    def test_homes_follow_the_environment(self):
        self.assertEqual(harnesses.harness_home("vibe", {"HOME": "/h"}), Path("/h/.vibe"))
        self.assertEqual(harnesses.harness_home("pi", {"HOME": "/h"}), Path("/h/.pi/agent"))
        self.assertEqual(harnesses.harness_home("opencode", {"HOME": "/h"}), Path("/h/.config/opencode"))
        self.assertEqual(harnesses.harness_home("opencode", {"HOME": "/h", "XDG_CONFIG_HOME": "/x"}),
                         Path("/x/opencode"))
        self.assertEqual(harnesses.harness_home("vibe", {"VIBE_HOME": "/v"}), Path("/v"))

    def test_vibe_plugin_files(self):
        paths = self.install("vibe")
        root = Path(self.env["VIBE_HOME"]) / "plugins" / "securikey"
        self.assertEqual(paths, sorted([root / "plugin.json", root / "ai.mistral.vibe" / "hooks.toml"]))
        manifest = json.loads((root / "plugin.json").read_text())
        self.assertEqual(manifest["name"], "securikey")
        self.assertEqual(manifest["extensions"], {"ai.mistral.vibe": {"schemaVersion": 1}})
        self.assertTrue(manifest["$schema"].startswith("https://agent-plugins.org/schemas/"))

    @unittest.skipIf(tomllib is None, "tomllib needs Python 3.11")
    def test_vibe_hooks_are_strict_and_cover_tools_and_prompts(self):
        self.install("vibe")
        text = (Path(self.env["VIBE_HOME"]) / "plugins" / "securikey" / "ai.mistral.vibe" / "hooks.toml").read_text()
        hooks = {h["name"]: h for h in tomllib.loads(text)["hooks"]}
        self.assertEqual({n: h["type"] for n, h in hooks.items()},
                         {"pre": "pre_tool", "post": "post_tool", "prompt": "pre_agent"})
        for hook in hooks.values():
            self.assertTrue(hook["strict"])
            self.assertEqual(hook["timeout"], harnesses.HOOK_TIMEOUT_S)
        self.assertEqual(hooks["pre"]["match"], "*")
        self.assertEqual(hooks["post"]["match"], "*")
        self.assertEqual(hooks["pre"]["command"], "%s run --quiet --script %s hook pre --host vibe" % (UV, SKEY))

    @unittest.skipIf(tomllib is None, "tomllib needs Python 3.11")
    def test_a_path_with_a_space_survives_in_the_command(self):
        with mock.patch.multiple(harnesses, skey_path=lambda: "/Users/a b/it's/skey"):
            self.install("vibe")
        text = (Path(self.env["VIBE_HOME"]) / "plugins" / "securikey" / "ai.mistral.vibe" / "hooks.toml").read_text()
        command = tomllib.loads(text)["hooks"][0]["command"]
        import shlex
        self.assertIn("/Users/a b/it's/skey", shlex.split(command))

    def test_pi_and_opencode_get_their_paths_filled_in(self):
        pi = self.install("pi")[0]
        self.assertEqual(pi, Path(self.env["PI_CODING_AGENT_DIR"]) / "extensions" / "securikey.ts")
        text = pi.read_text()
        self.assertIn('const UV = "%s";' % UV, text)
        self.assertIn('const SKEY = "%s";' % SKEY, text)
        self.assertNotIn("@@", text)
        oc = self.install("opencode")[0]
        self.assertEqual(oc, Path(self.env["OPENCODE_CONFIG_DIR"]) / "plugins" / "securikey.ts")
        self.assertIn("export default {", oc.read_text())

    def test_a_quote_in_a_path_is_escaped_in_typescript(self):
        with mock.patch.multiple(harnesses, skey_path=lambda: '/a"b\\c/skey'):
            text = self.install("pi")[0].read_text()
        self.assertIn(r'const SKEY = "/a\"b\\c/skey";', text)

    def test_every_shim_fails_closed_and_honours_the_bypass(self):
        for name in ("pi", "opencode"):
            source = (harnesses.PLUGIN_ROOT / "harness" / name / "securikey.ts").read_text()
            with self.subTest(name):
                self.assertIn(harnesses.MARKER, source.splitlines()[0])
                self.assertIn("SECURIKEY_HOST_BYPASS", source)
                self.assertIn("was not judged", source)
                self.assertIn("withheld", source.lower())

    def test_a_vibe_plugin_json_that_is_not_ours_is_not_overwritten(self):
        target = Path(self.env["VIBE_HOME"]) / "plugins" / "securikey" / "plugin.json"
        target.parent.mkdir(parents=True)
        target.write_text("{}\n")
        with self.assertRaises(VaultError):
            self.install("vibe")
        self.assertEqual(target.read_text(), "{}\n")

    @unittest.skipIf(tomllib is None, "tomllib needs Python 3.11")
    def test_a_path_outside_the_basic_multilingual_plane_still_parses(self):
        with mock.patch.multiple(harnesses, skey_path=lambda: "/Users/\U0001F510/skey"):
            self.install("vibe")
        text = (Path(self.env["VIBE_HOME"]) / "plugins" / "securikey" / "ai.mistral.vibe" / "hooks.toml").read_text(
            encoding="utf-8")
        self.assertIn("/Users/\U0001F510/skey", tomllib.loads(text)["hooks"][0]["command"])

    def test_the_opencode_prompt_is_not_judged_as_empty_when_the_text_is_missing(self):
        source = (harnesses.PLUGIN_ROOT / "harness" / "opencode" / "securikey.ts").read_text()
        self.assertNotIn('prompt?.text ?? ""', source)

    def test_install_is_repeatable(self):
        first = self.install("pi")
        self.assertEqual(self.install("pi"), first)

    def test_install_refuses_to_overwrite_a_file_it_did_not_write(self):
        target = Path(self.env["PI_CODING_AGENT_DIR"]) / "extensions" / "securikey.ts"
        target.parent.mkdir(parents=True)
        target.write_text("// mine\n")
        with self.assertRaises(VaultError):
            self.install("pi")
        self.assertEqual(target.read_text(), "// mine\n")

    def test_remove_deletes_what_install_wrote(self):
        for harness in ("vibe", "pi", "opencode"):
            with self.subTest(harness):
                written = self.install(harness)
                self.assertEqual(harnesses.remove(harness, self.env), written)
                self.assertFalse(any(p.exists() for p in written))
        self.assertFalse((Path(self.env["VIBE_HOME"]) / "plugins" / "securikey").exists())
        # The shared folders stay.
        self.assertTrue((Path(self.env["PI_CODING_AGENT_DIR"]) / "extensions").is_dir())

    def test_remove_leaves_a_file_it_did_not_write(self):
        target = Path(self.env["OPENCODE_CONFIG_DIR"]) / "plugins" / "securikey.ts"
        target.parent.mkdir(parents=True)
        target.write_text("// mine\n")
        with self.assertRaises(VaultError):
            harnesses.remove("opencode", self.env)
        self.assertTrue(target.exists())

    def test_remove_when_nothing_is_installed(self):
        self.assertEqual(harnesses.remove("vibe", self.env), [])


class SkeyPathTest(unittest.TestCase):
    def test_a_path_in_the_plugin_cache_is_refused(self):
        cached = Path("/home/me/.claude/plugins/cache/codeandcanvas/securikey/3.3.0")
        with mock.patch.object(harnesses, "PLUGIN_ROOT", cached), \
                mock.patch.object(harnesses.shutil, "which", return_value=None):
            with self.assertRaises(VaultError) as raised:
                harnesses.skey_path()
        self.assertIn("plugin cache", str(raised.exception))

    def test_the_link_on_path_is_kept_when_it_points_here(self):
        with tempfile.TemporaryDirectory() as tmp:
            link = Path(tmp) / "skey"
            link.symlink_to(harnesses.PLUGIN_ROOT / "bin" / "skey")
            with mock.patch.object(harnesses.shutil, "which", return_value=str(link)):
                self.assertEqual(harnesses.skey_path(), str(link))

    def test_the_checkout_is_used_without_a_link(self):
        with mock.patch.object(harnesses.shutil, "which", return_value=None):
            self.assertEqual(harnesses.skey_path(), str(harnesses.PLUGIN_ROOT / "bin" / "skey"))


class CommandTest(unittest.TestCase):
    def run_setup(self, *argv, terminal=True):
        args = SimpleNamespace(harness=argv[0], remove="--remove" in argv)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(cli, "_at_terminal", return_value=terminal), \
                redirect_stdout(out), redirect_stderr(err):
            try:
                cli.cmd_setup(args, MemoryStore({}))
            except VaultError as exc:
                return str(exc), out.getvalue()
        return None, out.getvalue()

    def test_it_runs_only_from_a_terminal(self):
        error, _ = self.run_setup("pi", terminal=False)
        self.assertIn("only from your own terminal", error or "")
        error, _ = self.run_setup("pi", "--remove", terminal=False)
        self.assertIn("only from your own terminal", error or "")

    def test_install_and_remove_report_what_they_did(self):
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict("os.environ", {"PI_CODING_AGENT_DIR": tmp}), \
                mock.patch.multiple(harnesses, uv_path=lambda: UV, skey_path=lambda: SKEY):
            error, out = self.run_setup("pi")
            self.assertIsNone(error)
            self.assertIn("securikey.ts", out)
            self.assertIn("SECURIKEY_HOST_BYPASS=1", out)
            error, out = self.run_setup("pi", "--remove")
            self.assertIn("removed", out)


if __name__ == "__main__":
    unittest.main()
