"""Manifest checks that need only the standard library, so CI can run them without the `claude` CLI.

`claude plugin validate plugin --profile directory` is the full check; this covers what a
rename or a release most often breaks.
"""
import json
import os
import re
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "plugin"
ICON_MIN, ICON_MAX, ICON_MAX_BYTES = 512, 2048, 2 * 1024 * 1024  # the plugin directory's limits


def load(path):
    return json.loads(path.read_text())


class PluginManifestTest(unittest.TestCase):
    def setUp(self):
        self.manifest = load(PLUGIN / ".claude-plugin" / "plugin.json")

    def test_required_fields_are_present(self):
        for field in ("name", "displayName", "version", "description", "repository", "homepage", "license", "icon"):
            self.assertTrue(self.manifest.get(field), field)
        self.assertTrue(self.manifest["author"].get("name") and self.manifest["author"].get("url"))

    def test_name_matches_the_package_the_skill_and_the_marketplace_entry(self):
        name = self.manifest["name"]
        self.assertTrue((PLUGIN / name).is_dir())
        self.assertTrue((PLUGIN / "skills" / name / "SKILL.md").is_file())
        entries = load(ROOT / ".claude-plugin" / "marketplace.json")["plugins"]
        self.assertEqual([e["name"] for e in entries], [name])
        self.assertTrue(all(e.get("description") for e in entries))

    def test_marketplace_has_a_description(self):
        self.assertTrue(load(ROOT / ".claude-plugin" / "marketplace.json").get("description"))

    def test_version_is_the_newest_changelog_entry(self):
        match = re.search(r"^## \[(\d+\.\d+\.\d+)\]", (ROOT / "CHANGELOG.md").read_text(), re.M)
        self.assertEqual(match.group(1), self.manifest["version"])

    def test_icon_is_a_square_png_within_the_directory_limits(self):
        icon = PLUGIN / self.manifest["icon"]
        data = icon.read_bytes()
        self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
        width, height = struct.unpack(">II", data[16:24])
        self.assertEqual(width, height)
        self.assertTrue(ICON_MIN <= width <= ICON_MAX, width)
        self.assertLess(len(data), ICON_MAX_BYTES)


class HooksManifestTest(unittest.TestCase):
    def test_every_hook_runs_an_existing_executable_script(self):
        hooks = load(PLUGIN / "hooks" / "hooks.json")["hooks"]
        scripts = set()
        for groups in hooks.values():
            for group in groups:
                for hook in group["hooks"]:
                    scripts.update(a for a in hook["args"] if a.startswith("${CLAUDE_PLUGIN_ROOT}/"))
        self.assertEqual(scripts, {"${CLAUDE_PLUGIN_ROOT}/bin/skey"})
        script = PLUGIN / "bin" / "skey"
        self.assertTrue(os.access(script, os.X_OK))

    def test_the_input_and_prompt_hooks_fail_closed(self):
        hooks = load(PLUGIN / "hooks" / "hooks.json")["hooks"]
        for event in ("PreToolUse", "PostToolUse", "PostToolUseFailure", "UserPromptSubmit"):
            for group in hooks[event]:
                for hook in group["hooks"]:
                    self.assertEqual(hook.get("onFailure"), "block", event)


if __name__ == "__main__":
    unittest.main()
