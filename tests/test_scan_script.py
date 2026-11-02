import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scan_all_git_repos.sh"
FAKE_SKEY = """#!/bin/sh
echo "$@" >> "$SKEY_LOG"
case "$*" in *--dry-run*) exit 0 ;; esac
exit 1  # a failed import leaves the backup on disk, so its mode can be checked
"""


class ScanScriptTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        for name in (".env", ".env.local", ".env.example", ".env.local.example", ".env.sample"):
            (self.repo / name).write_text("API_TOKEN=x\n")
            os.chmod(self.repo / name, 0o644)
        self.skey = self.root / "skey"
        self.skey.write_text(FAKE_SKEY)
        self.skey.chmod(0o755)
        self.log = self.root / "skey.log"
        # A cp shim records the mode of each copy the moment it exists, which is
        # the window `cp -p` + `chmod` left open (the copy briefly had the original mode).
        self.shim = self.root / "shim"
        self.shim.mkdir()
        cp = self.shim / "cp"
        cp.write_text("#!/bin/sh\n/bin/cp \"$@\" || exit $?\nfor last; do :; done\n"
                      "python3 -c 'import os,sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o777))' \"$last\" >> \"$CP_LOG\"\n")
        cp.chmod(0o755)
        self.cp_log = self.root / "cp.log"

    def tearDown(self):
        self.tmp.cleanup()

    def run_scan(self, *args):
        env = dict(os.environ, SKEY_LOG=str(self.log), CP_LOG=str(self.cp_log),
                   PATH="%s:%s" % (self.shim, os.environ["PATH"]))
        return subprocess.run(["bash", str(SCRIPT), "--dir", str(self.root), "--skey", str(self.skey), *args],
                              capture_output=True, text=True, env=env, timeout=60)

    def imported(self):
        return sorted(Path(line.split()[-1]).name for line in self.log.read_text().splitlines())

    def test_example_variants_are_skipped_including_compound_ones(self):
        self.run_scan()
        self.assertEqual(self.imported(), [".env", ".env.local"])

    def test_backups_are_owner_only_from_the_moment_they_exist(self):
        self.run_scan("--apply")
        backups = list(self.repo.glob("*.skey-backup-*"))
        self.assertEqual(len(backups), 2)
        self.assertEqual(self.cp_log.read_text().split(), ["0o600", "0o600"])  # at creation
        for b in backups:
            self.assertEqual(stat.S_IMODE(b.stat().st_mode), 0o600, b.name)

    def test_a_backup_that_already_existed_is_tightened_to_owner_only(self):
        # A backup with the same name (the same second) can be there already, with a mode
        # of its own: cp overwrites it and keeps that mode, so the script sets it again.
        stamp = "20260101-000000"
        date = self.shim / "date"
        date.write_text('#!/bin/sh\nif [ "$1" = "+%Y%m%d-%H%M%S" ]; then echo ' + stamp
                        + '; else exec /bin/date "$@"; fi\n')
        date.chmod(0o755)
        existing = self.repo / (".env.skey-backup-" + stamp)
        existing.write_text("old plaintext\n")
        os.chmod(existing, 0o644)
        self.run_scan("--apply")
        self.assertEqual(stat.S_IMODE(existing.stat().st_mode), 0o600)


    def test_a_backup_that_cannot_be_tightened_is_reported(self):
        # The backup holds plaintext: a mode that could not be set is said out loud,
        # not swallowed.
        chmod = self.shim / "chmod"
        chmod.write_text("#!/bin/sh\nexit 1\n")
        chmod.chmod(0o755)
        result = self.run_scan("--apply")
        self.assertIn("could not set the mode", result.stderr)


if __name__ == "__main__":
    unittest.main()
