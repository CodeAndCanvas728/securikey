import tempfile
import types
import unittest
from unittest import mock

from securikey.store import KeychainStore, VaultError


def _fake_keyring(payload):
    """A keyring module whose item holds `payload`."""
    fake = types.ModuleType("keyring")
    fake.get_password = lambda service, account: payload
    fake.set_password = lambda service, account, secret: None
    fake.errors = types.ModuleType("keyring.errors")
    fake.errors.KeyringError = type("KeyringError", (Exception,), {})
    return fake


class LockPathTest(unittest.TestCase):
    def test_the_legacy_service_keeps_its_2x_lock_file_so_old_writers_and_migrate_exclude_each_other(self):
        from securikey import store
        with mock.patch.dict("os.environ", {"XDG_RUNTIME_DIR": tempfile.mkdtemp()}):
            old = store._lock_path(store.LEGACY_SERVICE)
            new = store._lock_path(store.SERVICE)
        self.assertEqual(old.parent.name, "token-vault")
        self.assertEqual(new.parent.name, "securikey")


class KeychainStoreTest(unittest.TestCase):
    def load(self, payload):
        fake = _fake_keyring(payload)
        with mock.patch.dict("sys.modules", {"keyring": fake, "keyring.errors": fake.errors}):
            return KeychainStore(service="securikey-test").load()

    def test_a_map_loads(self):
        self.assertEqual(self.load('{"a": "b"}'), {"a": "b"})

    def test_an_empty_item_is_an_empty_map(self):
        self.assertEqual(self.load(None), {})

    def test_a_payload_that_is_not_json_is_an_error(self):
        with self.assertRaises(VaultError):
            self.load("not json")

    def test_a_payload_that_is_not_a_map_is_an_error(self):
        # An empty map would look like "no secrets stored", and the next
        # save would then wipe everything that was there.
        with self.assertRaises(VaultError):
            self.load('["not", "a", "map"]')
        with self.assertRaises(VaultError):
            self.load('"a string"')


if __name__ == "__main__":
    unittest.main()
