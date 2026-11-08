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


class ConfigMarksTest(unittest.TestCase):
    """The marks live in their own keychain item, so the secrets map keeps its format."""

    def fake(self, items):
        fake = _fake_keyring(None)
        fake.PasswordDeleteError = type("PasswordDeleteError", (Exception,), {})
        fake.errors.PasswordDeleteError = fake.PasswordDeleteError
        fake.get_password = lambda service, account: items.get(account)
        fake.set_password = lambda service, account, value: items.__setitem__(account, value)

        def delete(service, account):
            if account not in items:
                raise fake.errors.PasswordDeleteError("not found")  # what the real keyring does
            del items[account]

        fake.delete_password = delete
        return fake

    def test_marks_round_trip_in_their_own_item_and_leave_the_secrets_item_alone(self):
        items = {"secrets": '{"a": "b"}'}
        fake = self.fake(items)
        with mock.patch.dict("sys.modules", {"keyring": fake, "keyring.errors": fake.errors}):
            store = KeychainStore(service="securikey-test")
            self.assertEqual(store.load_config(), {})  # an upgrade: no item yet
            store.save_config({"a": "hash"})
            self.assertEqual(store.load_config(), {"a": "hash"})
            self.assertEqual(items["secrets"], '{"a": "b"}')
            store.save_config({})  # nothing marked: the item goes away
            self.assertNotIn("config", items)
            store.save_config({})  # and removing it again is not an error

    def test_saving_the_secrets_drops_the_marks_that_no_longer_match(self):
        from securikey.store import value_mark
        items = {"secrets": '{"a": "one", "b": "two"}',
                 "config": '{"a": "%s", "b": "%s"}' % (value_mark("one"), value_mark("two"))}
        fake = self.fake(items)
        with mock.patch.dict("sys.modules", {"keyring": fake, "keyring.errors": fake.errors}):
            store = KeychainStore(service="securikey-test")
            store.save({"a": "one", "b": "changed"})
            self.assertEqual(store.load_config(), {"a": value_mark("one")})
            store.save({"a": "other"})  # nothing left marked: the item goes away
            self.assertNotIn("config", items)

    def test_a_corrupt_item_marks_nothing(self):
        fake = self.fake({"config": "not json"})
        with mock.patch.dict("sys.modules", {"keyring": fake, "keyring.errors": fake.errors}):
            self.assertEqual(KeychainStore(service="securikey-test").load_config(), {})


if __name__ == "__main__":
    unittest.main()
