"""Documented limits of exact-value redaction, pinned so they stay documented.

A stored secret is matched as itself and in its base64 and URL-encoded forms. A command that
transforms the value before printing it produces text no stored form matches, and the output
reaches the model unchanged. README, "What it does not do", says so; these tests fail if the
behaviour changes, so the README is revised with it.
"""
import base64
import binascii
import unittest
import urllib.parse

from securikey.redact import find, redact

SECRET = "Zx9-quiet-Deploy-Value-7421"
STORED = {"deploy_key": SECRET}


def passes_through(text):
    out, labels = redact(text, STORED)
    return out == text and labels == []


class ExpectedPassThroughTest(unittest.TestCase):
    def test_a_reversed_value_is_not_redacted(self):
        # skey run --env A=deploy_key -- sh -c 'echo $A | rev'
        self.assertTrue(passes_through(SECRET[::-1]))

    def test_a_hex_encoded_value_is_not_redacted(self):
        self.assertTrue(passes_through(binascii.hexlify(SECRET.encode()).decode()))

    def test_a_value_printed_in_pieces_is_not_redacted(self):
        half = len(SECRET) // 2
        self.assertTrue(passes_through("%s\n%s" % (SECRET[:half], SECRET[half:])))

    def test_a_value_with_separators_between_characters_is_not_redacted(self):
        self.assertTrue(passes_through(" ".join(SECRET)))

    def test_a_case_changed_value_is_not_redacted(self):
        self.assertTrue(passes_through(SECRET.upper()))

    def test_an_unstored_jwt_glued_to_a_token_character_is_not_recognised_by_pattern(self):
        # The jwt pattern does not start inside a run of token characters: that is what keeps it linear
        # (a run of "-eyJ" was quadratic and stalled the hooks). A stored JWT is still matched exactly.
        jwt = "eyJhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0" + ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        self.assertEqual(find("token " + jwt, {}), ["jwt"])
        self.assertEqual(find("token-" + jwt, {}), [])
        self.assertEqual(find("token-" + jwt, {"stored_jwt": jwt}), ["stored_jwt"])


class MatchedFormsTest(unittest.TestCase):
    """The other side of the boundary: the forms that are matched."""

    def test_the_plain_value_is_redacted(self):
        self.assertEqual(redact("key=%s" % SECRET, STORED), ("key=[securikey:deploy_key]", ["deploy_key"]))

    def test_the_base64_form_is_redacted(self):
        form = base64.b64encode(SECRET.encode()).decode()
        self.assertEqual(redact(form, STORED)[1], ["deploy_key"])

    def test_the_url_encoded_form_is_redacted(self):
        value = "pa ss/word&Value+42"
        form = urllib.parse.quote(value, safe="")
        self.assertNotEqual(form, value)
        self.assertEqual(redact(form, {"pw": value})[1], ["pw"])


if __name__ == "__main__":
    unittest.main()
