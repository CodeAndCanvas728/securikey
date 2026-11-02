import base64
import time
import unittest
import urllib.parse

from securikey.redact import _signature, find, known_forms, redact, redact_obj

# The fakes below are assembled from parts, so that the file itself does not
# contain a string the CI secret scan would flag. The CI scans every file.
GH = "ghp_" + "a1B2c3D4e5" * 4  # 44 chars, GitHub token format (fake)
AWS = "AKIA" + "IOSFODNN7EXAMPLE"
SLACK = "xoxb-" + "1234567890-abcdefghij"
JWT = "eyJhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0" + ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
PEM_HEADER = "-----BEGIN " + "RSA PRIVATE KEY-----"
PEM_PLAIN = "-----BEGIN " + "PRIVATE KEY-----"
PEM_OPENSSH = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
PEM_END = "-----END " + "RSA PRIVATE KEY-----"
STORED = {"deploy_key": "s3cr3t-Deploy-Value-42"}


class PatternTest(unittest.TestCase):
    def test_an_anthropic_key_after_a_hyphen_is_still_found(self):
        self.assertEqual(find("ANTHROPIC-sk-ant-api03-" + "A" * 40, {}), ["anthropic"])

    def test_hyphenated_slugs_are_not_openai_keys(self):
        slug = "feature/task-s" + "k-update-the-quarterly-report-generator-v2"  # assembled: CI scans for the old pattern
        self.assertEqual(find("git checkout " + slug, {}), [])
        for other in ("feat_sk-update-the-quarterly-report-generator-v2",):
            self.assertEqual(find("git switch " + other, {}), [], other)
        key = "sk-" + "Ab1" * 15
        for text in ("key " + key, "OPENAI_API_KEY=" + key, '{"k": "' + key + '"}'):
            self.assertEqual(find(text, {}), ["openai"], text)

    def test_a_run_of_jwt_starts_takes_linear_time(self):
        # Every `-` before `eyJ` used to start a new match attempt inside the same run (quadratic): 160 KB
        # took 8 s, past the hook timeout.
        start = time.monotonic()
        self.assertEqual(find("-eyJ" * 100000, {}), [])
        self.assertLess(time.monotonic() - start, 1)
        self.assertEqual(find("token=" + JWT, {}), ["jwt"])

    def test_every_private_key_armor_header_is_found(self):
        for label in ("RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "SSH2 ENCRYPTED PRIVATE KEY",
                      "PGP PRIVATE KEY BLOCK"):
            text = "x -----BEGIN " + label + "-----\nQUJDREVGR0hJSktM\n-----END " + label + "-----\ny"
            self.assertEqual(find(text, {}), ["private_key"], label)
            self.assertEqual(redact(text, {})[0], "x [redacted:private_key]\ny", label)
        self.assertEqual(find("-----BEGIN " + "PGP PUBLIC KEY BLOCK-----\nabc\n", {}), [])  # a public key is not secret

    def test_provider_tokens_are_found(self):
        cases = {"github": GH, "aws_access_key": AWS, "anthropic": "sk-ant-" + "x" * 30,
                 "slack": SLACK, "private_key": PEM_OPENSSH, "jwt": JWT}
        for kind, token in cases.items():
            self.assertEqual(find("x %s y" % token, {}), [kind], kind)

    def test_ordinary_long_strings_are_not_secrets(self):
        # the v1 scanner flagged all of these (32+ character heuristic)
        benign = ["git show 5bdd55aaa355a3484c7ebb47e74f559e08d258ca",
                  "396af541-9e08-45d2-a870-3f8162901d4a",
                  "/home/dev/projects/some-project-name/src/components/Button.tsx",
                  "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
        for text in benign:
            self.assertEqual(find(text, {}), [], text)


PEM = """%s
MIIEowIBAAKCAQEAwSecretBase64BodyLineHereAAAAAAAAAAAA
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
%s""" % (PEM_HEADER, PEM_END)


class PrivateKeyTest(unittest.TestCase):
    def test_the_whole_pem_block_is_redacted_not_only_the_header(self):
        # The body is the key: anyone can prepend a standard header to it.
        text, labels = redact(PEM, {})
        self.assertEqual(labels, ["private_key"])
        self.assertNotIn("MIIEowIBAAKCAQEAwSecretBase64BodyLineHere", text)
        self.assertNotIn("BBBBBBBB", text)
        self.assertIn("[redacted:private_key]", text)

    def test_a_truncated_key_is_redacted_to_the_end_of_its_body(self):
        text, labels = redact("%s\nMIIESecretBodyLine\n" % PEM_HEADER, {})
        self.assertEqual(labels, ["private_key"])
        self.assertNotIn("MIIESecretBodyLine", text)

    def test_a_body_whose_last_line_has_no_newline_is_redacted(self):
        # a file read with `head -c 400` ends wherever it ends
        text, labels = redact("%s\nMIIESecretBodyAAAA\nBBBBBBBBBBBBBBBB" % PEM_HEADER, {})
        self.assertEqual(labels, ["private_key"])
        self.assertNotIn("MIIESecretBodyAAAA", text)
        self.assertNotIn("BBBBBBBBBBBBBBBB", text)

    def test_a_json_escaped_key_is_redacted(self):
        # the key arrives inside an already-serialised string, so the line
        # breaks are the two characters \ and n
        escaped = ("%s\\nMIIESecretBodyAAAA\\nBBBBBBBBBBBBBBBB\\n%s"
                   % (PEM_HEADER, PEM_END))
        text, labels = redact(escaped, {})
        self.assertEqual(labels, ["private_key"])
        self.assertNotIn("MIIESecretBodyAAAA", text)
        self.assertNotIn("BBBBBBBBBBBBBBBB", text)

    def test_a_key_body_is_redacted_whatever_shape_it_arrives_in(self):
        shapes = {
            "a tail shorter than four characters": "%s\nMIIESecretBody\nAB" % PEM_HEADER,
            "flattened onto one line": PEM_PLAIN + "MIIESecretBodyAAAA",
            "with RFC 1423 pre-headers": ("%s\nProc-Type: 4,ENCRYPTED\n"
                                         "DEK-Info: DES-EDE3-CBC,1234ABCD\n\nMIIESecretBody\n%s"
                                         % (PEM_HEADER, PEM_END)),
            "interrupted by a non-base64 byte": "%s\nMIIESecret%%Body\n" % PEM_HEADER,
        }
        for name, text in shapes.items():
            out, labels = redact(text, {})
            self.assertEqual(labels, ["private_key"], name)
            self.assertNotIn("MIIESecret", out, name)
            self.assertEqual(out.count("[redacted:private_key]"), 1, name)

    def test_a_key_body_does_not_leak_through_a_tool_response(self):
        response = {"stdout": PEM, "stderr": "", "interrupted": False, "isImage": False}
        out, labels = redact_obj(response, {})
        self.assertEqual(set(out), set(response))
        self.assertNotIn("MIIEowIBAAKCAQEAwSecretBase64BodyLineHere", repr(out))
        self.assertIn("[redacted:private_key]", out["stdout"])


class KnownValueTest(unittest.TestCase):
    def test_stored_value_and_its_encodings_are_redacted_by_name(self):
        value = STORED["deploy_key"]
        for form in (value, base64.b64encode(value.encode()).decode(), urllib.parse.quote(value, safe="")):
            text, labels = redact("before %s after" % form, STORED)
            self.assertEqual(labels, ["deploy_key"])
            self.assertNotIn(form, text)
            self.assertIn("[securikey:deploy_key]", text)

    def test_short_stored_values_are_ignored(self):
        self.assertEqual(find("the value is true", {"flag": "true"}), [])

    def test_shape_is_kept_and_no_value_survives(self):
        obj = {"stdout": "token=%s" % GH, "stderr": "", "interrupted": False, "n": [STORED["deploy_key"], 3]}
        out, labels = redact_obj(obj, STORED)
        self.assertEqual(set(out), set(obj))
        self.assertEqual(out["interrupted"], False)
        self.assertEqual(labels, ["deploy_key", "github"])
        self.assertNotIn(GH, repr(out))
        self.assertNotIn(STORED["deploy_key"], repr(out))

    def test_a_secret_in_a_dict_key_is_redacted_too(self):
        out, labels = redact_obj({STORED["deploy_key"]: "value"}, STORED)
        self.assertNotIn(STORED["deploy_key"], repr(out))
        self.assertIn("[securikey:deploy_key]", repr(out))
        self.assertEqual(labels, ["deploy_key"])

    def test_two_keys_that_redact_to_the_same_marker_do_not_collide(self):
        out, labels = redact_obj({STORED["deploy_key"]: 1, "x" + STORED["deploy_key"]: 2}, STORED)
        self.assertEqual(len(out), 2, out)
        self.assertEqual(sorted(out.values()), [1, 2])


class CountingText(str):
    """A text that counts how often it is searched for a known form."""

    searches = 0

    def __contains__(self, item):
        if len(item) == 1:
            return str.__contains__(self, item)  # the signature check, not a search
        CountingText.searches += 1
        return str.__contains__(self, item)


class SignatureFilterTest(unittest.TestCase):
    """A form can only be in a text that holds its signature character, so the forms that
    can't be in the payload are dropped once, and the rest are the only ones searched for."""

    VALUE = "Ab3-dEf9GhIjKlMnOpQrStUv"

    def test_a_form_whose_signature_character_is_absent_is_dropped(self):
        known = known_forms({"deploy_key": self.VALUE})
        self.assertEqual(known.in_text("a text without the character"), [])
        self.assertTrue(known.in_text("a text with a - in it"))

    def test_a_dropped_form_is_never_searched_for(self):
        known = known_forms({"deploy_key": self.VALUE})
        text = CountingText("a text without the character")
        pairs = known.in_text(text)
        CountingText.searches = 0
        self.assertEqual(find(text, known=pairs), [])
        self.assertEqual(CountingText.searches, 0)

    def test_the_filter_never_drops_a_secret_that_is_in_the_text(self):
        value = STORED["deploy_key"]
        known = known_forms(STORED)
        self.assertTrue(any(form == value for form, _ in known.in_text("before %s after" % value)))
        text, labels = redact("before %s after" % value, STORED)
        self.assertEqual(labels, ["deploy_key"])
        self.assertNotIn(value, text)

    def test_the_signature_is_the_rarest_character_of_the_form(self):
        known = known_forms({"k": self.VALUE})
        self.assertEqual(known.signatures[self.VALUE], "-")
        self.assertEqual(_signature("abcdefghijklmno"), "a")  # nothing rare in it
        self.assertEqual(_signature("abc123def"), "1")  # a digit before a letter


if __name__ == "__main__":
    unittest.main()
