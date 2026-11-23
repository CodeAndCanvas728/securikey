import time
import unittest

from securikey import shellparse


def argv(command):
    return [[w.text for w in c.argv] for c in shellparse.parse(command)]


class ShellParseTest(unittest.TestCase):
    def test_quotes_hide_operators_and_are_removed(self):
        self.assertEqual(argv('echo "a; b && c | d" \'e\\f\' g\\ h'), [["echo", "a; b && c | d", "e\\f", "g h"]])
        self.assertEqual(argv('ec"ho" x'), [["echo", "x"]])

    def test_operators_split_commands_and_pipes_are_marked(self):
        commands = shellparse.parse("a | b && c || d; e & f\ng")
        self.assertEqual([[w.text for w in c.argv] for c in commands], [[x] for x in "abcdefg"])
        self.assertEqual([c.piped for c in commands], [True, False, False, False, False, False, False])
        self.assertTrue(shellparse.parse("a |& b")[0].piped)

    def test_assignments_redirects_and_descriptors(self):
        command = shellparse.parse("A=1 B='x y' cmd arg 2>err >>out <in &>both >&2")[0]
        self.assertEqual([w.text for w in command.assignments], ["A=1", "B=x y"])
        self.assertEqual([w.text for w in command.argv], ["cmd", "arg"])
        self.assertEqual([(op, w.text) for op, w in command.redirects],
                         [(">", "err"), (">>", "out"), ("<", "in"), (">", "both"), (">", "2")])

    def test_heredocs_hold_their_body_whatever_it_says(self):
        text = "mkdir -p \"$D\" && cat > \"$D/n\" <<'EOF'\na; b | c `d` $(e) ${f} 'g\nEOF\nls"
        commands = shellparse.parse(text)
        self.assertEqual([[w.text for w in c.argv] for c in commands], [["mkdir", "-p", "$D"], ["cat"], ["ls"]])
        heredoc = commands[1].heredocs[0]
        self.assertTrue(heredoc.quoted)
        self.assertEqual(heredoc.body, "a; b | c `d` $(e) ${f} 'g")
        self.assertEqual(commands[1].redirects[0][1].text, "$D/n")

    def test_a_tab_stripped_heredoc_and_two_on_one_line(self):
        command = shellparse.parse("cat <<-EOF\n\tone\n\tEOF")[0]
        self.assertEqual(command.heredocs[0].body, "one")
        command = shellparse.parse("cat <<A <<B\n1\nA\n2\nB")[0]
        self.assertEqual([h.body for h in command.heredocs], ["1", "2"])

    def test_substitutions_are_kept_as_bodies_and_make_a_word_dynamic(self):
        command = shellparse.parse('echo "$(cat "a)b" | x)" `y` <(z)')[0]
        self.assertEqual([w.subs for w in command.argv[1:]], [['cat "a)b" | x'], ["y"], ["z"]])
        self.assertTrue(all(w.dynamic for w in command.argv[1:]))
        self.assertFalse(shellparse.parse("echo 'a $x'")[0].argv[1].dynamic)
        self.assertTrue(shellparse.parse('echo "a $x"')[0].argv[1].dynamic)

    def test_comments_end_at_the_line_and_only_at_a_word_start(self):
        self.assertEqual(argv("a # b; c\nd"), [["a"], ["d"]])
        self.assertEqual(argv("a#b"), [["a#b"]])

    def test_what_is_not_modelled_is_not_parsed(self):
        for text in ["echo ${X}", "echo $'x'", 'echo $"x"', "(a)", "a; (b)", "{ a; }", "if a; then b; fi", "for x in y; do z; done",
                     "case x in y) a;; esac", "echo 'x", 'echo "x', "echo $(x", "echo `x", "cat <<EOF\nno end",
                     "cat <<EOF", "cat <<$X\nx\n$X", "echo $(cat <<EOF\nx\nEOF\n)", "x =(y)", "a |", "echo x \\"]:
            self.assertIsNone(shellparse.parse(text), text)
        self.assertIsNone(shellparse.parse("echo " + "x" * shellparse.MAX_PARSE_CHARS))
        self.assertIsNone(shellparse.parse(";".join(["a"] * (shellparse.MAX_COMMANDS + 1))))
        self.assertIsNotNone(shellparse.parse("echo x"))

    def test_time_grows_with_the_length_of_the_input(self):
        for body in ['"' * 60000, "'" * 60000, "$(" * 20000, "<<A " * 5000, "\\ " * 30000, "a;" * 30000, "| " * 30000]:
            start = time.monotonic()
            shellparse.parse("echo " + body)
            self.assertLess(time.monotonic() - start, 1.0, body[:6])


if __name__ == "__main__":
    unittest.main()
