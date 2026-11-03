import os
import re
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import domains2rules as d2r  # noqa: E402

SCRIPT = os.path.join(ROOT, "domains2rules.py")


def run(args, stdin="", env=None):
    e = {k: v for k, v in os.environ.items()
         if k not in ("DOMAINS2RULES_LANG", "LC_ALL", "LC_MESSAGES", "LANG")}
    e.update(env or {})
    return subprocess.run([sys.executable, SCRIPT, *args], input=stdin,
                          capture_output=True, text=True, env=e)


class NormalizeTest(unittest.TestCase):
    def test_formats(self):
        cases = {
            "Example.COM": "example.com",
            "*.foo.org": "foo.org",
            "||bar.net^": "bar.net",
            "https://baz.io/p?x=1": "baz.io",
            "0.0.0.0 qux.dev": "qux.dev",
            "пример.рф": "xn--e1afmkfd.xn--p1ai",
            "bar.net^$dnsrewrite=1.1.1.1": "bar.net",
        }
        for src, want in cases.items():
            self.assertEqual(d2r.normalize(src), want, src)

    def test_rejected(self):
        for bad in ("", "# c", "10.0.0.1", "two words", "single", "bad_.-x"):
            self.assertIsNone(d2r.normalize(bad), bad)


class PruneTest(unittest.TestCase):
    def test_parent_covers_child(self):
        keep, dropped = d2r.prune(["a.com", "x.a.com", "b.org"])
        self.assertEqual(keep, ["a.com", "b.org"])
        self.assertEqual(dropped, ["x.a.com"])


class CliTest(unittest.TestCase):
    def test_no_args_prints_help(self):
        r = run([])
        self.assertEqual(r.returncode, 0)
        self.assertIn("usage:", r.stdout)

    def test_ip_required(self):
        r = run(["-"], stdin="a.com\n")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--ip", r.stderr)

    def test_bad_ip(self):
        r = run(["-i", "999.1.1.1"], stdin="a.com\n")
        self.assertNotEqual(r.returncode, 0)

    def test_ip_order_and_default_limit(self):
        domains = "".join(f"host{i}-{i * 7}.example{i % 13}.com\n" for i in range(400))
        r = run(["-i", "1.1.1.1", "-i", "2.2.2.2"], stdin=domains)
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = r.stdout.splitlines()
        self.assertGreater(len(lines), 2)                 # было разбиение на куски
        self.assertTrue(all(len(l) <= 1024 for l in lines))
        ips = [l.rsplit("=", 1)[1] for l in lines]
        self.assertEqual(ips, ["1.1.1.1", "2.2.2.2"] * (len(lines) // 2))

    def test_union_matches(self):
        domains = [f"h{i}.site{i % 5}.net" for i in range(300)] + ["foo.co.uk", "dnstest0.org", "dnstest1.org", "dnstest2.org"]
        r = run(["-i", "1.1.1.1", "--max-len", "300"], stdin="\n".join(domains))
        self.assertEqual(r.returncode, 0, r.stderr)
        rxs = [re.compile(l[1:l.rindex("/$dnsrewrite")]) for l in r.stdout.splitlines()]
        for d in domains:
            self.assertTrue(any(x.match("sub." + d) for x in rxs), d)
        self.assertFalse(any(x.match("xfoo.co.uk") for x in rxs))


class LocalizationTest(unittest.TestCase):
    def test_help_languages(self):
        en = run(["--lang", "en"]).stdout
        ru = run(["--lang", "ru"]).stdout
        self.assertIn("Simple domain list", en)
        self.assertIn("Простой список доменов", ru)

    def test_autodetect_from_locale(self):
        self.assertIn("Простой список", run([], env={"LANG": "ru_RU.UTF-8"}).stdout)
        self.assertIn("Simple domain list", run([], env={"LANG": "C"}).stdout)
        self.assertIn("Simple domain list", run([]).stdout)       # default: English

    def test_env_override_and_flag_priority(self):
        self.assertIn("Простой список", run([], env={"DOMAINS2RULES_LANG": "ru"}).stdout)
        r = run(["--lang", "en"], env={"DOMAINS2RULES_LANG": "ru"})
        self.assertIn("Simple domain list", r.stdout)

    def test_messages_translated(self):
        en = run(["-i", "1.1.1.1", "--lang", "en"], stdin="a.com\n")
        ru = run(["-i", "1.1.1.1", "--lang", "ru"], stdin="a.com\n")
        self.assertIn("self-check: OK", en.stderr)
        self.assertIn("самопроверка: OK", ru.stderr)
        self.assertIn("Invalid IP", run(["-i", "300.1.1.1", "--lang", "en"], "a.com").stderr)
        self.assertIn("Некорректный IP", run(["-i", "300.1.1.1", "--lang", "ru"], "a.com").stderr)

    def test_same_output_in_all_languages(self):
        a = run(["-i", "1.1.1.1", "--lang", "en"], stdin="a.com\nb.org\n").stdout
        b = run(["-i", "1.1.1.1", "--lang", "ru"], stdin="a.com\nb.org\n").stdout
        self.assertEqual(a, b)

    def test_message_tables_have_same_keys(self):
        self.assertEqual(set(d2r.MESSAGES["en"]), set(d2r.MESSAGES["ru"]))


if __name__ == "__main__":
    unittest.main()
