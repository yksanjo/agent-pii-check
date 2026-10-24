import json
import os
import shutil
import tempfile
import unittest

import pii_check as pc

# Test fixtures use reserved/fictional values where possible. The Luhn-valid
# number 4111111111111111 is the universal card-network test number, and
# 078-05-1120 is the historical SSA advertising example.


class PiiTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, name, text):
        p = os.path.join(self.dir, name)
        with open(p, "w") as f:
            f.write(text)
        return p

    def codes(self, findings):
        return {f["code"] for f in findings}

    def test_clean_text_passes(self):
        p = self.write("notes.txt", "Deploy finished at 14:30. Team of five reviewed the diff.\n")
        self.assertEqual(pc.scan(p), [])

    def test_email_flagged_masked(self):
        p = self.write("t.txt", "Contact sarah.chen@realcompany.io for access.\n")
        findings = pc.scan(p)
        self.assertIn("email", self.codes(findings))
        f = findings[0]
        self.assertEqual(f["severity"], "warning")
        self.assertNotIn("sarah.chen", f["detail"])  # masked in output

    def test_placeholder_domain_skipped(self):
        p = self.write("t.txt", "examples use bob@example.com and docs@example.org\n")
        self.assertEqual(pc.scan(p), [])

    def test_phone_flagged(self):
        p = self.write("t.txt", "Reach Sam at (212) 555-0148 or 415-202-9481.\n")
        findings = pc.scan(p)
        phones = [f for f in findings if f["code"] == "phone"]
        self.assertEqual(len(phones), 1)  # 555-0148 is reserved fiction range
        self.assertNotIn("415-202-9481", phones[0]["detail"])

    def test_fiction_range_phone_skipped(self):
        p = self.write("t.txt", "Call 212-555-0148 for demo purposes.\n")
        self.assertEqual(pc.scan(p), [])

    def test_ssn_flagged_error(self):
        p = self.write("t.txt", "On file: 078-05-1120 for the account holder.\n")
        findings = pc.scan(p)
        self.assertIn("ssn", self.codes(findings))
        self.assertEqual(findings[0]["severity"], "error")
        self.assertNotIn("078-05", findings[0]["detail"])

    def test_invalid_ssn_shapes_skipped(self):
        p = self.write("t.txt", "codes 000-12-3456 and 900-11-2222 and 123-00-4567\n")
        self.assertEqual(pc.scan(p), [])

    def test_luhn_card_flagged_error(self):
        p = self.write("t.txt", "Card on file 4111 1111 1111 1111 exp 12/29.\n")
        findings = pc.scan(p)
        self.assertIn("payment-card", self.codes(findings))
        self.assertEqual(findings[0]["severity"], "error")
        self.assertNotIn("4111", findings[0]["detail"])

    def test_non_luhn_digit_run_skipped(self):
        p = self.write("t.txt", "Reference 4111 1111 1111 1112 in the ledger.\n")
        self.assertEqual(pc.scan(p), [])

    def test_short_digit_run_not_card(self):
        p = self.write("t.txt", "Order 123456 shipped Tuesday.\n")
        self.assertEqual(pc.scan(p), [])

    def test_street_address_info(self):
        p = self.write("t.txt", "Ship to 1600 Amphitheatre Parkway soon.\n")
        findings = pc.scan(p)
        self.assertIn("street-address", self.codes(findings))
        self.assertEqual(findings[0]["severity"], "info")

    def test_jsonl_text_field(self):
        rec = {"type": "result", "text": "user email is jane.doe@company.co"}
        p = self.write("trace.jsonl", json.dumps(rec) + "\n")
        self.assertIn("email", self.codes(pc.scan(p)))

    def test_jsonl_malformed_scanned_as_text(self):
        p = self.write("trace.jsonl", '{broken: 078-05-1120\n')
        self.assertIn("ssn", self.codes(pc.scan(p)))

    def test_directory_walk_filters_extensions(self):
        self.write("a.md", "jane@company.co\n")
        self.write("b.py", "# jane2@company.co in a comment (py not scanned)\n")
        findings = pc.scan(self.dir)
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0]["source"].endswith("a.md:1"))

    def test_missing_path(self):
        self.assertIn("no-input", self.codes(pc.scan(os.path.join(self.dir, "nope"))))

    def test_empty_dir(self):
        self.assertIn("no-input", self.codes(pc.scan(self.dir)))

    def test_line_numbers(self):
        p = self.write("t.txt", "ok\nok\n078-05-1120\n")
        self.assertTrue(pc.scan(p)[0]["source"].endswith(":3"))

    def test_luhn_helper(self):
        self.assertTrue(pc.luhn_ok("4111111111111111"))
        self.assertFalse(pc.luhn_ok("4111111111111112"))
        self.assertFalse(pc.luhn_ok("123"))

    def test_ssn_helper(self):
        self.assertTrue(pc.ssn_ok("078", "05", "1120"))
        self.assertFalse(pc.ssn_ok("000", "05", "1120"))
        self.assertFalse(pc.ssn_ok("666", "05", "1120"))
        self.assertFalse(pc.ssn_ok("900", "05", "1120"))
        self.assertFalse(pc.ssn_ok("078", "00", "1120"))
        self.assertFalse(pc.ssn_ok("078", "05", "0000"))

    def test_min_severity_filter(self):
        findings = [{"severity": "info"}, {"severity": "warning"}, {"severity": "error"}]
        self.assertEqual(len(pc.filter_severity(findings, "warning")), 2)
        self.assertEqual(len(pc.filter_severity(findings, "error")), 1)

    def test_cli_exit_codes(self):
        clean = self.write("clean.txt", "nothing sensitive here\n")
        self.assertEqual(pc.main([clean]), 0)
        dirty = self.write("dirty.txt", "078-05-1120\n")
        self.assertEqual(pc.main([dirty]), 1)
        warn_only = self.write("warn.txt", "email me at jane@company.co\n")
        self.assertEqual(pc.main([warn_only]), 0)  # warnings don't fail CI

    def test_cli_json_format(self):
        import io
        from contextlib import redirect_stdout
        p = self.write("dirty.txt", "078-05-1120\n")
        buf = io.StringIO()
        with redirect_stdout(buf):
            pc.main([p, "--format", "json"])
        parsed = json.loads(buf.getvalue())
        self.assertEqual(parsed[0]["code"], "ssn")


if __name__ == "__main__":
    unittest.main()
