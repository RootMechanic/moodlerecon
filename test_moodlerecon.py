"""Regresiones locales: no contactan objetivos ni servicios externos."""
import unittest
from unittest.mock import Mock, patch
import contextlib
import io
import tempfile
from pathlib import Path
import moodlerecon as scanner


class RegressionTests(unittest.TestCase):
    def test_pdftex_fixed_releases_are_excluded(self):
        for version in ("4.4.2", "4.3.6", "4.2.9", "4.1.12"):
            with self.subTest(version=version):
                self.assertFalse(scanner.version_in_affected(version, scanner.PDFTEX_ADVISORY["affected"]))

    def test_old_pdftex_branch_requires_review(self):
        self.assertIn("REQUIERE_REVISION", scanner.affected_status("3.11.7", scanner.PDFTEX_ADVISORY["affected"]))

    def test_wiki_sql_injection_patch_boundary(self):
        advisory = next(a for a in scanner.BUILTIN_ADVISORIES if a["id"] == "CVE-2023-30944")
        self.assertTrue(scanner.version_in_affected("3.11.13", advisory["affected"]))
        self.assertFalse(scanner.version_in_affected("3.11.14", advisory["affected"]))

    def test_cvss_takes_precedence_over_lower_named_severity(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        self.assertEqual(scanner.cvss3_base(vector), 9.8)
        self.assertEqual(scanner.severity_from_osv({"database_specific": {"severity": "MODERATE"}, "severity": [{"score": vector}]}), "CRITICAL")

    def test_guest_words_in_content_are_not_login_evidence(self):
        self.assertFalse(scanner.guest_marker("<p>You are currently using guest access</p>"))
        self.assertTrue(scanner.guest_marker('<div class="logininfo">You are currently using guest access</div>'))

    def test_redirect_does_not_forward_credentials_outside_scope(self):
        client = Mock(timeout=10)
        response = Mock(status_code=307, headers={"Location": "https://outside.example/login"})
        client.session.request.return_value = response
        self.assertIsNone(scanner.scoped_request(client, "https://moodle.example/site", "https://moodle.example/site/login", "POST", {"token": "test-secret"}))
        self.assertEqual(client.session.request.call_count, 1)

    def test_source_url_redacts_tokens(self):
        self.assertEqual(scanner.safe_source("https://moodle.example/user/profile.php?id=4&token=secret#secret"), "https://moodle.example/user/profile.php?id=4")

    def test_invalid_cookie_file_fails_before_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.txt"
            malformed = Path(directory) / "invalid.txt"
            malformed.write_text("not a Netscape cookie file", encoding="utf-8")
            for filename in (missing, malformed):
                with self.subTest(filename=filename), patch("sys.argv", ["moodlerecon.py", "--url", "https://moodle.example", "--enum-users", "--cookies", str(filename)]), patch.object(scanner, "scan") as scan, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as error:
                    with self.assertRaises(SystemExit) as caught:
                        scanner.main()
                    self.assertEqual(caught.exception.code, 2)
                    scan.assert_not_called()
                    self.assertIn("No se pudo cargar --cookies", error.getvalue())

    def test_valid_cookie_file_is_loaded_before_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / "cookies.txt"
            filename.write_text("# Netscape HTTP Cookie File\n.example.com\tTRUE\t/\tTRUE\t\tMoodleSession\ttest-value\n", encoding="utf-8")
            with patch("sys.argv", ["moodlerecon.py", "--url", "https://moodle.example", "--enum-users", "--cookies", str(filename)]), patch.object(scanner, "scan") as scan, contextlib.redirect_stdout(io.StringIO()):
                scanner.main()
            self.assertEqual(len(scan.call_args.args[0].cookie_jar), 1)


if __name__ == "__main__":
    unittest.main()
