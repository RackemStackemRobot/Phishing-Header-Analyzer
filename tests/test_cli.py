import io
import json
import tempfile
import unittest
from pathlib import Path

from phishing_header_analyzer.main import EXIT_ERROR, EXIT_OK, EXIT_RISK, main

ROOT = Path(__file__).parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
EXAMPLE_CONFIG = ROOT / "examples" / "config.example.json"


def run(args, stdin_bytes=b""):
    out, err = io.BytesIO(), io.StringIO()
    code = main(args, stdin=io.BytesIO(stdin_bytes), stdout=out, stderr=err)
    return code, out.getvalue().decode("utf-8"), err.getvalue()


class CliTests(unittest.TestCase):
    def test_json_default(self):
        code, out, _ = run([str(FIXTURES / "spf_fail.eml"), "--config", str(EXAMPLE_CONFIG)])
        self.assertEqual(code, EXIT_OK)
        report = json.loads(out)
        self.assertEqual(report["risk"]["level"], "high")
        self.assertIsNotNone(report["analyzed_at"])

    def test_markdown(self):
        code, out, _ = run([str(FIXTURES / "clean.eml"), "--format", "md", "--config", str(EXAMPLE_CONFIG)])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("**Risk: LOW (0/100)**", out)

    def test_no_timestamp_is_reproducible(self):
        args = [str(FIXTURES / "lookalike_domain.eml"), "--no-timestamp", "--config", str(EXAMPLE_CONFIG)]
        self.assertEqual(run(args)[1], run(args)[1])
        self.assertIsNone(json.loads(run(args)[1])["analyzed_at"])

    def test_stdin(self):
        data = (FIXTURES / "headers_only.txt").read_bytes()
        code, out, _ = run(["-", "--config", str(EXAMPLE_CONFIG)], stdin_bytes=data)
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(json.loads(out)["source"], "<stdin>")

    def test_out_file(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "report.md"
            code, out, err = run([str(FIXTURES / "spf_fail.eml"), "--format", "md", "--out", str(target)])
            self.assertEqual(code, EXIT_OK)
            self.assertEqual(out, "")
            self.assertIn("Report written", err)
            self.assertIn("# Phishing Header Analysis", target.read_text(encoding="utf-8"))

    def test_non_latin_output_is_utf8(self):
        code, out, _ = run([str(FIXTURES / "headers_only.txt"), "--format", "md", "--no-defang",
                            "--config", str(EXAMPLE_CONFIG)])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("nоrthwind", out)  # Cyrillic o survived the round trip

    def test_fail_on(self):
        cfg = ["--config", str(EXAMPLE_CONFIG)]
        self.assertEqual(run([str(FIXTURES / "spf_fail.eml"), "--fail-on", "high", *cfg])[0], EXIT_RISK)
        self.assertEqual(run([str(FIXTURES / "clean.eml"), "--fail-on", "medium", *cfg])[0], EXIT_OK)
        self.assertEqual(run([str(FIXTURES / "clean.eml"), "--fail-on", "low", *cfg])[0], EXIT_RISK)


class CliErrorTests(unittest.TestCase):
    def test_missing_file(self):
        code, _, err = run(["does-not-exist.eml"])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("not found", err)

    def test_empty_input(self):
        code, _, err = run(["-"], stdin_bytes=b"   \n")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("empty", err)

    def test_not_an_email(self):
        code, _, err = run(["-"], stdin_bytes=b"just some random text\nnothing here\n")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("no email headers", err)

    def test_bad_config(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            fh.write("{not json")
        code, _, err = run([str(FIXTURES / "clean.eml"), "--config", fh.name])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("error:", err)

    def test_bad_format_is_usage_error(self):
        with self.assertRaises(SystemExit) as ctx:
            run([str(FIXTURES / "clean.eml"), "--format", "pdf"])
        self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
