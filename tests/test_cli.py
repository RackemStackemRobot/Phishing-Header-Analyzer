import io
import json
import tempfile
import unittest
from pathlib import Path

from phishing_header_analyzer.main import EXIT_CANCELLED, EXIT_ERROR, EXIT_OK, EXIT_RISK, main

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
        self.assertIn("**Header risk: LOW (0/100)**", out)

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


def run_at_keyboard(args, key):
    """Simulate a person at a terminal pressing one key at the body-inspection prompt."""
    out, err = io.BytesIO(), io.StringIO()

    def reader():
        if isinstance(key, BaseException):
            raise key
        return key

    code = main(args, stdin=io.BytesIO(b""), stdout=out, stderr=err, interactive=True, key_reader=reader)
    return code, out.getvalue().decode("utf-8"), err.getvalue()


def never_called():
    raise AssertionError("prompt shown when it shouldn't be")


class BodyPromptTests(unittest.TestCase):
    ARGS = [str(FIXTURES / "clean.eml"), "--config", str(EXAMPLE_CONFIG)]

    def test_y_inspects_body(self):
        code, out, err = run_at_keyboard(self.ARGS, "y")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("Inspect the message body too?", err)
        self.assertTrue(json.loads(out)["body"]["inspected"])

    def test_uppercase_y_too(self):
        self.assertTrue(json.loads(run_at_keyboard(self.ARGS, "Y")[1])["body"]["inspected"])

    def test_n_is_headers_only(self):
        code, out, _ = run_at_keyboard(self.ARGS, "n")
        self.assertEqual(code, EXIT_OK)
        self.assertFalse(json.loads(out)["body"]["inspected"])

    def test_esc_cancels(self):
        code, out, err = run_at_keyboard(self.ARGS, "\x1b")
        self.assertEqual((code, out), (EXIT_CANCELLED, ""))
        self.assertIn("Cancelled", err)

    def test_any_other_key_cancels(self):
        for key in ("q", "\r", " ", "1", ""):
            with self.subTest(key=repr(key)):
                self.assertEqual(run_at_keyboard(self.ARGS, key)[0], EXIT_CANCELLED)

    def test_ctrl_c_cancels(self):
        self.assertEqual(run_at_keyboard(self.ARGS, KeyboardInterrupt())[0], EXIT_CANCELLED)

    def test_cancel_writes_no_file(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "report.md"
            run_at_keyboard([*self.ARGS, "--out", str(target)], "\x1b")
            self.assertFalse(target.exists())

    def test_flags_skip_the_prompt(self):
        for flag, expected in (("--inspect-body", True), ("--headers-only", False)):
            with self.subTest(flag=flag):
                out, err = io.BytesIO(), io.StringIO()
                code = main([*self.ARGS, flag], stdout=out, stderr=err,
                            interactive=True, key_reader=never_called)
                self.assertEqual(code, EXIT_OK)
                self.assertEqual(json.loads(out.getvalue())["body"]["inspected"], expected)

    def test_flags_are_mutually_exclusive(self):
        with self.assertRaises(SystemExit) as ctx:
            run([*self.ARGS, "--inspect-body", "--headers-only"])
        self.assertEqual(ctx.exception.code, 2)

    def test_scripts_never_prompt_and_stay_headers_only(self):
        out, err = io.BytesIO(), io.StringIO()
        code = main(self.ARGS, stdin=io.BytesIO(b""), stdout=out, stderr=err,
                    interactive=False, key_reader=never_called)
        self.assertEqual(code, EXIT_OK)
        self.assertNotIn("Inspect", err.getvalue())
        self.assertFalse(json.loads(out.getvalue())["body"]["inspected"])


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
