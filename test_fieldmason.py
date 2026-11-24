#!/usr/bin/env python3
"""Tests for fieldmason.py — stdlib unittest only."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOL = HERE / "fieldmason.py"


def run(*argv):
    return subprocess.run(
        [sys.executable, str(TOOL), *argv],
        capture_output=True, text=True)


class FieldMasonTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        return p

    def scan_json(self, *paths):
        proc = run("scan", *[str(p) for p in paths], "--json")
        return proc, json.loads(proc.stdout)

    # --- clean cases -------------------------------------------------
    def test_clean_jsonl_exit_0(self):
        self.write("a.jsonl", '{"id": 1, "name": "ada"}\n'
                              '{"id": 2, "name": "bea"}\n')
        proc, data = self.scan_json(self.root)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(data["findings"], [])
        self.assertEqual(data["counts"]["records_total"], 2)
        self.assertEqual(data["counts"]["files_parsed"], 1)

    def test_clean_json_object_exit_0(self):
        self.write("a.json", '{"id": 1, "tags": ["x", "y"]}')
        proc, data = self.scan_json(self.root)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(data["counts"]["records_total"], 1)

    # --- parse errors ------------------------------------------------
    def test_parse_error_json(self):
        self.write("bad.json", '{"id": 1,,}')
        proc, data = self.scan_json(self.root)
        self.assertEqual(proc.returncode, 1)
        rules = [f["rule"] for f in data["findings"]]
        self.assertIn("parse-error", rules)
        self.assertEqual(data["counts"]["files_parsed"], 0)

    def test_parse_error_jsonl_line_continues(self):
        self.write("a.jsonl", '{"id": 1}\nnot json\n{"id": 2}\n')
        proc, data = self.scan_json(self.root)
        self.assertEqual(proc.returncode, 1)
        det = [f["detail"] for f in data["findings"]
               if f["rule"] == "parse-error"]
        self.assertEqual(len(det), 1)
        self.assertTrue(det[0].startswith("line 2:"))
        self.assertEqual(data["counts"]["records_total"], 2)

    # --- duplicate keys ----------------------------------------------
    def test_duplicate_key_json(self):
        self.write("a.json", '{"id": 1, "id": 2}')
        proc, data = self.scan_json(self.root)
        self.assertEqual(proc.returncode, 1)
        det = [f["detail"] for f in data["findings"]
               if f["rule"] == "duplicate-key"]
        self.assertEqual(det, ["key 'id' appears 2 times in one object"])

    def test_duplicate_key_jsonl_line_prefix(self):
        self.write("a.jsonl", '{"id": 1}\n{"id": 1, "id": 9}\n')
        _, data = self.scan_json(self.root)
        det = [f["detail"] for f in data["findings"]
               if f["rule"] == "duplicate-key"]
        self.assertEqual(len(det), 1)
        self.assertTrue(det[0].startswith("line 2: "))

    def test_duplicate_key_nested_object(self):
        self.write("a.json", '{"outer": {"x": 1, "x": 2}}')
        _, data = self.scan_json(self.root)
        rules = [f["rule"] for f in data["findings"]]
        self.assertIn("duplicate-key", rules)

    # --- drift --------------------------------------------------------
    def test_type_drift(self):
        self.write("a.jsonl", '{"age": 30}\n{"age": 41}\n{"age": "old"}\n')
        proc, data = self.scan_json(self.root)
        det = [f["detail"] for f in data["findings"]
               if f["rule"] == "type-drift"]
        self.assertEqual(det, ["field 'age': types number, string "
                               "across 3 records"])
        # medium only: default fail-on high -> exit 0
        self.assertEqual(proc.returncode, 0)

    def test_type_drift_null_ignored(self):
        self.write("a.jsonl", '{"age": 30}\n{"age": null}\n{"age": 41}\n')
        _, data = self.scan_json(self.root)
        rules = [f["rule"] for f in data["findings"]]
        self.assertNotIn("type-drift", rules)

    def test_key_drift(self):
        self.write("a.jsonl", '{"id": 1, "note": "x"}\n{"id": 2}\n')
        _, data = self.scan_json(self.root)
        det = [f["detail"] for f in data["findings"]
               if f["rule"] == "key-drift"]
        self.assertEqual(det, ["field 'note' present in 1 of 2 records"])

    def test_record_type_drift_suppresses_key_drift(self):
        self.write("a.jsonl", '{"id": 1}\n[1, 2]\n{"id": 2, "x": 1}\n')
        _, data = self.scan_json(self.root)
        rules = [f["rule"] for f in data["findings"]]
        self.assertIn("record-type-drift", rules)
        self.assertNotIn("key-drift", rules)

    def test_json_array_records_drift(self):
        self.write("a.json", '[{"n": 1}, {"n": "two"}]')
        _, data = self.scan_json(self.root)
        rules = [f["rule"] for f in data["findings"]]
        self.assertIn("type-drift", rules)
        self.assertEqual(data["counts"]["records_total"], 2)

    # --- other rules --------------------------------------------------
    def test_empty_file(self):
        self.write("a.json", "   \n")
        self.write("b.jsonl", "\n\n")
        _, data = self.scan_json(self.root)
        empties = [f for f in data["findings"] if f["rule"] == "empty-file"]
        self.assertEqual(len(empties), 2)

    def test_blank_line_jsonl(self):
        self.write("a.jsonl", '{"id": 1}\n\n{"id": 2}\n')
        _, data = self.scan_json(self.root)
        det = [f["detail"] for f in data["findings"]
               if f["rule"] == "blank-line"]
        self.assertEqual(det, ["1 blank line(s)"])

    def test_big_int(self):
        self.write("a.json", '{"id": 9007199254740993}')
        _, data = self.scan_json(self.root)
        det = [f["detail"] for f in data["findings"]
               if f["rule"] == "big-int"]
        self.assertEqual(det, ["integer at $.id exceeds the safe "
                               "integer range"])

    def test_safe_int_and_bool_not_big(self):
        self.write("a.json", '{"id": 9007199254740991, "ok": true}')
        _, data = self.scan_json(self.root)
        self.assertEqual(data["findings"], [])

    def test_deep_nesting(self):
        deep = '{"a": ' * 25 + "1" + "}" * 25
        self.write("a.json", deep)
        _, data = self.scan_json(self.root)
        det = [f["detail"] for f in data["findings"]
               if f["rule"] == "deep-nesting"]
        self.assertEqual(len(det), 1)
        self.assertIn("exceeds max 20", det[0])

    def test_max_depth_option(self):
        self.write("a.json", '{"a": {"b": {"c": 1}}}')
        proc = run("scan", str(self.root), "--json", "--max-depth", "2")
        data = json.loads(proc.stdout)
        rules = [f["rule"] for f in data["findings"]]
        self.assertIn("deep-nesting", rules)

    # --- walking / gating ---------------------------------------------
    def test_symlink_skipped(self):
        target = self.write("real.jsonl", '{"id": 1, "id": 2}\n')
        os.symlink(target, self.root / "link.jsonl")
        _, data = self.scan_json(self.root)
        self.assertEqual(data["counts"]["links_skipped"], 1)
        self.assertEqual(data["counts"]["files_matched"], 1)

    def test_extension_filter_and_explicit_file(self):
        self.write("a.txt", '{"id": 1, "id": 2}')
        self.write("b.json", '{"id": 1}')
        _, data = self.scan_json(self.root)
        self.assertEqual(data["counts"]["files_matched"], 1)
        proc, data2 = self.scan_json(self.root / "a.txt")
        self.assertEqual(data2["counts"]["files_matched"], 1)
        self.assertIn("duplicate-key",
                      [f["rule"] for f in data2["findings"]])

    def test_missing_root_exit_2(self):
        proc = run("scan", str(self.root / "nope"))
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn("Traceback", proc.stderr)

    def test_min_severity_hides_low(self):
        self.write("a.jsonl", '{"id": 1, "note": "x"}\n{"id": 2}\n')
        proc = run("scan", str(self.root), "--json",
                   "--min-severity", "medium")
        data = json.loads(proc.stdout)
        self.assertEqual(data["findings"], [])

    def test_fail_on_medium_and_never(self):
        self.write("a.jsonl", '{"age": 30}\n{"age": "old"}\n')
        proc = run("scan", str(self.root), "--fail-on", "medium")
        self.assertEqual(proc.returncode, 1)
        proc = run("scan", str(self.root), "--fail-on", "never")
        self.assertEqual(proc.returncode, 0)

    def test_determinism(self):
        self.write("a.jsonl", '{"age": 30}\n{"age": "old", "id": 1}\n')
        self.write("b.json", '{"id": 9007199254740993}')
        p1 = run("scan", str(self.root), "--json")
        p2 = run("scan", str(self.root), "--json")
        self.assertEqual(p1.stdout, p2.stdout)

    def test_read_only(self):
        p = self.write("a.jsonl", '{"id": 1, "id": 2}\n')
        before = p.read_bytes()
        listing_before = sorted(os.listdir(self.root))
        run("scan", str(self.root))
        self.assertEqual(p.read_bytes(), before)
        self.assertEqual(sorted(os.listdir(self.root)), listing_before)

    def test_text_summary_shape(self):
        self.write("a.jsonl", '{"id": 1}\n{"id": 2}\n')
        proc = run("scan", str(self.root))
        self.assertIn("fieldmason: 1 dirs scanned, 1 files matched, "
                      "1 files parsed, 2 records, 0 findings "
                      "(0 high, 0 medium, 0 low), 0 links skipped, "
                      "0 errors", proc.stdout)

    def test_version(self):
        proc = run("--version")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("1.0.0", proc.stdout)


if __name__ == "__main__":
    unittest.main()
