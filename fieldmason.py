#!/usr/bin/env python3
"""FieldMason: audit the shape of JSON and JSON Lines record collections.

Parses are not proof of health: a field can change type halfway
through a log, a key can vanish from newer records, and a duplicate
key can silently overwrite a value while every record still parses.
FieldMason scans a tree of .json / .jsonl / .ndjson files read-only
and reports that drift under named rules with a gate-shaped exit
code. Single file, Python 3.10+, standard library only.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

VERSION = "1.0.0"
TOOL = "fieldmason"
SAFE_INT = 9007199254740991  # 2**53 - 1
SEVERITIES = {"low": 0, "medium": 1, "high": 2}
DEFAULT_EXTENSIONS = (".json", ".jsonl", ".ndjson")
JSONL_EXTENSIONS = (".jsonl", ".ndjson")


def type_name(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unknown"


def depth_of(value):
    if isinstance(value, dict):
        if not value:
            return 1
        return 1 + max(depth_of(v) for v in value.values())
    if isinstance(value, list):
        if not value:
            return 1
        return 1 + max(depth_of(v) for v in value)
    return 0


class DupRecorder:
    """object_pairs_hook that records duplicate keys per object."""

    def __init__(self):
        self.duplicates = []  # list of (key, count)

    def hook(self, pairs):
        seen = {}
        order = []
        for key, _ in pairs:
            if key not in seen:
                order.append(key)
            seen[key] = seen.get(key, 0) + 1
        for key in order:
            if seen[key] > 1:
                self.duplicates.append((key, seen[key]))
        return dict(pairs)


def find_big_ints(value, path, out):
    if isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) > SAFE_INT:
            out.append(path)
        return
    if isinstance(value, dict):
        for key in sorted(value):
            find_big_ints(value[key], f"{path}.{key}", out)
    elif isinstance(value, list):
        for i, item in enumerate(value):
            find_big_ints(item, f"{path}[{i}]", out)


class FileAudit:
    def __init__(self, path):
        self.path = path
        self.records = 0
        self.parsed = False
        self.findings = []  # (rule, severity, detail)

    def add(self, rule, severity, detail):
        self.findings.append((rule, severity, detail))


def audit_records(audit, records, line_numbers, max_depth):
    """records: list of values. line_numbers: parallel list, None for JSON docs."""
    if not records:
        return
    audit.records = len(records)
    audit.parsed = True

    def prefix(i):
        ln = line_numbers[i] if line_numbers else None
        return f"line {ln}: " if ln is not None else ""

    # record-type-drift
    types = sorted({type_name(r) for r in records})
    has_type_drift = len(types) > 1
    if has_type_drift:
        audit.add("record-type-drift", "medium",
                  "record types: " + ", ".join(types))

    object_idx = [i for i, r in enumerate(records) if isinstance(r, dict)]
    if len(object_idx) >= 2:
        # type-drift per top-level field (non-null types)
        fields = {}
        for i in object_idx:
            for key, val in records[i].items():
                if val is None:
                    continue
                entry = fields.setdefault(key, {"types": set(), "count": 0})
                entry["types"].add(type_name(val))
                entry["count"] += 1
        for key in sorted(fields):
            entry = fields[key]
            if len(entry["types"]) >= 2:
                audit.add("type-drift", "medium",
                          f"field '{key}': types "
                          f"{', '.join(sorted(entry['types']))} "
                          f"across {entry['count']} records")
        # key-drift (suppressed when record types drift)
        if not has_type_drift:
            all_keys = set()
            for i in object_idx:
                all_keys.update(records[i].keys())
            total = len(object_idx)
            for key in sorted(all_keys):
                present = sum(1 for i in object_idx if key in records[i])
                if 0 < present < total:
                    audit.add("key-drift", "low",
                              f"field '{key}' present in {present} of "
                              f"{total} records")

    # big-int and deep-nesting
    deepest = -1
    deepest_depth = -1
    for i, record in enumerate(records):
        paths = []
        find_big_ints(record, "$", paths)
        for p in paths:
            audit.add("big-int", "low",
                      f"{prefix(i)}integer at {p} exceeds the safe "
                      f"integer range")
        d = depth_of(record)
        if d > deepest_depth:
            deepest_depth = d
            deepest = i
    if deepest_depth > max_depth:
        audit.add("deep-nesting", "low",
                  f"{prefix(deepest)}nesting depth {deepest_depth} "
                  f"exceeds max {max_depth}")


def audit_json_document(audit, text, max_depth):
    if not text.strip():
        audit.add("empty-file", "medium", "empty file")
        return
    recorder = DupRecorder()
    try:
        doc = json.loads(text, object_pairs_hook=recorder.hook)
    except json.JSONDecodeError as exc:
        audit.add("parse-error", "high",
                  f"line {exc.lineno} column {exc.colno}")
        return
    for key, count in recorder.duplicates:
        audit.add("duplicate-key", "high",
                  f"key '{key}' appears {count} times in one object")
    records = doc if isinstance(doc, list) else [doc]
    if isinstance(doc, list) and not doc:
        audit.parsed = True
        audit.records = 0
        return
    audit_records(audit, records, None, max_depth)


def audit_jsonl(audit, text, max_depth):
    lines = text.splitlines()
    non_blank = [(n, ln) for n, ln in enumerate(lines, 1) if ln.strip()]
    blank_count = len(lines) - len(non_blank)
    if not non_blank:
        audit.add("empty-file", "medium", "empty file")
        return
    if blank_count:
        audit.add("blank-line", "low", f"{blank_count} blank line(s)")
    records = []
    line_numbers = []
    for lineno, line in non_blank:
        recorder = DupRecorder()
        try:
            value = json.loads(line, object_pairs_hook=recorder.hook)
        except json.JSONDecodeError as exc:
            audit.add("parse-error", "high",
                      f"line {lineno}: line {exc.lineno} column {exc.colno}")
            continue
        for key, count in recorder.duplicates:
            audit.add("duplicate-key", "high",
                      f"line {lineno}: key '{key}' appears {count} "
                      f"times in one object")
        records.append(value)
        line_numbers.append(lineno)
    audit_records(audit, records, line_numbers, max_depth)


def parse_extensions(raw):
    if raw is None:
        return set(DEFAULT_EXTENSIONS)
    exts = set()
    for part in raw.split(","):
        part = part.strip().lower()
        if not part:
            continue
        if not part.startswith("."):
            part = "." + part
        exts.add(part)
    if not exts:
        raise ValueError("empty extension list")
    return exts


def collect_files(roots, extensions):
    """Returns (files, dirs_scanned, links_skipped, errors, root_error)."""
    files = []
    dirs_scanned = 0
    links_skipped = 0
    errors = 0
    for root in roots:
        p = Path(root)
        if os.path.islink(p):
            links_skipped += 1
            continue
        if p.is_file():
            files.append(p)
            continue
        if not p.is_dir():
            return None, 0, 0, 0, f"scan root is not a file or directory: {root}"
        for dirpath, dirnames, filenames in os.walk(p, followlinks=False):
            dirs_scanned += 1
            kept = []
            for name in dirnames:
                full = Path(dirpath) / name
                if os.path.islink(full):
                    links_skipped += 1
                else:
                    kept.append(name)
            dirnames[:] = sorted(kept)
            for name in sorted(filenames):
                full = Path(dirpath) / name
                if os.path.islink(full):
                    links_skipped += 1
                    continue
                if full.suffix.lower() in extensions:
                    files.append(full)
    files.sort(key=lambda x: str(x))
    return files, dirs_scanned, links_skipped, errors, None


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog=TOOL,
        description="Audit the shape of JSON / JSONL record collections.")
    parser.add_argument("--version", action="version",
                        version=f"{TOOL} {VERSION}")
    sub = parser.add_subparsers(dest="command")
    scan = sub.add_parser("scan", help="scan one or more paths")
    scan.add_argument("paths", nargs="+")
    scan.add_argument("--json", action="store_true")
    scan.add_argument("--min-severity", choices=list(SEVERITIES),
                      default="low")
    scan.add_argument("--fail-on", choices=list(SEVERITIES) + ["never"],
                      default="high")
    scan.add_argument("--max-depth", type=int, default=20)
    scan.add_argument("--extensions", default=None)
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_usage(sys.stderr)
        return 2
    if args.max_depth < 0:
        print(f"{TOOL}: --max-depth must be >= 0", file=sys.stderr)
        return 2
    try:
        extensions = parse_extensions(args.extensions)
    except ValueError as exc:
        print(f"{TOOL}: {exc}", file=sys.stderr)
        return 2

    files, dirs_scanned, links_skipped, errors, root_error = \
        collect_files(args.paths, extensions)
    if root_error is not None:
        print(f"{TOOL}: {root_error}", file=sys.stderr)
        return 2

    min_rank = SEVERITIES[args.min_severity]
    all_findings = []  # (path, rule, severity, detail)
    file_rows = []     # (path, records)
    files_parsed = 0
    records_total = 0

    for path in files:
        audit = FileAudit(str(path))
        try:
            text = path.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeDecodeError):
            errors += 1
            continue
        if path.suffix.lower() in JSONL_EXTENSIONS:
            # JSONL is decided by suffix, including explicit file roots.
            audit_jsonl(audit, text, args.max_depth)
        else:
            audit_json_document(audit, text, args.max_depth)
        if audit.parsed:
            files_parsed += 1
            records_total += audit.records
            file_rows.append((audit.path, audit.records))
        for rule, severity, detail in audit.findings:
            if SEVERITIES[severity] >= min_rank:
                all_findings.append((audit.path, rule, severity, detail))

    all_findings.sort(key=lambda f: (f[0], f[1], f[3]))
    counts_by_sev = {"high": 0, "medium": 0, "low": 0}
    for _, _, severity, _ in all_findings:
        counts_by_sev[severity] += 1

    counts = {
        "dirs_scanned": dirs_scanned,
        "files_matched": len(files),
        "files_parsed": files_parsed,
        "records_total": records_total,
        "findings": len(all_findings),
        "high": counts_by_sev["high"],
        "medium": counts_by_sev["medium"],
        "low": counts_by_sev["low"],
        "links_skipped": links_skipped,
        "errors": errors,
    }

    if args.json:
        payload = {
            "tool": TOOL,
            "version": VERSION,
            "roots": list(args.paths),
            "counts": counts,
            "files": [{"path": p, "records": r} for p, r in file_rows],
            "findings": [
                {"path": p, "rule": rule, "severity": sev, "detail": det}
                for p, rule, sev, det in all_findings
            ],
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for p, rule, sev, det in all_findings:
            print(f"{sev.upper()} {rule} {p} [{det}]")
        for p, r in file_rows:
            print(f"file {p}: {r} records")
        print(f"{TOOL}: {dirs_scanned} dirs scanned, {len(files)} files "
              f"matched, {files_parsed} files parsed, {records_total} "
              f"records, {len(all_findings)} findings "
              f"({counts_by_sev['high']} high, {counts_by_sev['medium']} "
              f"medium, {counts_by_sev['low']} low), {links_skipped} links "
              f"skipped, {errors} errors")

    if args.fail_on == "never":
        return 0
    threshold = SEVERITIES[args.fail_on]
    for _, _, severity, _ in all_findings:
        if SEVERITIES[severity] >= threshold:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
