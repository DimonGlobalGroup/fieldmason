# FieldMason

**Audit the shape of JSON and JSON Lines record collections — read-only, one file, no dependencies.**

Parses are not proof of health. A field can be a number in 400
records and a string in 3. A key can quietly disappear from newer
records. A duplicate key can silently overwrite a value while every
record still parses — standard parsers keep the last value and say
nothing. FieldMason scans a whole tree of `.json` / `.jsonl` /
`.ndjson` files and reports that drift under named rules, in one
deterministic report with a CI-shaped exit code.

```console
$ fieldmason scan ./data
MEDIUM type-drift data/events.jsonl [field 'age': types number, string across 312 records]
LOW key-drift data/events.jsonl [field 'note' present in 287 of 312 records]
file data/events.jsonl: 312 records
fieldmason: 1 dirs scanned, 1 files matched, 1 files parsed, 312 records, 2 findings (0 high, 1 medium, 1 low), 0 links skipped, 0 errors
```

## Why it is different

- **The collection is the unit, not the document.** Syntax linters
  validate one file at a time. FieldMason compares records against
  each other — within a JSONL file, within a top-level JSON array,
  and file by file across a tree — and reports where the shape
  changed.
- **Duplicate keys are findings, not silent data loss.** Parsing
  runs through a pairs hook, so a repeated key is reported instead
  of the last value quietly winning.
- **Gate-shaped, not editor-shaped.** Named rules, severities,
  `--min-severity` / `--fail-on` thresholds, deterministic text or
  JSON output, exit 0/1/2 — built to stand in front of a backup, a
  restore, or a commit.
- **Read-only by construction.** It never rewrites, repairs,
  normalises, or deletes anything. Its whole write surface is
  stdout, so it can run against data you do not trust yet.

## Install

Nothing to install beyond Python 3.10+ (standard library only):

```console
$ cp fieldmason.py ~/bin/fieldmason && chmod +x ~/bin/fieldmason
```

## Usage

```console
$ fieldmason scan PATH [PATH ...] [--json] \
    [--min-severity low|medium|high] \
    [--fail-on low|medium|high|never] \
    [--max-depth N] [--extensions .json,.jsonl,.ndjson]
```

Each path may be a file or a directory (walked recursively, in
sorted order; symlinks are counted and never followed). Files
ending `.jsonl` / `.ndjson` are parsed as JSON Lines; other matched
files are parsed as one JSON document, whose records are its
top-level array elements if it is an array, otherwise the document
itself. An explicitly named file is always audited, whatever its
suffix.

### Example

```console
$ cat demo.jsonl
{"id": 1, "age": 30}
{"id": 2, "age": "old"}

$ fieldmason scan demo.jsonl
MEDIUM type-drift demo.jsonl [field 'age': types number, string across 2 records]
file demo.jsonl: 2 records
fieldmason: 0 dirs scanned, 1 files matched, 1 files parsed, 2 records, 1 findings (0 high, 1 medium, 0 low), 0 links skipped, 0 errors
```

(Medium findings do not fail the default `--fail-on high` gate, so
that run exits 0; add `--fail-on medium` to gate on drift.)

## Rules

| Rule | Severity | Meaning |
|---|---|---|
| `parse-error` | high | A JSON document, or one JSONL line, fails to parse (line/column reported; other lines still audit) |
| `duplicate-key` | high | An object repeats a key — a standard parser would silently keep only the last value |
| `empty-file` | medium | The file is empty or whitespace only (JSONL: no non-blank lines) |
| `record-type-drift` | medium | A file's records have more than one top-level JSON type |
| `type-drift` | medium | A top-level field holds two or more distinct non-null types across a file's object records |
| `key-drift` | low | A top-level field is present in some but not all of a file's object records |
| `big-int` | low | An integer exceeds the safe integer range (2^53 − 1) and would lose precision in many consumers |
| `deep-nesting` | low | A record nests deeper than `--max-depth` (default 20) |
| `blank-line` | low | A JSONL file contains blank lines |

Exit codes: **0** = no finding at or above `--fail-on`;
**1** = at least one such finding; **2** = usage or scan-root
error. Findings below `--min-severity` are excluded from output,
counts, and the exit decision.

## Limitations, honestly

- Drift is judged per file, not across files: two files that
  disagree with each other are each reported on their own records.
- Only top-level fields are compared for `type-drift` / `key-drift`;
  nested shape changes surface only through `big-int`,
  `deep-nesting`, and `duplicate-key`.
- Duplicate-key findings name the key and its count, not the exact
  byte offset of each occurrence.
- This is an auditor, not a fixer: it never edits the data it
  reports on.

## Tests

```console
$ python3 -m unittest test_fieldmason -v
```

## License

MIT — see `LICENSE`. A Dimon Global Group release.
