#!/usr/bin/env python3
"""Syntax-level instrumentation scanner — The Software Field Guide, issue #61.

Extracts telemetry.event(...) and telemetry.metric(...) calls from
source files and emits the scan document the obs linter consumes:

    {"calls": [{"file", "line", "kind", "name", "labels"}]}

Deliberately NOT a parser: the scan is a deterministic, dependency-free
regular expression pass, honest about being syntax-level — the same
stance as the book's other companion tools (Roslyn ParseText-only, no
semantic binding). Calls spanning multiple lines are out of scope; the
demo keeps every call on one line.

Usage:  python3 scan/scan_instrumentation.py FILE... > scan.json
"""

import json
import re
import sys

EVENT_RE = re.compile(r'\btelemetry\.event\(\s*"([^"]+)"')
METRIC_RE = re.compile(r'\btelemetry\.metric\(\s*"([^"]+)"\s*,\s*\{')
LABEL_RE = re.compile(r'"([A-Za-z_][A-Za-z0-9_]*)"\s*:')


def scan_file(path):
    calls = []
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            m = METRIC_RE.search(line)
            if m:
                # from the opening brace of the label dict to the end of
                # the line: every "key": pattern inside is a label
                rest = line[m.end() - 1:]
                labels = sorted(set(LABEL_RE.findall(rest)))
                calls.append({
                    "file": path,
                    "line": lineno,
                    "kind": "metric",
                    "name": m.group(1),
                    "labels": labels,
                })
                continue
            m = EVENT_RE.search(line)
            if m:
                calls.append({
                    "file": path,
                    "line": lineno,
                    "kind": "event",
                    "name": m.group(1),
                    "labels": [],
                })
    return calls


def main(argv):
    if len(argv) < 2:
        sys.stderr.write(__doc__)
        return 2
    calls = []
    for path in argv[1:]:
        calls.extend(scan_file(path))
    calls.sort(key=lambda c: (c["file"], c["line"], c["kind"], c["name"]))
    json.dump({"calls": calls}, sys.stdout, indent="\t")
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
