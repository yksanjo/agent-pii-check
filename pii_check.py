#!/usr/bin/env python3
"""Offline PII scanner for agent traces and artifacts.

Agents produce traces, logs, and reports that get shared: pasted into issues,
sent to vendors, committed to repos. PII inside them travels with them. This
tool scans a file or directory of traces/artifacts and reports where PII
appears, with the sensitive values masked in its own output. It never touches
the network, never calls a model, and cannot prove a file is PII-free - it is
a heuristic scanner for human review.
"""

import argparse
import json
import os
import re
import sys

SEVERITY_ORDER = {"info": 0, "warning": 1, "error": 2}
TEXT_EXTENSIONS = {".md", ".markdown", ".txt", ".jsonl", ".json", ".yaml", ".yml", ".log", ".csv"}

EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b")
PHONE_RE = re.compile(r"(?<![\w])(?:\+?1[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]\d{3}[\s.-]\d{4}(?![\w])")
SSN_RE = re.compile(r"\b(\d{3})-(\d{2})-(\d{4})\b")
CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
ADDRESS_RE = re.compile(r"\b\d{1,6}\s+(?:[A-Z][a-z]+\s){1,3}(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Way|Court|Ct|Parkway|Pkwy|Terrace|Place|Pl)\b")

# Well-known placeholder values that are not real PII.
PLACEHOLDER_DOMAINS = {"example.com", "example.org", "example.net", "localhost"}


def luhn_ok(digits):
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def ssn_ok(area, group, serial):
    return not (area == "000" or group == "00" or serial == "0000"
                or area == "666" or area.startswith("9"))


def mask(text, keep=2):
    """Mask a matched value so the report itself does not leak it."""
    if len(text) <= keep * 2:
        return "*" * len(text)
    return text[:keep] + "*" * (len(text) - keep * 2) + text[-keep:]


def finding(code, severity, source, line_no, detail):
    return {"code": code, "severity": severity, "source": "%s:%d" % (source, line_no),
            "detail": detail}


def scan_text(source, line_no, text, findings):
    for m in EMAIL_RE.finditer(text):
        addr = m.group(0)
        domain = addr.split("@", 1)[1].lower()
        if domain in PLACEHOLDER_DOMAINS:
            continue
        findings.append(finding("email", "warning", source, line_no,
                                "email address %s" % mask(addr, 1)))
    for m in PHONE_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        national = digits[-10:]
        # 555-0100 through 555-0199 are reserved for fiction.
        if national[3:6] == "555" and 100 <= int(national[6:]) <= 199:
            continue
        findings.append(finding("phone", "warning", source, line_no,
                                "phone number %s" % mask(m.group(0), 3)))
    for m in SSN_RE.finditer(text):
        area, group, serial = m.groups()
        if ssn_ok(area, group, serial):
            findings.append(finding("ssn", "error", source, line_no,
                                    "US social security number ***-**-%s" % serial))
    for m in CARD_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if luhn_ok(digits):
            findings.append(finding("payment-card", "error", source, line_no,
                                    "%d-digit number passing the Luhn check, masked ****%s"
                                    % (len(digits), digits[-4:])))
    for m in ADDRESS_RE.finditer(text):
        findings.append(finding("street-address", "info", source, line_no,
                                "possible street address '%s'" % mask(m.group(0), 6)))


def iter_entries(path):
    with open(path, errors="replace") as f:
        raw = f.read()
    if path.endswith(".jsonl"):
        for i, line in enumerate(raw.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                yield i, line
                continue
            if isinstance(rec, dict):
                text = rec.get("text") or rec.get("content") or rec.get("body") or ""
                yield i, str(text) if text else line
            else:
                yield i, line
    else:
        for i, line in enumerate(raw.splitlines(), 1):
            if line.strip():
                yield i, line


def scan(path):
    findings = []
    files = []
    if os.path.isfile(path):
        files.append(path)
    elif os.path.isdir(path):
        for root, _dirs, names in os.walk(path):
            for name in sorted(names):
                if os.path.splitext(name)[1].lower() in TEXT_EXTENSIONS:
                    files.append(os.path.join(root, name))
    else:
        return [finding("no-input", "error", path, 0, "path not found")]
    if not files:
        return [finding("no-input", "error", path, 0, "no scannable text files found")]
    for f in files:
        for line_no, text in iter_entries(f):
            scan_text(f, line_no, text, findings)
    return findings


def filter_severity(findings, min_severity):
    floor = SEVERITY_ORDER[min_severity]
    return [f for f in findings if SEVERITY_ORDER[f["severity"]] >= floor]


def format_text(findings):
    return "\n".join("%-7s %-15s %-26s %s" % (
        f["severity"].upper(), f["code"], f["source"], f["detail"])
        for f in findings)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Scan agent traces and artifacts for PII before sharing them.")
    parser.add_argument("path", help="file or directory to scan")
    parser.add_argument("--min-severity", choices=["info", "warning", "error"], default="info")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    args = parser.parse_args(argv)

    findings = filter_severity(scan(args.path), args.min_severity)
    if args.format == "json":
        print(json.dumps(findings, indent=2))
    elif findings:
        print(format_text(findings))
    else:
        print("no findings")
    return 1 if any(f["severity"] == "error" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
