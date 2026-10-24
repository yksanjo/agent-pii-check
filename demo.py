#!/usr/bin/env python3
"""Synthetic demo: a support-bundle trace with PII mixed into ordinary
content. All values are invented; the card number is the card networks'
universal published test number."""

import os
import tempfile

import pii_check as pc

FILES = {
    "trace.jsonl": (
        '{"type": "call", "id": "s1", "tool": "calendar.read", '
        '"text": "Found 3 events for next Tuesday."}\n'
        '{"type": "result", "id": "s1", "ok": true, '
        '"text": "Lunch with Dana Revera, d.revera@brightlabs.io, 415-202-9481"}\n'
        '{"type": "call", "id": "s2", "tool": "payments.lookup", '
        '"text": "Card on file 4111 1111 1111 1111 exp 12/29"}\n'
        '{"type": "result", "id": "s2", "ok": true, '
        '"text": "Billing address 1600 Amphitheatre Parkway, verified."}\n'
    ),
    "notes.md": (
        "# Support notes\n"
        "Customer asked about invoice 8842. Account holder SSN 078-05-1120 "
        "was pasted into the ticket by mistake.\n"
        "Docs example (safe): contact bob@example.com or call 212-555-0148.\n"
    ),
}


def main():
    d = tempfile.mkdtemp()
    for name, text in FILES.items():
        with open(os.path.join(d, name), "w") as f:
            f.write(text)
    print("bundle directory:", d)
    print("files:", ", ".join(sorted(FILES)))
    print()
    findings = pc.scan(d)
    print(pc.format_text(findings) if findings else "no findings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
