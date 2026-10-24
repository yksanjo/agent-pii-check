# agent-pii-check

Offline PII scanner for agent traces and artifacts.

Agents produce traces, logs, and reports that get shared: pasted into issues, sent to vendors, committed to repos. PII inside them travels with them. This tool scans a file or directory before it leaves and reports where PII appears - with the sensitive values masked in its own output, so the report doesn't become a second leak. It never touches the network, never calls a model.

## What it reports

| Code | Severity | Signal |
| --- | --- | --- |
| `payment-card` | error | 13-19 digit run passing the Luhn check |
| `ssn` | error | US SSN shape with valid area/group/serial rules |
| `email` | warning | email address (placeholder domains like example.com skipped) |
| `phone` | warning | US/international phone shape (555-0100..0199 fiction range skipped) |
| `street-address` | info | number + street-name pattern, heuristic |
| `no-input` | error | path missing or no scannable files |

Validation is deliberately conservative: the Luhn check and the SSN area rules exist to cut false positives on ordinary digit runs, and fictional/placeholder values are skipped so examples in docs don't drown the signal.

## Usage

```bash
python3 pii_check.py ./support-bundle
python3 pii_check.py trace.jsonl --min-severity warning
python3 pii_check.py notes.md --format json
python3 demo.py
python3 -m unittest test_pii_check
```

Scans `.md`, `.txt`, `.jsonl`, `.json`, `.yaml`, `.yml`, `.log`, `.csv` files. JSONL traces are read record by record (`text`, `content`, or `body` fields); other files line by line. Exit code is 1 when any reported finding is an error, else 0 - wire it in front of whatever shares or commits the artifact.

## Honest limits

- **A clean scan does not prove a file is PII-free.** Regex heuristics miss names without context, international ID formats, dates of birth, free-form addresses, and anything non-standard. They also flag false positives (long IDs that pass Luhn, phone-shaped order numbers).
- Street-address detection is the weakest pattern - info severity only, expect both misses and noise.
- Masked previews still leak length and fragments; treat the report itself as sensitive when the source is.
- It scans text as stored. It cannot tell whose data it is, whether sharing is authorized, or what consent applies - those are decisions for whoever runs the check.
- US-centric patterns (SSN, phone shapes). Other countries' ID formats are not covered.
- Demo fixtures are synthetic; the card number is the card networks' published test number and the SSN is the SSA's historical advertising example.

## License

MIT
