# NetSentinel — Network Log Analyzer

NetSentinel is a defensive, offline analyzer for tcpdump-style text logs. It parses
packet records, aggregates traffic by source IP, flags simple high-signal patterns,
and can optionally request an LLM-generated explanation through Groq.

The detection pipeline works without an API key. LLM output is an explanatory aid,
not a detection engine or a security verdict.

## Features

- Parses supported tcpdump-style IPv4/IPv6 endpoint text records.
- Extracts source/destination IPs and ports, timestamps, and protocol labels.
- Aggregates packet volume, destination diversity, and protocol counts by source.
- Rule-based alerts for many distinct destination ports and high packet volume.
- JSON output suitable for downstream tools.
- Optional Groq explanation layer with cautious, evidence-based prompting.
- Unit tests for parsing and alert logic.

## Requirements

- Python 3.10+
- Optional: Groq API key for `--llm`

## Setup

```bash
python -m venv .venv
# macOS/Linux
source .venv/bin/activate
# Windows PowerShell
.venv\Scripts\Activate.ps1

pip install -e ".[dev]"
```

## Run

```bash
netsentinel samples/sample_tcpdump.log
netsentinel samples/sample_tcpdump.log --output reports/report.json
netsentinel samples/sample_tcpdump.log --port-scan-threshold 5
```

Run tests:

```bash
pytest
```

## Optional LLM explanations

```bash
pip install -e ".[llm]"
```

Set `GROQ_API_KEY` in your environment (or load it using your preferred secrets manager),
then run:

```bash
netsentinel samples/sample_tcpdump.log --llm
```

Never commit API keys. `.env.example` is a template only.

## Detection logic

- `possible_port_scan`: a source contacts at least N distinct destination ports in the
  supplied input file.
- `high_packet_volume`: a source generates at least M packet records in the input file.

These are simple heuristics, not proof of malicious activity. Thresholds should be
calibrated for the environment. The current implementation analyzes the whole input
file as one observation window; it does not perform time-window correlation or packet
payload inspection.

## Limitations

- The parser supports a common text representation, not every tcpdump output format.
- No packet capture is performed; supply a text log created separately.
- It does not identify malware, attribute attackers, or block traffic.
- LLM explanations can be inaccurate; verify all suggestions independently.

## Project structure

```text
netsentinel/
  analyzer.py
  cli.py
  llm.py
  parser.py
tests/
  test_analyzer.py
  test_parser.py
samples/
  sample_tcpdump.log
```

## License

MIT — see [LICENSE](LICENSE).
