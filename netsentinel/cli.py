"""Command-line interface for NetSentinel."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analyzer import analyze_packets
from .llm import explain_with_groq
from .parser import parse_lines


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netsentinel",
        description="Analyze tcpdump-style text logs for basic suspicious traffic patterns.",
    )
    parser.add_argument("input", type=Path, help="Path to a tcpdump-style text log")
    parser.add_argument("--output", type=Path, help="Write JSON report to this path")
    parser.add_argument("--port-scan-threshold", type=int, default=12)
    parser.add_argument("--burst-threshold", type=int, default=80)
    parser.add_argument("--llm", action="store_true", help="Add optional Groq explanation")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if not args.input.exists():
        raise SystemExit(f"Input file does not exist: {args.input}")
    if args.port_scan_threshold < 1 or args.burst_threshold < 1:
        raise SystemExit("Thresholds must be positive integers.")

    with args.input.open(encoding="utf-8", errors="replace") as handle:
        packets, rejected = parse_lines(handle)

    report = analyze_packets(
        packets,
        port_scan_threshold=args.port_scan_threshold,
        connection_burst_threshold=args.burst_threshold,
    )
    report["rejected_line_count"] = len(rejected)
    report["rejected_lines_sample"] = rejected[:10]

    if args.llm:
        report["llm_explanation"] = explain_with_groq(report)

    rendered = json.dumps(report, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
