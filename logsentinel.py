#!/usr/bin/env python3
"""LogSentinel: local SSH/authentication log analyzer. No network access."""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

IP_TOKEN = r"(\S+)"
PATTERNS = [
    ("failed_login", re.compile(rf"Failed password for (?:invalid user )?(\S+) from {IP_TOKEN}", re.I), "high"),
    ("invalid_user", re.compile(rf"Invalid user (\S+) from {IP_TOKEN}", re.I), "medium"),
    ("accepted_login", re.compile(rf"Accepted (?:password|publickey) for (\S+) from {IP_TOKEN}", re.I), "info"),
    ("sudo", re.compile(r"sudo:.*?\b(\S+)\s*:", re.I), "low"),
    ("account_locked", re.compile(r"account .* locked|user .* locked", re.I), "high"),
]


@dataclass
class Event:
    line: int
    timestamp: str
    event: str
    severity: str
    username: str = ""
    source_ip: str = ""
    raw: str = ""


def parse_line(text: str, number: int) -> Event | None:
    """Parse one syslog-style line; reject malformed source IP addresses."""
    if not isinstance(text, str):
        return None

    for kind, pattern, severity in PATTERNS:
        match = pattern.search(text)
        if not match:
            continue

        groups = match.groups()
        username = groups[0] if groups else ""
        source_ip = ""

        if kind in ("failed_login", "invalid_user", "accepted_login"):
            candidate = groups[1]
            try:
                source_ip = str(ipaddress.ip_address(candidate))
            except ValueError:
                continue

        return Event(
            line=number,
            timestamp=text[:15].strip(),
            event=kind,
            severity=severity,
            username=username,
            source_ip=source_ip,
            raw=text.rstrip(),
        )
    return None


def analyze(lines, threshold: int = 5):
    """Analyze an iterable of log lines and return a JSON-serializable report."""
    if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 2:
        raise ValueError("threshold must be an integer greater than or equal to 2")

    events = [
        event
        for line_number, line in enumerate(lines, 1)
        if (event := parse_line(line, line_number)) is not None
    ]

    failed_events = {"failed_login", "invalid_user"}
    failures = Counter(
        event.source_ip
        for event in events
        if event.event in failed_events and event.source_ip
    )
    alerts = [
        {
            "type": "possible_brute_force",
            "source_ip": source_ip,
            "failed_attempts": count,
            "severity": "critical" if count >= threshold * 2 else "high",
        }
        for source_ip, count in sorted(failures.items())
        if count >= threshold
    ]

    return {
        "summary": {
            "lines_scanned": len(lines) if hasattr(lines, "__len__") else sum(1 for _ in []),
            "events_found": len(events),
            "failed_logins": sum(event.event in failed_events for event in events),
            "successful_logins": sum(event.event == "accepted_login" for event in events),
            "unique_source_ips": len({event.source_ip for event in events if event.source_ip}),
            "alerts": len(alerts),
        },
        "alerts": alerts,
        "events": [asdict(event) for event in events],
    }


def main():
    parser = argparse.ArgumentParser(description="Analyze a local authentication log file.")
    parser.add_argument("file", type=Path, help="Local log file to analyze")
    parser.add_argument("--threshold", type=int, default=5, help="Failed attempts per IP before alert (default: 5)")
    parser.add_argument("--format", choices=("json", "csv"), default="json")
    parser.add_argument("--output", type=Path, help="Write report to this path; otherwise stdout")
    args = parser.parse_args()

    if args.threshold < 2:
        parser.error("--threshold must be at least 2")

    try:
        lines = args.file.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        parser.error(str(exc))

    report = analyze(lines, args.threshold)
    if args.format == "json":
        result = json.dumps(report, indent=2, ensure_ascii=False)
    else:
        import io
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=list(Event.__dataclass_fields__))
        writer.writeheader()
        writer.writerows(report["events"])
        result = output.getvalue()

    try:
        if args.output:
            args.output.write_text(result + "\n", encoding="utf-8")
        else:
            print(result)
    except OSError as exc:
        parser.error(f"cannot write report: {exc}")

    print(
        f"LogSentinel: {report['summary']['events_found']} events, "
        f"{report['summary']['alerts']} alert(s).",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
