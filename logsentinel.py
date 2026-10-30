#!/usr/bin/env python3
"""LogSentinel: local SSH/authentication log analyzer. No network access."""
from __future__ import annotations
import argparse, csv, json, re, sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

IP = r"(?:\d{1,3}\.){3}\d{1,3}"
PATTERNS = [
    ("failed_login", re.compile(rf"Failed password for (?:invalid user )?(\S+) from ({IP})", re.I), "high"),
    ("invalid_user", re.compile(rf"Invalid user (\S+) from ({IP})", re.I), "medium"),
    ("accepted_login", re.compile(rf"Accepted (?:password|publickey) for (\S+) from ({IP})", re.I), "info"),
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
    for kind, pattern, severity in PATTERNS:
        match = pattern.search(text)
        if match:
            groups = match.groups()
            user = groups[0] if groups else ""
            ip = groups[1] if len(groups) > 1 and kind in ("failed_login", "invalid_user", "accepted_login") else ""
            return Event(number, text[:15].strip(), kind, severity, user, ip, text.rstrip())
    return None

def analyze(lines, threshold=5):
    events = [e for i, line in enumerate(lines, 1) if (e := parse_line(line, i))]
    failures = Counter(e.source_ip for e in events if e.event in ("failed_login", "invalid_user") and e.source_ip)
    alerts = [{"type":"possible_brute_force","source_ip":ip,"failed_attempts":count,
               "severity":"critical" if count >= threshold * 2 else "high"}
              for ip, count in failures.items() if count >= threshold]
    return {"summary":{"lines_scanned":len(lines),"events_found":len(events),
                       "failed_logins":sum(e.event in ("failed_login","invalid_user") for e in events),
                       "successful_logins":sum(e.event=="accepted_login" for e in events),
                       "unique_source_ips":len({e.source_ip for e in events if e.source_ip}),
                       "alerts":len(alerts)},
            "alerts":alerts,"events":[asdict(e) for e in events]}

def main():
    p=argparse.ArgumentParser(description="Analyze a local authentication log file.")
    p.add_argument("file", type=Path, help="Local log file to analyze")
    p.add_argument("--threshold",type=int,default=5,help="Failed attempts per IP before alert (default: 5)")
    p.add_argument("--format",choices=("json","csv"),default="json")
    p.add_argument("--output",type=Path,help="Write report to this path; otherwise stdout")
    a=p.parse_args()
    if a.threshold < 2: p.error("--threshold must be at least 2")
    try: lines=a.file.read_text(encoding="utf-8",errors="replace").splitlines()
    except OSError as exc: p.error(str(exc))
    report=analyze(lines,a.threshold)
    if a.format=="json": result=json.dumps(report,indent=2,ensure_ascii=False)
    else:
        import io
        out=io.StringIO(); w=csv.DictWriter(out,fieldnames=list(Event.__dataclass_fields__))
        w.writeheader(); w.writerows(report["events"]); result=out.getvalue()
    if a.output: a.output.write_text(result+"\n",encoding="utf-8")
    else: print(result)
    print(f"LogSentinel: {report['summary']['events_found']} events, {report['summary']['alerts']} alert(s).",file=sys.stderr)
if __name__=="__main__": main()
