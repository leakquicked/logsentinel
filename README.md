![Python checks](https://github.com/leakquicked/logsentinel/actions/workflows/python-checks.yml/badge.svg)

# LogSentinel

A lightweight, **local-first** authentication log analyzer for defensive security learning.

## Features
- Parses common Linux SSH authentication events: failed/accepted logins, invalid users, sudo activity and account-lock messages.
- Groups failed attempts by source IP and flags possible brute-force patterns.
- Exports JSON or CSV reports.
- Uses Python's standard library only. Log contents never leave your computer.

## Quick start
Requires Python 3.10+.

```bash
python logsentinel.py sample_auth.log
python logsentinel.py /var/log/auth.log --threshold 4 --format json --output report.json
python logsentinel.py sample_auth.log --format csv --output events.csv
python -m unittest discover -s tests -v
```

On some Linux systems, reading `/var/log/auth.log` requires appropriate permissions. Use only logs you are authorized to access.

## Detection notes
The brute-force rule counts matching failed-login and invalid-user events per source IP across the supplied file. It is a simple heuristic, not a SIEM correlation engine; timestamps are preserved as text and events are not correlated across hosts.

## Privacy & safety
- Files are read locally; this program makes no network requests.
- Review logs before sharing reports: they can contain usernames, IP addresses and other sensitive operational data.
- Use this tool only on systems and logs you are permitted to analyze.

## Project
MIT License. Educational defensive-security tooling.
