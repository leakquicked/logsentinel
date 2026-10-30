import unittest
from logsentinel import analyze, parse_line

class LogSentinelTests(unittest.TestCase):
    def test_failed_login_parsed(self):
        event = parse_line("Oct 30 10:01:02 host sshd: Failed password for admin from 203.0.113.8 port 22 ssh2", 1)
        self.assertEqual(event.event, "failed_login")
        self.assertEqual(event.source_ip, "203.0.113.8")
    def test_bruteforce_alert(self):
        lines = [f"Oct 30 10:01:0{i} host sshd: Failed password for admin from 203.0.113.8 port 22 ssh2" for i in range(5)]
        report = analyze(lines, threshold=5)
        self.assertEqual(report["summary"]["alerts"], 1)
    def test_unrelated_line_ignored(self):
        self.assertIsNone(parse_line("system boot complete", 1))

if __name__ == "__main__": unittest.main()
