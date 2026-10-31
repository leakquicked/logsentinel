import unittest

from logsentinel import analyze, parse_line


class LogSentinelTests(unittest.TestCase):
    def test_failed_login_parsed(self):
        event = parse_line(
            "Oct 30 10:01:02 host sshd: Failed password for admin from 203.0.113.8 port 22 ssh2",
            1,
        )
        self.assertEqual(event.event, "failed_login")
        self.assertEqual(event.source_ip, "203.0.113.8")

    def test_bruteforce_alert_at_threshold(self):
        lines = [
            f"Oct 30 10:01:0{i} host sshd: Failed password for admin from 203.0.113.8 port 22 ssh2"
            for i in range(5)
        ]
        report = analyze(lines, threshold=5)
        self.assertEqual(report["summary"]["alerts"], 1)
        self.assertEqual(report["alerts"][0]["failed_attempts"], 5)

    def test_no_alert_below_threshold(self):
        lines = [
            "Oct 30 10:01:02 host sshd: Failed password for admin from 203.0.113.8 port 22 ssh2"
        ] * 4
        self.assertEqual(analyze(lines, threshold=5)["summary"]["alerts"], 0)

    def test_invalid_ipv4_is_rejected(self):
        line = "Oct 30 10:01:02 host sshd: Failed password for admin from 999.1.1.1 port 22 ssh2"
        self.assertIsNone(parse_line(line, 1))

    def test_ipv6_is_supported(self):
        line = "Oct 30 10:01:02 host sshd: Failed password for admin from 2001:db8::1 port 22 ssh2"
        event = parse_line(line, 1)
        self.assertEqual(event.source_ip, "2001:db8::1")

    def test_successful_login_is_parsed(self):
        line = "Oct 30 10:01:02 host sshd: Accepted publickey for alice from 192.0.2.4 port 22 ssh2"
        event = parse_line(line, 1)
        self.assertEqual(event.event, "accepted_login")
        self.assertEqual(event.username, "alice")

    def test_unrelated_line_ignored(self):
        self.assertIsNone(parse_line("system boot complete", 1))

    def test_non_string_line_ignored(self):
        self.assertIsNone(parse_line(None, 1))

    def test_threshold_must_be_at_least_two(self):
        with self.assertRaises(ValueError):
            analyze([], threshold=1)


if __name__ == "__main__":
    unittest.main()
