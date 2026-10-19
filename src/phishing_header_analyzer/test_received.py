import unittest
from datetime import datetime, timezone

from phishing_header_analyzer.received import parse_chain, parse_received


class ParseReceivedTests(unittest.TestCase):
    def test_full_hop(self):
        hop = parse_received(
            "from mail.contoso-bank.example (mail.contoso-bank.example [198.51.100.20])\n"
            "\tby mx1.northwind.example (Postfix) with ESMTPS id 4F1A2B3C4D\n"
            "\tfor <analyst@northwind.example>; Mon, 19 Oct 2026 14:02:09 -0500"
        )
        self.assertEqual(hop.from_host, "mail.contoso-bank.example")
        self.assertEqual(hop.from_ip, "198.51.100.20")
        self.assertEqual(hop.by_host, "mx1.northwind.example")
        self.assertEqual(hop.protocol, "ESMTPS")
        self.assertEqual(hop.timestamp, datetime(2026, 10, 19, 19, 2, 9, tzinfo=timezone.utc))
        self.assertEqual(hop.parse_notes, [])

    def test_ip_taken_from_from_clause_only(self):
        hop = parse_received("from a.example by b.example [192.0.2.99] with SMTP; Mon, 19 Oct 2026 10:00:00 +0000")
        self.assertIsNone(hop.from_ip)

    def test_ipv6(self):
        hop = parse_received("from a.example ([IPv6:2001:db8::1]) by b.example; Mon, 19 Oct 2026 10:00:00 +0000")
        self.assertEqual(hop.from_ip, "2001:db8::1")

    def test_missing_timestamp_noted(self):
        hop = parse_received("from a.example by b.example with SMTP")
        self.assertIsNone(hop.timestamp)
        self.assertIn("no timestamp found", hop.parse_notes)

    def test_bad_ip_noted(self):
        hop = parse_received("from a.example ([999.1.1.1]) by b.example; Mon, 19 Oct 2026 10:00:00 +0000")
        self.assertIsNone(hop.from_ip)
        self.assertTrue(any("unparseable IP" in n for n in hop.parse_notes))


class ParseChainTests(unittest.TestCase):
    def test_order_and_delays(self):
        # As they appear in a message: newest (top) first.
        values = [
            "from b.example ([192.0.2.2]) by c.example; Mon, 19 Oct 2026 10:00:30 +0000",
            "from a.example ([192.0.2.1]) by b.example; Mon, 19 Oct 2026 10:00:10 +0000",
        ]
        hops = parse_chain(values)
        self.assertEqual([h.index for h in hops], [1, 2])
        self.assertEqual(hops[0].from_host, "a.example")
        self.assertIsNone(hops[0].delay_seconds)
        self.assertEqual(hops[1].delay_seconds, 20.0)

    def test_out_of_order_gives_negative_delay(self):
        values = [
            "from b.example by c.example; Mon, 19 Oct 2026 10:00:00 +0000",
            "from a.example by b.example; Mon, 19 Oct 2026 12:00:00 +0000",
        ]
        hops = parse_chain(values)
        self.assertLess(hops[1].delay_seconds, 0)


if __name__ == "__main__":
    unittest.main()
