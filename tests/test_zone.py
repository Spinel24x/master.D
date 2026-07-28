import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dnscore.records import TYPE_A, TYPE_AAAA, TYPE_CNAME, TYPE_NS, TYPE_SOA, TYPE_TXT
from dnscore.zone import ZoneError, parse_ttl, parse_zone_text

SAMPLE = """
$ORIGIN example.com.
$TTL 1h

@   IN SOA ns1 hostmaster (
        2026072801 ; serial
        2h         ; refresh
        30m        ; retry
        2w         ; expire
        5m )       ; minimum

@       NS   ns1
@       NS   ns2
ns1     A    192.0.2.53
ns2     A    198.51.100.53
@       A    192.0.2.10
@       AAAA 2001:db8::10
www     CNAME @
api     600 A    192.0.2.20
        AAAA 2001:db8::20
@       MX   10 mail
mail    A    192.0.2.25
@       TXT  "v=spf1 mx -all"
info    TXT  "hello" " world"
*.dev   A    192.0.2.99
"""


class TTLTests(unittest.TestCase):
    def test_plain_seconds(self):
        self.assertEqual(parse_ttl("300"), 300)

    def test_units(self):
        self.assertEqual(parse_ttl("2h"), 7200)
        self.assertEqual(parse_ttl("30m"), 1800)
        self.assertEqual(parse_ttl("2w"), 1209600)
        self.assertEqual(parse_ttl("1h30m"), 5400)
        self.assertEqual(parse_ttl("1d12h"), 129600)

    def test_invalid(self):
        with self.assertRaises(ZoneError):
            parse_ttl("soon")


class ZoneParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.zone = parse_zone_text(SAMPLE)

    def test_origin(self):
        self.assertEqual(self.zone.origin, "example.com")

    def test_soa_fields_with_time_units(self):
        soa = self.zone.soa.rdata
        self.assertEqual(soa.mname, "ns1.example.com")
        self.assertEqual(soa.rname, "hostmaster.example.com")
        self.assertEqual(soa.serial, 2026072801)
        self.assertEqual(soa.refresh, 7200)
        self.assertEqual(soa.retry, 1800)
        self.assertEqual(soa.expire, 1209600)
        self.assertEqual(soa.minimum, 300)

    def test_default_ttl_from_directive(self):
        rr = self.zone.rrset("example.com", TYPE_A)[0]
        self.assertEqual(rr.ttl, 3600)

    def test_explicit_ttl_wins(self):
        rr = self.zone.rrset("api.example.com", TYPE_A)[0]
        self.assertEqual(rr.ttl, 600)

    def test_relative_names_get_origin(self):
        ns = sorted(rr.rdata for rr in self.zone.rrset("example.com", TYPE_NS))
        self.assertEqual(ns, ["ns1.example.com", "ns2.example.com"])

    def test_owner_inheritance(self):
        rr = self.zone.rrset("api.example.com", TYPE_AAAA)
        self.assertEqual(len(rr), 1)
        self.assertEqual(rr[0].rdata, "2001:db8::20")

    def test_cname_to_origin(self):
        rr = self.zone.rrset("www.example.com", TYPE_CNAME)[0]
        self.assertEqual(rr.rdata, "example.com")

    def test_txt_multiple_strings(self):
        rr = self.zone.rrset("info.example.com", TYPE_TXT)[0]
        self.assertEqual(rr.rdata, (b"hello", b" world"))

    def test_wildcard_node_exists(self):
        self.assertIsNotNone(self.zone.node("*.dev.example.com"))

    def test_empty_non_terminal_materialised(self):
        self.assertIsNotNone(self.zone.node("dev.example.com"))
        self.assertEqual(self.zone.node("dev.example.com"), {})

    def test_transfer_starts_and_ends_with_soa(self):
        records = list(self.zone.transfer_records())
        self.assertEqual(records[0].rtype, TYPE_SOA)
        self.assertEqual(records[-1].rtype, TYPE_SOA)
        self.assertEqual(records[0], records[-1])
        # every record exactly once, plus the closing SOA
        self.assertEqual(len(records), self.zone.record_count() + 1)

    def test_validate_passes(self):
        self.assertEqual(self.zone.validate(), [])


class ZoneErrorTests(unittest.TestCase):
    def test_missing_soa_fails_validation(self):
        zone = parse_zone_text("$ORIGIN x.test.\n@ A 192.0.2.1\n")
        with self.assertRaises(ZoneError):
            zone.validate()

    def test_out_of_zone_owner_rejected(self):
        with self.assertRaises(ZoneError):
            parse_zone_text(
                "$ORIGIN x.test.\n"
                "@ SOA ns1 root 1 2h 1h 2w 5m\n"
                "other.example. A 192.0.2.1\n"
            )

    def test_cname_and_other_data_rejected(self):
        with self.assertRaises(ZoneError):
            parse_zone_text(
                "$ORIGIN x.test.\n"
                "@ SOA ns1 root 1 2h 1h 2w 5m\n"
                "www CNAME @\n"
                "www A 192.0.2.1\n"
            )

    def test_unbalanced_parenthesis_rejected(self):
        with self.assertRaises(ZoneError):
            parse_zone_text("$ORIGIN x.test.\n@ SOA ns1 root ( 1 2h 1h 2w 5m\n")

    def test_bad_ipv4_rejected(self):
        with self.assertRaises(ZoneError):
            parse_zone_text(
                "$ORIGIN x.test.\n"
                "@ SOA ns1 root 1 2h 1h 2w 5m\n"
                "bad A 999.1.1.1\n"
            )

    def test_relative_name_without_origin_rejected(self):
        with self.assertRaises(ZoneError):
            parse_zone_text("www A 192.0.2.1\n")


if __name__ == "__main__":
    unittest.main()
