import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dnscore.message import Message, Question
from dnscore.records import (
    TYPE_A,
    TYPE_AAAA,
    TYPE_ANY,
    TYPE_CNAME,
    TYPE_MX,
    TYPE_NS,
    TYPE_PTR,
    TYPE_SOA,
    TYPE_TXT,
)
from dnscore.resolver import Resolver
from dnscore.wire import (
    RCODE_NOERROR,
    RCODE_NOTIMP,
    RCODE_NXDOMAIN,
    RCODE_REFUSED,
)
from dnscore.zone import parse_zone_text

FORWARD = """
$ORIGIN example.com.
$TTL 3600
@   SOA ns1 hostmaster ( 2026072801 2h 1h 2w 5m )
@   NS   ns1
@   NS   ns2
ns1 A    192.0.2.53
ns2 A    198.51.100.53
@   A    192.0.2.10
@   AAAA 2001:db8::10
www CNAME @
ftp CNAME www
api A    192.0.2.20
mail A   192.0.2.25
@   MX   10 mail
@   MX   20 backup.mail.example.net.
@   TXT  "v=spf1 mx -all"
*.dev A  192.0.2.99
"""

REVERSE = """
$ORIGIN 2.0.192.in-addr.arpa.
$TTL 3600
@  SOA ns1.example.com. hostmaster.example.com. ( 1 2h 1h 2w 5m )
@  NS  ns1.example.com.
10 PTR example.com.
"""


def q(name, qtype, qclass=1, opcode=0):
    msg = Message(id=1, flags=(opcode & 0xF) << 11)
    msg.questions.append(Question(name.lower().rstrip("."), qtype, qclass, raw_qname=name))
    return msg


class ResolverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.resolver = Resolver([parse_zone_text(FORWARD), parse_zone_text(REVERSE)])

    # -- positive answers ---------------------------------------------------

    def test_a_query(self):
        resp = self.resolver.resolve(q("example.com", TYPE_A))
        self.assertEqual(resp.rcode, RCODE_NOERROR)
        self.assertTrue(resp.aa)
        self.assertEqual([rr.rdata for rr in resp.answers], ["192.0.2.10"])

    def test_aaaa_query(self):
        resp = self.resolver.resolve(q("example.com", TYPE_AAAA))
        self.assertEqual([rr.rdata for rr in resp.answers], ["2001:db8::10"])

    def test_case_insensitive_lookup(self):
        resp = self.resolver.resolve(q("ExAmPlE.CoM", TYPE_A))
        self.assertEqual(len(resp.answers), 1)
        self.assertEqual(resp.questions[0].raw_qname, "ExAmPlE.CoM")

    def test_cname_chain_is_chased(self):
        resp = self.resolver.resolve(q("ftp.example.com", TYPE_A))
        self.assertEqual(
            [(rr.name, rr.rtype) for rr in resp.answers],
            [
                ("ftp.example.com", TYPE_CNAME),
                ("www.example.com", TYPE_CNAME),
                ("example.com", TYPE_A),
            ],
        )

    def test_cname_query_returns_cname_itself(self):
        resp = self.resolver.resolve(q("www.example.com", TYPE_CNAME))
        self.assertEqual(len(resp.answers), 1)
        self.assertEqual(resp.answers[0].rtype, TYPE_CNAME)

    def test_any_query_returns_all_rrsets(self):
        resp = self.resolver.resolve(q("example.com", TYPE_ANY))
        types = {rr.rtype for rr in resp.answers}
        self.assertEqual(types, {TYPE_SOA, TYPE_NS, TYPE_A, TYPE_AAAA, TYPE_MX, TYPE_TXT})

    def test_ptr_in_second_zone(self):
        resp = self.resolver.resolve(q("10.2.0.192.in-addr.arpa", TYPE_PTR))
        self.assertEqual([rr.rdata for rr in resp.answers], ["example.com"])

    # -- wildcards ------------------------------------------------------------

    def test_wildcard_synthesis(self):
        resp = self.resolver.resolve(q("foo.dev.example.com", TYPE_A))
        self.assertEqual(len(resp.answers), 1)
        self.assertEqual(resp.answers[0].name, "foo.dev.example.com")
        self.assertEqual(resp.answers[0].rdata, "192.0.2.99")

    def test_wildcard_matches_multiple_labels(self):
        resp = self.resolver.resolve(q("a.b.dev.example.com", TYPE_A))
        self.assertEqual(resp.answers[0].name, "a.b.dev.example.com")

    def test_wildcard_nodata_for_other_type(self):
        resp = self.resolver.resolve(q("foo.dev.example.com", TYPE_AAAA))
        self.assertEqual(resp.rcode, RCODE_NOERROR)
        self.assertEqual(len(resp.answers), 0)
        self.assertEqual(resp.authorities[0].rtype, TYPE_SOA)

    def test_empty_non_terminal_is_nodata_not_nxdomain(self):
        resp = self.resolver.resolve(q("dev.example.com", TYPE_A))
        self.assertEqual(resp.rcode, RCODE_NOERROR)
        self.assertEqual(len(resp.answers), 0)

    # -- negatives ------------------------------------------------------------

    def test_nxdomain_with_negative_ttl(self):
        resp = self.resolver.resolve(q("nope.example.com", TYPE_A))
        self.assertEqual(resp.rcode, RCODE_NXDOMAIN)
        self.assertTrue(resp.aa)
        soa = resp.authorities[0]
        self.assertEqual(soa.rtype, TYPE_SOA)
        self.assertEqual(soa.ttl, 300)  # min(3600, SOA minimum 300)

    def test_nodata_for_existing_name(self):
        resp = self.resolver.resolve(q("api.example.com", TYPE_MX))
        self.assertEqual(resp.rcode, RCODE_NOERROR)
        self.assertEqual(len(resp.answers), 0)
        self.assertEqual(resp.authorities[0].rtype, TYPE_SOA)

    def test_refused_outside_authority(self):
        resp = self.resolver.resolve(q("other.org", TYPE_A))
        self.assertEqual(resp.rcode, RCODE_REFUSED)
        self.assertFalse(resp.aa)

    def test_notimp_for_non_query_opcode(self):
        resp = self.resolver.resolve(q("example.com", TYPE_A, opcode=4))
        self.assertEqual(resp.rcode, RCODE_NOTIMP)

    def test_refused_for_chaos_class(self):
        resp = self.resolver.resolve(q("example.com", TYPE_A, qclass=3))
        self.assertEqual(resp.rcode, RCODE_REFUSED)

    # -- additional-section processing ---------------------------------------

    def test_ns_answers_carry_glue(self):
        resp = self.resolver.resolve(q("example.com", TYPE_NS))
        glue = {(rr.name, rr.rdata) for rr in resp.additionals}
        self.assertIn(("ns1.example.com", "192.0.2.53"), glue)
        self.assertIn(("ns2.example.com", "198.51.100.53"), glue)

    def test_mx_answers_carry_in_zone_glue_only(self):
        resp = self.resolver.resolve(q("example.com", TYPE_MX))
        names = {rr.name for rr in resp.additionals}
        self.assertEqual(names, {"mail.example.com"})


if __name__ == "__main__":
    unittest.main()
