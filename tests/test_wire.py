import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dnscore import wire
from dnscore.message import Message, Question, build, parse_message
from dnscore.wire import FLAG_RD, FLAG_TC, MessageWriter, WireError, read_name


class NameCodecTests(unittest.TestCase):
    def test_roundtrip_with_compression(self):
        w = MessageWriter(0, 0)
        w.write_name("example.com")       # written in full at offset 12
        w.write_name("www.example.com")   # "www" + pointer
        w.write_name("example.com")       # bare pointer
        data = w.take()

        name1, off1 = read_name(data, 12)
        self.assertEqual(name1, "example.com")
        name2, off2 = read_name(data, off1)
        self.assertEqual(name2, "www.example.com")
        name3, off3 = read_name(data, off2)
        self.assertEqual(name3, "example.com")
        self.assertEqual(off3 - off2, 2, "third name should be a bare 2-octet pointer")

    def test_root_name(self):
        w = MessageWriter(0, 0)
        w.write_name("")
        data = w.take()
        self.assertEqual(data[12], 0)
        self.assertEqual(read_name(data, 12), ("", 13))

    def test_compression_is_case_insensitive_but_case_preserving(self):
        w = MessageWriter(0, 0)
        w.write_name("EXAMPLE.Com")
        w.write_name("www.example.COM")   # must compress against the first name
        data = w.take()
        self.assertIn(b"EXAMPLE", data)   # original case on the wire
        name2, off2 = read_name(data, 12 + 1 + 7 + 1 + 3 + 1)
        self.assertEqual(name2, "www.example.com")
        # "www" label (4 octets) + pointer (2 octets)
        self.assertEqual(off2 - (12 + 13), 4 + 2)

    def test_pointer_loop_rejected(self):
        data = bytes(12) + b"\xc0\x0c"    # name at 12 points at itself
        with self.assertRaises(WireError):
            read_name(data, 12)

    def test_forward_pointer_rejected(self):
        data = bytes(12) + b"\xc0\x20" + bytes(40)
        with self.assertRaises(WireError):
            read_name(data, 12)

    def test_truncated_name_rejected(self):
        data = bytes(12) + b"\x05exa"
        with self.assertRaises(WireError):
            read_name(data, 12)

    def test_label_too_long_rejected(self):
        with self.assertRaises(WireError):
            wire.split_labels("a" * 64 + ".com")

    def test_name_too_long_rejected(self):
        name = ".".join(["a" * 63] * 4)   # 4*64 = 256 > 255
        with self.assertRaises(WireError):
            wire.split_labels(name)


class MessageRoundtripTests(unittest.TestCase):
    def test_query_roundtrip_preserves_case(self):
        q = Message(id=0x1234, flags=FLAG_RD)
        q.questions.append(Question("www.example.com", 1, 1, raw_qname="WwW.Example.Com"))
        parsed = parse_message(build(q))
        self.assertEqual(parsed.id, 0x1234)
        self.assertTrue(parsed.rd)
        self.assertFalse(parsed.qr)
        self.assertEqual(parsed.questions[0].qname, "www.example.com")
        self.assertEqual(parsed.questions[0].raw_qname, "WwW.Example.Com")

    def test_short_message_rejected(self):
        with self.assertRaises(WireError):
            parse_message(b"\x00\x01\x00")

    def test_truncation_sets_tc_and_drops_answers(self):
        from dnscore.records import RR, TYPE_A

        msg = Message(id=7, flags=wire.FLAG_QR)
        msg.questions.append(Question("big.example.com", 1, 1))
        for i in range(60):
            msg.answers.append(RR("big.example.com", TYPE_A, 1, 60, "192.0.2.%d" % (i % 250 + 1)))
        full = build(msg)
        self.assertGreater(len(full), 512)
        limited = build(msg, max_size=512)
        self.assertLessEqual(len(limited), 512)
        parsed = parse_message(limited)
        self.assertTrue(parsed.tc)
        self.assertEqual(len(parsed.answers), 0)
        self.assertEqual(len(parsed.questions), 1)


if __name__ == "__main__":
    unittest.main()
