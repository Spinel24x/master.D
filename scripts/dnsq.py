#!/usr/bin/env python3
"""dnsq — a tiny dig-like DNS client built on dnscore's own wire codec.

Handy where dig isn't installed, and it doubles as a second, independent
exerciser of the from-scratch parser (both ends of the wire are ours).

Usage:
    python3 scripts/dnsq.py @127.0.0.1 -p 5353 example.com A
    python3 scripts/dnsq.py @127.0.0.1 -p 5353 example.com AXFR   # TCP stream
    python3 scripts/dnsq.py @127.0.0.1 -p 5353 www.example.com A --tcp
"""

import argparse
import os
import random
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from dnscore.message import Message, Question, build, parse_message  # noqa: E402
from dnscore.records import NAME_TYPES, TYPE_AXFR, TYPE_OPT, TYPE_SOA, type_name  # noqa: E402
from dnscore.wire import FLAG_RD, RCODE_TEXT  # noqa: E402


def make_query(name: str, qtype: int, rd: bool = False) -> bytes:
    msg = Message(id=random.randrange(65536), flags=FLAG_RD if rd else 0)
    canonical = name.rstrip(".").lower()
    msg.questions.append(Question(canonical, qtype, 1, raw_qname=name.rstrip(".")))
    return build(msg)


def udp_query(server: str, port: int, wire_query: bytes, timeout: float) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(wire_query, (server, port))
        data, _ = s.recvfrom(65535)
        return data


def tcp_query(server: str, port: int, wire_query: bytes, timeout: float) -> bytes:
    with socket.create_connection((server, port), timeout=timeout) as s:
        s.sendall(struct.pack("!H", len(wire_query)) + wire_query)
        f = s.makefile("rb")
        (length,) = struct.unpack("!H", f.read(2))
        return f.read(length)


def print_message(msg: Message, elapsed_ms=None) -> None:
    flags = [name for name, on in (
        ("qr", msg.qr), ("aa", msg.aa), ("tc", msg.tc), ("rd", msg.rd), ("ra", msg.ra),
    ) if on]
    print(";; ->>HEADER<<- opcode: QUERY, status: %s, id: %d"
          % (RCODE_TEXT.get(msg.rcode, str(msg.rcode)), msg.id))
    print(";; flags: %s; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d"
          % (" ".join(flags), len(msg.questions), len(msg.answers),
             len(msg.authorities), len(msg.additionals)))
    if msg.questions:
        print("\n;; QUESTION SECTION:")
        for q in msg.questions:
            print(";%s.\t\t\tIN\t%s" % (q.display_name() or "", type_name(q.qtype)))
    for title, section in (("ANSWER", msg.answers),
                           ("AUTHORITY", msg.authorities),
                           ("ADDITIONAL", msg.additionals)):
        rrs = [rr for rr in section if rr.rtype != TYPE_OPT]
        if rrs:
            print("\n;; %s SECTION:" % title)
            for rr in rrs:
                print(str(rr))
    if elapsed_ms is not None:
        print("\n;; Query time: %d msec" % elapsed_ms)


def do_axfr(server: str, port: int, name: str, timeout: float) -> int:
    wire_query = make_query(name, TYPE_AXFR)
    started = time.time()
    total = 0
    soa_seen = 0
    with socket.create_connection((server, port), timeout=timeout) as s:
        s.sendall(struct.pack("!H", len(wire_query)) + wire_query)
        f = s.makefile("rb")
        while soa_seen < 2:
            header = f.read(2)
            if len(header) < 2:
                print(";; transfer failed: connection closed mid-stream")
                return 1
            (length,) = struct.unpack("!H", header)
            msg = parse_message(f.read(length))
            if msg.rcode != 0:
                print(";; transfer failed: %s" % RCODE_TEXT.get(msg.rcode, msg.rcode))
                return 1
            for rr in msg.answers:
                print(str(rr))
                total += 1
                if rr.rtype == TYPE_SOA:
                    soa_seen += 1
                    if soa_seen == 2:
                        break
    print(";; XFR size: %d records (in %d msec)"
          % (total, int((time.time() - started) * 1000)))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="tiny dig-like client for dnscore")
    parser.add_argument("server", help="server address, e.g. @127.0.0.1")
    parser.add_argument("name", help="domain name to query")
    parser.add_argument("qtype", nargs="?", default="A", help="query type (default A)")
    parser.add_argument("-p", "--port", type=int, default=53)
    parser.add_argument("--tcp", action="store_true", help="force TCP")
    parser.add_argument("--rd", action="store_true", help="set the RD flag")
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args()

    server = args.server.lstrip("@")
    qtype_text = args.qtype.upper()
    if qtype_text in NAME_TYPES:
        qtype = NAME_TYPES[qtype_text]
    elif qtype_text.startswith("TYPE"):
        qtype = int(qtype_text[4:])
    else:
        parser.error("unknown query type %r" % args.qtype)

    if qtype == TYPE_AXFR:
        return do_axfr(server, args.port, args.name, args.timeout)

    wire_query = make_query(args.name, qtype, rd=args.rd)
    started = time.time()
    if args.tcp:
        data = tcp_query(server, args.port, wire_query, args.timeout)
    else:
        data = udp_query(server, args.port, wire_query, args.timeout)
        msg = parse_message(data)
        if msg.tc:
            print(";; truncated — retrying over TCP")
            data = tcp_query(server, args.port, wire_query, args.timeout)
    elapsed_ms = int((time.time() - started) * 1000)
    print_message(parse_message(data), elapsed_ms)
    return 0


if __name__ == "__main__":
    sys.exit(main())
