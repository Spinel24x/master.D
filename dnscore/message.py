"""DNS message model: parsing queries and serialising responses."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from . import records
from .wire import (
    CLASS_IN,
    FLAG_AA,
    FLAG_QR,
    FLAG_RA,
    FLAG_RD,
    FLAG_TC,
    HEADER_LEN,
    RCODE_NOERROR,
    SECTION_ADDITIONAL,
    SECTION_ANSWER,
    SECTION_AUTHORITY,
    MessageWriter,
    WireError,
    read_labels,
    read_name,
)


@dataclass
class Question:
    qname: str                     # canonical (lowercase, no trailing dot)
    qtype: int
    qclass: int = CLASS_IN
    raw_qname: str = None          # case as received; echoed back verbatim

    def display_name(self) -> str:
        return self.raw_qname if self.raw_qname is not None else self.qname


@dataclass
class Message:
    id: int = 0
    flags: int = 0
    questions: list = field(default_factory=list)
    answers: list = field(default_factory=list)
    authorities: list = field(default_factory=list)
    additionals: list = field(default_factory=list)

    # -- flag helpers -----------------------------------------------------

    @property
    def qr(self) -> bool:
        return bool(self.flags & FLAG_QR)

    @property
    def opcode(self) -> int:
        return (self.flags >> 11) & 0xF

    @property
    def aa(self) -> bool:
        return bool(self.flags & FLAG_AA)

    @property
    def tc(self) -> bool:
        return bool(self.flags & FLAG_TC)

    @property
    def rd(self) -> bool:
        return bool(self.flags & FLAG_RD)

    @property
    def ra(self) -> bool:
        return bool(self.flags & FLAG_RA)

    @property
    def rcode(self) -> int:
        return self.flags & 0xF

    def set_rcode(self, rcode: int) -> None:
        self.flags = (self.flags & ~0xF) | (rcode & 0xF)

    def opt(self):
        """Return the EDNS0 OPT pseudo-record from ADDITIONAL, if any."""
        for rr in self.additionals:
            if rr.rtype == records.TYPE_OPT:
                return rr
        return None


# ---------------------------------------------------------------------------
# Parsing

def parse_message(data: bytes) -> Message:
    if len(data) < HEADER_LEN:
        raise WireError("message shorter than the 12-octet header")
    msg_id, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", data, 0)
    msg = Message(id=msg_id, flags=flags)
    pos = HEADER_LEN
    for _ in range(qd):
        labels, pos = read_labels(data, pos)
        raw = b".".join(labels).decode("latin-1")
        if pos + 4 > len(data):
            raise WireError("question section truncated")
        qtype, qclass = struct.unpack_from("!HH", data, pos)
        pos += 4
        msg.questions.append(Question(raw.lower(), qtype, qclass, raw_qname=raw))
    for count, bucket in ((an, msg.answers), (ns, msg.authorities), (ar, msg.additionals)):
        for _ in range(count):
            rr, pos = _read_rr(data, pos)
            bucket.append(rr)
    return msg


def _read_rr(data: bytes, pos: int):
    name, pos = read_name(data, pos)
    if pos + 10 > len(data):
        raise WireError("resource record header truncated")
    rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", data, pos)
    pos += 10
    rdata = records.parse_rdata(data, pos, rdlength, rtype)
    return records.RR(name, rtype, rclass, ttl, rdata), pos + rdlength


# ---------------------------------------------------------------------------
# Serialising

def build(msg: Message, max_size: int = None) -> bytes:
    """Serialise *msg*; if it exceeds *max_size*, return a truncated (TC=1)
    reply containing just the question (and OPT), as UDP clients expect."""
    wire = _build(msg)
    if max_size is not None and len(wire) > max_size:
        truncated = Message(
            id=msg.id,
            flags=msg.flags | FLAG_TC,
            questions=list(msg.questions),
            additionals=[rr for rr in msg.additionals if rr.rtype == records.TYPE_OPT],
        )
        wire = _build(truncated)
        if len(wire) > max_size:  # give up on OPT; header+question fits in 512
            truncated.additionals = []
            wire = _build(truncated)
    return wire


def _build(msg: Message) -> bytes:
    w = MessageWriter(msg.id, msg.flags)
    for q in msg.questions:
        w.add_question(q.display_name(), q.qtype, q.qclass)
    for rr in msg.answers:
        _write_rr(w, rr, SECTION_ANSWER)
    for rr in msg.authorities:
        _write_rr(w, rr, SECTION_AUTHORITY)
    for rr in msg.additionals:
        _write_rr(w, rr, SECTION_ADDITIONAL)
    return w.take()


def _write_rr(w: MessageWriter, rr, section: int) -> None:
    pos = w.begin_rr(rr.name, rr.rtype, rr.rclass, rr.ttl)
    records.write_rdata(w, rr)
    w.end_rr(pos, section)


def make_response(query: Message, rcode: int = RCODE_NOERROR, aa: bool = False) -> Message:
    """Start a response for *query*: same id/opcode, echoed question and RD."""
    flags = FLAG_QR | ((query.opcode & 0xF) << 11) | (query.flags & FLAG_RD) | (rcode & 0xF)
    if aa:
        flags |= FLAG_AA
    return Message(id=query.id, flags=flags, questions=list(query.questions))
