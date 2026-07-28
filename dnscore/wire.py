"""Low-level DNS wire-format primitives (RFC 1035), implemented from scratch.

No third-party DNS libraries anywhere: this module deals purely in bytes —
domain-name encoding/decoding (including message compression pointers) and an
incremental message writer used by the higher layers. It knows nothing about
resource-record semantics.
"""

from __future__ import annotations

import struct

__all__ = [
    "WireError",
    "MessageWriter",
    "read_labels",
    "read_name",
    "split_labels",
    "normalize_name",
    "FLAG_QR", "FLAG_AA", "FLAG_TC", "FLAG_RD", "FLAG_RA",
    "OPCODE_QUERY",
    "RCODE_NOERROR", "RCODE_FORMERR", "RCODE_SERVFAIL", "RCODE_NXDOMAIN",
    "RCODE_NOTIMP", "RCODE_REFUSED", "RCODE_TEXT",
    "CLASS_IN", "CLASS_ANY",
    "SECTION_ANSWER", "SECTION_AUTHORITY", "SECTION_ADDITIONAL",
    "HEADER_LEN",
]

# ---------------------------------------------------------------------------
# Constants

FLAG_QR = 0x8000  # message is a response
FLAG_AA = 0x0400  # authoritative answer
FLAG_TC = 0x0200  # truncated
FLAG_RD = 0x0100  # recursion desired
FLAG_RA = 0x0080  # recursion available

OPCODE_QUERY = 0

RCODE_NOERROR = 0
RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_NOTIMP = 4
RCODE_REFUSED = 5

RCODE_TEXT = {
    RCODE_NOERROR: "NOERROR",
    RCODE_FORMERR: "FORMERR",
    RCODE_SERVFAIL: "SERVFAIL",
    RCODE_NXDOMAIN: "NXDOMAIN",
    RCODE_NOTIMP: "NOTIMP",
    RCODE_REFUSED: "REFUSED",
}

CLASS_IN = 1
CLASS_ANY = 255

SECTION_ANSWER = 1
SECTION_AUTHORITY = 2
SECTION_ADDITIONAL = 3

MAX_LABEL_LEN = 63
MAX_NAME_LEN = 255
MAX_POINTER_JUMPS = 64
HEADER_LEN = 12


class WireError(Exception):
    """Raised when data violates the DNS wire format."""


# ---------------------------------------------------------------------------
# Domain names
#
# Canonical form used throughout the code base: lowercase presentation string
# with NO trailing dot. The root zone is the empty string "".

def normalize_name(name: str) -> str:
    """Return the canonical form of *name* (lowercase, no trailing dot)."""
    name = name.strip()
    if name in (".", ""):
        return ""
    return name.rstrip(".").lower()


def split_labels(name: str) -> "list[bytes]":
    """Split a presentation-form name into raw label bytes (case preserved)."""
    name = name.rstrip(".")
    if not name:
        return []
    labels = []
    for label in name.split("."):
        if not label:
            raise WireError("empty label in name %r" % name)
        raw = label.encode("latin-1")
        if len(raw) > MAX_LABEL_LEN:
            raise WireError("label longer than 63 octets in %r" % name)
        labels.append(raw)
    if sum(len(l) + 1 for l in labels) + 1 > MAX_NAME_LEN:
        raise WireError("name longer than 255 octets: %r" % name)
    return labels


def read_labels(data: bytes, offset: int) -> "tuple[list[bytes], int]":
    """Decode a possibly-compressed name into raw labels.

    Returns ``(labels, next_offset)`` where *next_offset* is the position in
    the original stream right after the name (i.e. right after the first
    compression pointer, if the name used one).

    Safety: pointers must point strictly backwards and the total number of
    jumps is capped, so malicious pointer loops cannot hang the server.
    """
    labels = []  # type: list[bytes]
    pos = offset
    end = -1
    jumps = 0
    name_len = 0
    while True:
        if pos >= len(data):
            raise WireError("name extends past end of message")
        octet = data[pos]
        if octet & 0xC0 == 0xC0:  # compression pointer
            if pos + 1 >= len(data):
                raise WireError("truncated compression pointer")
            if end < 0:
                end = pos + 2
            target = ((octet & 0x3F) << 8) | data[pos + 1]
            if target >= pos:
                raise WireError("compression pointer does not point backwards")
            jumps += 1
            if jumps > MAX_POINTER_JUMPS:
                raise WireError("too many compression pointers")
            pos = target
            continue
        if octet & 0xC0:
            raise WireError("reserved label type 0x%02X" % (octet & 0xC0))
        pos += 1
        if octet == 0:
            break
        if pos + octet > len(data):
            raise WireError("label extends past end of message")
        name_len += octet + 1
        if name_len + 1 > MAX_NAME_LEN:
            raise WireError("decoded name longer than 255 octets")
        labels.append(bytes(data[pos:pos + octet]))
        pos += octet
    if end < 0:
        end = pos
    return labels, end


def read_name(data: bytes, offset: int) -> "tuple[str, int]":
    """Decode a possibly-compressed name to canonical (lowercase) form."""
    labels, end = read_labels(data, offset)
    return b".".join(labels).decode("latin-1").lower(), end


# ---------------------------------------------------------------------------
# Message writer

class MessageWriter:
    """Incrementally builds a wire-format DNS message with name compression.

    Compression matching is case-insensitive (as required by RFC 1035) while
    the emitted bytes preserve the caller's case — important for clients that
    verify the echoed question byte-for-byte (DNS 0x20 randomization).
    """

    def __init__(self, msg_id: int, flags: int) -> None:
        self.buf = bytearray(HEADER_LEN)
        struct.pack_into("!HH", self.buf, 0, msg_id & 0xFFFF, flags & 0xFFFF)
        self.counts = [0, 0, 0, 0]  # QD, AN, NS, AR
        self._offsets = {}  # type: dict[tuple, int]

    # -- names ----------------------------------------------------------

    def write_name(self, name: str, compress: bool = True) -> None:
        labels = split_labels(name)
        keys = tuple(l.lower() for l in labels)
        for i in range(len(labels)):
            suffix = keys[i:]
            if compress:
                ptr = self._offsets.get(suffix)
                if ptr is not None:
                    self.buf += struct.pack("!H", 0xC000 | ptr)
                    return
            if len(self.buf) <= 0x3FFF:
                self._offsets[suffix] = len(self.buf)
            self.buf.append(len(labels[i]))
            self.buf += labels[i]
        self.buf.append(0)

    # -- primitives -------------------------------------------------------

    def u8(self, value: int) -> None:
        self.buf.append(value & 0xFF)

    def u16(self, value: int) -> None:
        self.buf += struct.pack("!H", value & 0xFFFF)

    def u32(self, value: int) -> None:
        self.buf += struct.pack("!I", value & 0xFFFFFFFF)

    def raw(self, data: bytes) -> None:
        self.buf += data

    # -- sections ---------------------------------------------------------

    def add_question(self, qname: str, qtype: int, qclass: int = CLASS_IN) -> None:
        self.write_name(qname)
        self.buf += struct.pack("!HH", qtype, qclass)
        self.counts[0] += 1

    def begin_rr(self, name: str, rtype: int, rclass: int, ttl: int) -> int:
        """Write an RR preamble; returns the RDLENGTH position to patch."""
        self.write_name(name)
        self.buf += struct.pack("!HHI", rtype, rclass, ttl & 0xFFFFFFFF)
        pos = len(self.buf)
        self.buf += b"\x00\x00"
        return pos

    def end_rr(self, rdlength_pos: int, section: int) -> None:
        rdlen = len(self.buf) - rdlength_pos - 2
        if rdlen > 0xFFFF:
            raise WireError("RDATA longer than 65535 octets")
        struct.pack_into("!H", self.buf, rdlength_pos, rdlen)
        self.counts[section] += 1

    # -- output -------------------------------------------------------------

    def take(self) -> bytes:
        struct.pack_into("!HHHH", self.buf, 4, *self.counts)
        if len(self.buf) > 0xFFFF:
            raise WireError("message longer than 65535 octets")
        return bytes(self.buf)

    def __len__(self) -> int:
        return len(self.buf)
