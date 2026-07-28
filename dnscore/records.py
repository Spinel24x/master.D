"""Resource records: the type registry plus per-type RDATA codecs.

Supported record types: A, NS, CNAME, SOA, PTR, MX, TXT, AAAA. Unknown types
round-trip as opaque bytes (RFC 3597 spirit) so the parser never chokes on
them. Name compression inside RDATA is used only for the RFC 1035 well-known
types where it is permitted (NS, CNAME, SOA, PTR, MX).
"""

from __future__ import annotations

import dataclasses
import socket
import struct
from dataclasses import dataclass

from .wire import MessageWriter, WireError, read_name

TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_PTR = 12
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_OPT = 41
TYPE_AXFR = 252
TYPE_ANY = 255

TYPE_NAMES = {
    TYPE_A: "A",
    TYPE_NS: "NS",
    TYPE_CNAME: "CNAME",
    TYPE_SOA: "SOA",
    TYPE_PTR: "PTR",
    TYPE_MX: "MX",
    TYPE_TXT: "TXT",
    TYPE_AAAA: "AAAA",
    TYPE_OPT: "OPT",
    TYPE_AXFR: "AXFR",
    TYPE_ANY: "ANY",
}
NAME_TYPES = {v: k for k, v in TYPE_NAMES.items()}

# Types whose RDATA contains domain names that may be compressed in messages.
_NAME_RDATA_TYPES = (TYPE_NS, TYPE_CNAME, TYPE_PTR)


def type_name(rtype: int) -> str:
    return TYPE_NAMES.get(rtype, "TYPE%d" % rtype)


@dataclass(frozen=True)
class SOA:
    mname: str
    rname: str
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int


@dataclass(frozen=True)
class MX:
    preference: int
    exchange: str


@dataclass(frozen=True)
class RR:
    """One resource record. ``name`` is canonical (lowercase, no trailing dot).

    ``rdata`` is type-specific: str for A/AAAA/NS/CNAME/PTR, SOA/MX dataclass,
    tuple[bytes, ...] for TXT, raw bytes for OPT/unknown types.
    """

    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: object

    def with_owner(self, name: str) -> "RR":
        return dataclasses.replace(self, name=name)

    def with_ttl(self, ttl: int) -> "RR":
        return dataclasses.replace(self, ttl=ttl)

    def __str__(self) -> str:
        owner = (self.name + ".") if self.name else "."
        return "%s\t%d\tIN\t%s\t%s" % (owner, self.ttl, type_name(self.rtype), rdata_text(self))


def _pname(name: str) -> str:
    return (name + ".") if name else "."


def rdata_text(rr: RR) -> str:
    """Zone-file-style presentation of RDATA (for logs and the dnsq client)."""
    r, t = rr.rdata, rr.rtype
    if t in (TYPE_A, TYPE_AAAA):
        return str(r)
    if t in _NAME_RDATA_TYPES:
        return _pname(str(r))
    if t == TYPE_MX:
        return "%d %s" % (r.preference, _pname(r.exchange))
    if t == TYPE_SOA:
        return "%s %s %d %d %d %d %d" % (
            _pname(r.mname), _pname(r.rname),
            r.serial, r.refresh, r.retry, r.expire, r.minimum,
        )
    if t == TYPE_TXT:
        parts = []
        for chunk in r:
            text = chunk.decode("latin-1").replace("\\", "\\\\").replace('"', '\\"')
            parts.append('"%s"' % text)
        return " ".join(parts)
    if isinstance(r, (bytes, bytearray)):
        return "\\# %d %s" % (len(r), bytes(r).hex())
    return str(r)


# ---------------------------------------------------------------------------
# RDATA codecs

def write_rdata(w: MessageWriter, rr: RR) -> None:
    r, t = rr.rdata, rr.rtype
    if t == TYPE_A:
        w.raw(socket.inet_pton(socket.AF_INET, r))
    elif t == TYPE_AAAA:
        w.raw(socket.inet_pton(socket.AF_INET6, r))
    elif t in _NAME_RDATA_TYPES:
        w.write_name(r)
    elif t == TYPE_MX:
        w.u16(r.preference)
        w.write_name(r.exchange)
    elif t == TYPE_SOA:
        w.write_name(r.mname)
        w.write_name(r.rname)
        w.raw(struct.pack("!IIIII", r.serial, r.refresh, r.retry, r.expire, r.minimum))
    elif t == TYPE_TXT:
        if not r:
            raise WireError("TXT record needs at least one string")
        for chunk in r:
            if len(chunk) > 255:
                raise WireError("TXT string longer than 255 octets")
            w.u8(len(chunk))
            w.raw(chunk)
    elif isinstance(r, (bytes, bytearray)):
        w.raw(bytes(r))
    else:
        raise WireError("cannot serialise RDATA for %s" % type_name(t))


def parse_rdata(data: bytes, rdstart: int, rdlength: int, rtype: int):
    rdend = rdstart + rdlength
    if rdend > len(data):
        raise WireError("RDATA extends past end of message")
    if rtype == TYPE_A:
        if rdlength != 4:
            raise WireError("A RDATA must be 4 octets")
        return socket.inet_ntop(socket.AF_INET, data[rdstart:rdend])
    if rtype == TYPE_AAAA:
        if rdlength != 16:
            raise WireError("AAAA RDATA must be 16 octets")
        return socket.inet_ntop(socket.AF_INET6, data[rdstart:rdend])
    if rtype in _NAME_RDATA_TYPES:
        name, _ = read_name(data, rdstart)
        return name
    if rtype == TYPE_MX:
        if rdlength < 3:
            raise WireError("MX RDATA too short")
        (pref,) = struct.unpack_from("!H", data, rdstart)
        exchange, _ = read_name(data, rdstart + 2)
        return MX(pref, exchange)
    if rtype == TYPE_SOA:
        mname, off = read_name(data, rdstart)
        rname, off = read_name(data, off)
        if off + 20 > len(data):
            raise WireError("SOA RDATA too short")
        serial, refresh, retry, expire, minimum = struct.unpack_from("!IIIII", data, off)
        return SOA(mname, rname, serial, refresh, retry, expire, minimum)
    if rtype == TYPE_TXT:
        strings, pos = [], rdstart
        while pos < rdend:
            slen = data[pos]
            pos += 1
            if pos + slen > rdend:
                raise WireError("TXT string extends past RDATA")
            strings.append(bytes(data[pos:pos + slen]))
            pos += slen
        return tuple(strings)
    return bytes(data[rdstart:rdend])  # OPT and unknown types stay opaque
