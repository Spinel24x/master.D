"""Zone files: a practical RFC 1035 master-file parser and in-memory store.

Supported syntax: $ORIGIN and $TTL directives, ``@`` for the origin, relative
and absolute owner names, owner inheritance (lines starting with whitespace),
parenthesised multi-line records, quoted strings, ``;`` comments, and TTL
values with s/m/h/d/w units. $INCLUDE and escaped dots inside labels are not
supported (kept out deliberately — this is a readable core, not BIND).
"""

from __future__ import annotations

import re
import socket
from pathlib import Path

from .records import (
    MX,
    NAME_TYPES,
    RR,
    SOA,
    TYPE_CNAME,
    TYPE_SOA,
    TYPE_A,
    TYPE_AAAA,
    TYPE_MX,
    TYPE_NS,
    TYPE_PTR,
    TYPE_TXT,
)
from .wire import CLASS_IN, normalize_name

DEFAULT_TTL = 3600

# Types that may appear as zone data (query-only pseudo-types excluded).
_ZONE_TYPES = {
    name: code for name, code in NAME_TYPES.items()
    if name not in ("ANY", "AXFR", "OPT")
}

_TTL_RE = re.compile(r"^(?:\d+[smhdw]?)+$", re.IGNORECASE)
_TTL_PART = re.compile(r"(\d+)([smhdw]?)", re.IGNORECASE)
_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


class ZoneError(Exception):
    """Raised for syntax or consistency errors in zone data."""


def parse_ttl(text: str) -> int:
    """Parse a TTL like ``300``, ``30m``, ``2h``, ``1d12h`` into seconds."""
    if not _TTL_RE.match(text):
        raise ZoneError("invalid TTL value %r" % text)
    return sum(int(num) * _UNITS[unit.lower()] for num, unit in _TTL_PART.findall(text))


# ---------------------------------------------------------------------------
# Tokeniser

def _tokenize_line(line: str):
    """Split one physical line into (text, quoted) tokens; strips comments."""
    tokens = []
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if c in " \t":
            i += 1
            continue
        if c == ";":
            break
        if c == '"':
            j = i + 1
            buf = []
            while j < n and line[j] != '"':
                if line[j] == "\\" and j + 1 < n:
                    buf.append(line[j + 1])
                    j += 2
                else:
                    buf.append(line[j])
                    j += 1
            if j >= n:
                raise ZoneError("unterminated quoted string")
            tokens.append(("".join(buf), True))
            i = j + 1
            continue
        if c in "()":
            tokens.append((c, False))
            i += 1
            continue
        j = i
        while j < n and line[j] not in ' \t;()"':
            j += 1
        tokens.append((line[i:j], False))
        i = j
    return tokens


def _logical_records(text: str):
    """Yield ``(tokens, owner_inherited, lineno)`` per logical record,
    joining lines inside parentheses."""
    pending = []
    pending_ws = False
    pending_line = 0
    depth = 0
    for lineno, line in enumerate(text.splitlines(), 1):
        try:
            toks = _tokenize_line(line)
        except ZoneError as exc:
            raise ZoneError("line %d: %s" % (lineno, exc))
        if depth == 0:
            if not toks:
                continue
            pending = []
            pending_ws = line[:1] in (" ", "\t")
            pending_line = lineno
        for tok, quoted in toks:
            if not quoted and tok == "(":
                depth += 1
            elif not quoted and tok == ")":
                depth -= 1
                if depth < 0:
                    raise ZoneError("line %d: unbalanced ')'" % lineno)
            else:
                pending.append((tok, quoted))
        if depth == 0 and pending:
            yield pending, pending_ws, pending_line
    if depth != 0:
        raise ZoneError("unbalanced '(' at end of file")


# ---------------------------------------------------------------------------
# Zone store

class Zone:
    """An authoritative zone: origin plus a name → {rtype → [RR]} map.

    ``Zone.add`` materialises empty non-terminals (parents of every owner),
    which makes NXDOMAIN vs NODATA decisions and RFC 4592 wildcard matching
    exact set-membership checks.
    """

    def __init__(self, origin: str) -> None:
        self.origin = normalize_name(origin)
        self.nodes = {}  # type: dict[str, dict[int, list[RR]]]

    # -- membership -----------------------------------------------------

    def contains(self, name: str) -> bool:
        if not self.origin:
            return True  # root zone contains everything
        return name == self.origin or name.endswith("." + self.origin)

    def node(self, name: str):
        return self.nodes.get(name)

    def rrset(self, name: str, rtype: int):
        return list(self.nodes.get(name, {}).get(rtype, ()))

    @property
    def soa(self):
        rrs = self.nodes.get(self.origin, {}).get(TYPE_SOA)
        return rrs[0] if rrs else None

    # -- building ---------------------------------------------------------

    def add(self, rr: RR) -> None:
        if not self.contains(rr.name):
            raise ZoneError("record %s is outside zone %s" % (rr.name or ".", self.origin or "."))
        if rr.rtype == TYPE_SOA and rr.name != self.origin:
            raise ZoneError("SOA must live at the zone apex, not %s" % rr.name)
        node = self.nodes.setdefault(rr.name, {})
        if rr.rtype == TYPE_CNAME:
            if set(node) - {TYPE_CNAME}:
                raise ZoneError("CNAME and other data at %s" % rr.name)
            if node.get(TYPE_CNAME):
                raise ZoneError("multiple CNAME records at %s" % rr.name)
        elif TYPE_CNAME in node:
            raise ZoneError("CNAME and other data at %s" % rr.name)
        if rr.rtype == TYPE_SOA and node.get(TYPE_SOA):
            raise ZoneError("multiple SOA records in zone %s" % (self.origin or "."))
        node.setdefault(rr.rtype, []).append(rr)
        # Materialise empty non-terminals up to (not including) the apex.
        parent = rr.name
        while parent != self.origin:
            dot = parent.find(".")
            if dot < 0:
                break
            parent = parent[dot + 1:]
            if parent == self.origin:
                break
            self.nodes.setdefault(parent, {})

    # -- iteration ----------------------------------------------------------

    def iter_records(self):
        for name in sorted(self.nodes):
            for rtype in sorted(self.nodes[name]):
                for rr in self.nodes[name][rtype]:
                    yield rr

    def transfer_records(self):
        """Records in AXFR order: SOA first, everything else, SOA again."""
        soa = self.soa
        if soa is None:
            raise ZoneError("zone %s has no SOA record" % (self.origin or "."))
        yield soa
        for rr in self.iter_records():
            if rr.rtype != TYPE_SOA:
                yield rr
        yield soa

    def record_count(self) -> int:
        return sum(len(rrs) for node in self.nodes.values() for rrs in node.values())

    # -- validation ---------------------------------------------------------

    def validate(self):
        """Raise ZoneError on fatal problems; return a list of warnings."""
        if self.soa is None:
            raise ZoneError("zone %s has no SOA record" % (self.origin or "."))
        warnings = []
        if not self.nodes.get(self.origin, {}).get(TYPE_NS):
            warnings.append("no NS records at the zone apex")
        return warnings


# ---------------------------------------------------------------------------
# Parser

def _full_name(token: str, origin) -> str:
    if token == "@":
        if origin is None:
            raise ZoneError("'@' used before $ORIGIN is known")
        return origin
    if token.endswith("."):
        return normalize_name(token)
    if origin is None:
        raise ZoneError("relative name %r used before $ORIGIN is known" % token)
    rel = token.lower()
    return "%s.%s" % (rel, origin) if origin else rel


def _parse_ip4(text: str) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET, socket.inet_pton(socket.AF_INET, text))
    except OSError:
        raise ZoneError("invalid IPv4 address %r" % text)


def _parse_ip6(text: str) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET6, socket.inet_pton(socket.AF_INET6, text))
    except OSError:
        raise ZoneError("invalid IPv6 address %r" % text)


def _parse_rdata_tokens(rtype: int, toks, origin):
    def text(i):
        return toks[i][0]

    def need(count):
        if len(toks) != count:
            raise ZoneError("%s record needs %d field(s), got %d"
                            % (NAME_TYPES_INV.get(rtype, rtype), count, len(toks)))

    if rtype == TYPE_A:
        need(1)
        return _parse_ip4(text(0))
    if rtype == TYPE_AAAA:
        need(1)
        return _parse_ip6(text(0))
    if rtype in (TYPE_NS, TYPE_CNAME, TYPE_PTR):
        need(1)
        return _full_name(text(0), origin)
    if rtype == TYPE_MX:
        need(2)
        return MX(int(text(0)), _full_name(text(1), origin))
    if rtype == TYPE_SOA:
        need(7)
        return SOA(
            _full_name(text(0), origin),
            _full_name(text(1), origin),
            int(text(2)),
            parse_ttl(text(3)),
            parse_ttl(text(4)),
            parse_ttl(text(5)),
            parse_ttl(text(6)),
        )
    if rtype == TYPE_TXT:
        if not toks:
            raise ZoneError("TXT record needs at least one string")
        strings = []
        for tok, _quoted in toks:
            raw = tok.encode("latin-1")
            if len(raw) > 255:  # long strings are split, as BIND does
                strings.extend(raw[i:i + 255] for i in range(0, len(raw), 255))
            else:
                strings.append(raw)
        return tuple(strings)
    raise ZoneError("unsupported record type %d" % rtype)


NAME_TYPES_INV = {code: name for name, code in _ZONE_TYPES.items()}


def parse_zone_text(text: str, origin: str = None, default_ttl: int = DEFAULT_TTL) -> Zone:
    origin = normalize_name(origin) if origin else None
    ttl = default_ttl
    zone = None
    last_owner = None

    for tokens, owner_inherited, lineno in _logical_records(text):
        try:
            first, first_quoted = tokens[0]

            # Directives -------------------------------------------------
            if not first_quoted and first.startswith("$"):
                directive = first.upper()
                if directive == "$ORIGIN":
                    if len(tokens) < 2:
                        raise ZoneError("$ORIGIN needs a name")
                    origin = normalize_name(tokens[1][0])
                elif directive == "$TTL":
                    if len(tokens) < 2:
                        raise ZoneError("$TTL needs a value")
                    ttl = parse_ttl(tokens[1][0])
                else:
                    raise ZoneError("unsupported directive %s" % first)
                continue

            # Owner name ---------------------------------------------------
            if owner_inherited:
                if last_owner is None:
                    raise ZoneError("record inherits an owner but none was seen yet")
                owner = last_owner
                rest = tokens
            else:
                owner = _full_name(first, origin)
                rest = tokens[1:]
            last_owner = owner

            # Optional TTL / class (any order), then the type ---------------
            rr_ttl = None
            rtype = None
            idx = 0
            while idx < len(rest):
                tok, quoted = rest[idx]
                up = tok.upper()
                if not quoted and up in _ZONE_TYPES:
                    rtype = _ZONE_TYPES[up]
                    idx += 1
                    break
                if not quoted and up == "IN":
                    pass  # class IN is the only supported class
                elif not quoted and up in ("CH", "HS", "CS"):
                    raise ZoneError("only class IN is supported")
                elif not quoted and _TTL_RE.match(tok):
                    rr_ttl = parse_ttl(tok)
                else:
                    raise ZoneError("unexpected token %r (expected TTL, class or type)" % tok)
                idx += 1
            if rtype is None:
                raise ZoneError("missing record type")

            rdata = _parse_rdata_tokens(rtype, rest[idx:], origin)

            if zone is None:
                if origin is None:
                    raise ZoneError("no $ORIGIN before the first record")
                zone = Zone(origin)
            zone.add(RR(owner, rtype, CLASS_IN, rr_ttl if rr_ttl is not None else ttl, rdata))
        except ZoneError as exc:
            raise ZoneError("line %d: %s" % (lineno, exc))

    if zone is None:
        raise ZoneError("zone file contains no records")
    return zone


def parse_zone_file(path, origin: str = None):
    """Load a zone file. Returns ``(zone, warnings)``.

    If neither *origin* nor an in-file $ORIGIN is given, the origin is derived
    from the file name (``example.com.zone`` → ``example.com``).
    """
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    if origin is None:
        stem = path.name
        if stem.endswith(".zone"):
            stem = stem[: -len(".zone")]
        origin = stem
    zone = parse_zone_text(text, origin=origin)
    warnings = zone.validate()
    return zone, warnings
