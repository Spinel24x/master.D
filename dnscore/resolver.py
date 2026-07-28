"""The authoritative answering engine.

Implements the master-server half of RFC 1034 §4.3: exact matches, CNAME
chasing, RFC 4592 wildcard synthesis via the closest encloser, NXDOMAIN vs
NODATA (both with the SOA and RFC 2308 negative TTL in AUTHORITY), REFUSED
for names outside our authority, and glue-style additional-section processing
for NS and MX answers.
"""

from __future__ import annotations

from .message import Message, make_response
from .records import (
    TYPE_A,
    TYPE_AAAA,
    TYPE_ANY,
    TYPE_AXFR,
    TYPE_CNAME,
    TYPE_MX,
    TYPE_NS,
    TYPE_SOA,
)
from .wire import (
    CLASS_ANY,
    CLASS_IN,
    OPCODE_QUERY,
    RCODE_FORMERR,
    RCODE_NOTIMP,
    RCODE_NXDOMAIN,
    RCODE_REFUSED,
)

MAX_CNAME_CHAIN = 8


class Resolver:
    def __init__(self, zones) -> None:
        self.zones = {}
        for zone in zones:
            if zone.origin in self.zones:
                raise ValueError("duplicate zone %s" % (zone.origin or "."))
            self.zones[zone.origin] = zone

    # ------------------------------------------------------------------

    def find_zone(self, qname: str):
        """Longest-suffix match: the closest enclosing zone we serve."""
        best = None
        for zone in self.zones.values():
            if zone.contains(qname) and (best is None or len(zone.origin) > len(best.origin)):
                best = zone
        return best

    # ------------------------------------------------------------------

    def resolve(self, query: Message) -> Message:
        if query.opcode != OPCODE_QUERY:
            return make_response(query, RCODE_NOTIMP)
        if len(query.questions) != 1:
            return make_response(query, RCODE_FORMERR)
        q = query.questions[0]
        if q.qclass not in (CLASS_IN, CLASS_ANY):
            return make_response(query, RCODE_REFUSED)
        if q.qtype == TYPE_AXFR:
            # AXFR is TCP-only; the server layer intercepts it there.
            return make_response(query, RCODE_NOTIMP)
        zone = self.find_zone(q.qname)
        if zone is None:
            return make_response(query, RCODE_REFUSED)  # authoritative-only

        resp = make_response(query, aa=True)
        self._answer(zone, q.qname, q.qtype, resp, depth=0)
        self._add_additionals(resp)
        return resp

    # ------------------------------------------------------------------

    def _answer(self, zone, qname, qtype, resp, depth) -> None:
        node, synthesized = self._find_node(zone, qname)
        if node is None:
            self._negative(zone, resp, nxdomain=True)
            return

        cname_rrs = node.get(TYPE_CNAME)
        if cname_rrs and qtype not in (TYPE_CNAME, TYPE_ANY):
            cname = cname_rrs[0].with_owner(qname) if synthesized else cname_rrs[0]
            resp.answers.append(cname)
            self._chase(cname.rdata, qtype, resp, depth + 1)
            return

        if qtype == TYPE_ANY:
            found = False
            for rtype in sorted(node):
                for rr in node[rtype]:
                    resp.answers.append(rr.with_owner(qname) if synthesized else rr)
                    found = True
            if not found:
                self._negative(zone, resp, nxdomain=False)
            return

        rrs = node.get(qtype)
        if rrs:
            for rr in rrs:
                resp.answers.append(rr.with_owner(qname) if synthesized else rr)
        else:
            self._negative(zone, resp, nxdomain=False)

    def _chase(self, target, qtype, resp, depth) -> None:
        """Follow a CNAME target through any zone we are authoritative for."""
        if depth > MAX_CNAME_CHAIN:
            return
        zone = self.find_zone(target)
        if zone is None:
            return  # target is outside our authority; the client recurses on
        self._answer(zone, target, qtype, resp, depth)

    def _find_node(self, zone, qname):
        """Return ``(node, synthesized_from_wildcard)`` for *qname*.

        Empty non-terminals are materialised at load time, so the closest
        encloser (RFC 4592) is simply the first existing ancestor.
        """
        node = zone.node(qname)
        if node is not None:
            return node, False
        name = qname
        while name != zone.origin:
            dot = name.find(".")
            if dot < 0:
                if zone.origin:
                    return None, False
                name = ""
            else:
                name = name[dot + 1:]
            ancestor = zone.node(name)
            if ancestor is not None:
                wildcard = zone.node("*." + name if name else "*")
                if wildcard is not None:
                    return wildcard, True
                return None, False
            if name == zone.origin:
                break
        return None, False

    def _negative(self, zone, resp, nxdomain) -> None:
        if nxdomain:
            resp.set_rcode(RCODE_NXDOMAIN)
        if any(rr.rtype == TYPE_SOA for rr in resp.authorities):
            return
        soa = zone.soa
        if soa is not None:
            resp.authorities.append(soa.with_ttl(min(soa.ttl, soa.rdata.minimum)))

    def _add_additionals(self, resp) -> None:
        """Add A/AAAA glue for NS and MX targets we are authoritative for."""
        targets = []
        for rr in resp.answers:
            if rr.rtype == TYPE_NS:
                targets.append(rr.rdata)
            elif rr.rtype == TYPE_MX:
                targets.append(rr.rdata.exchange)
        placed = {(rr.name, rr.rtype) for rr in resp.answers}
        for target in targets:
            zone = self.find_zone(target)
            if zone is None:
                continue
            node = zone.node(target)
            if node is None:
                continue
            for rtype in (TYPE_A, TYPE_AAAA):
                for rr in node.get(rtype, ()):
                    key = (rr.name, rr.rtype)
                    if key not in placed:
                        placed.add(key)
                        resp.additionals.append(rr)
