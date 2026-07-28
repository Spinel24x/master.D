"""asyncio UDP/TCP front-end: sockets, EDNS limits, truncation, AXFR."""

from __future__ import annotations

import argparse
import asyncio
import logging
import struct
from pathlib import Path

from . import __version__
from .message import Message, build, make_response, parse_message
from .records import RR, TYPE_AXFR, TYPE_OPT, type_name
from .resolver import Resolver
from .wire import (
    FLAG_QR,
    HEADER_LEN,
    RCODE_FORMERR,
    RCODE_REFUSED,
    RCODE_SERVFAIL,
    RCODE_TEXT,
    WireError,
)
from .zone import ZoneError, parse_zone_file

log = logging.getLogger("dnscore")

EDNS_OUR_PAYLOAD = 1232        # the de-facto safe EDNS buffer size
UDP_FALLBACK_LIMIT = 512       # RFC 1035 limit when the client sent no OPT
EDNS_MAX_HONOURED = 4096
AXFR_RECORDS_PER_MESSAGE = 250
TCP_IDLE_TIMEOUT = 30.0


class Engine:
    """Protocol-independent request handling shared by UDP and TCP."""

    def __init__(self, resolver: Resolver, allow_axfr: bool = True) -> None:
        self.resolver = resolver
        self.allow_axfr = allow_axfr

    # -- shared helpers ---------------------------------------------------

    def _parse(self, data: bytes):
        """Returns ``(query, early_reply_bytes)`` — exactly one is not None,
        or both are None when the datagram should be silently dropped."""
        try:
            query = parse_message(data)
        except WireError as exc:
            log.warning("malformed query dropped: %s", exc)
            if len(data) >= HEADER_LEN:
                msg_id = struct.unpack_from("!H", data, 0)[0]
                return None, build(Message(id=msg_id, flags=FLAG_QR | RCODE_FORMERR))
            return None, None
        if query.qr:
            return None, None  # a response, not a query — ignore (loop guard)
        return query, None

    def _resolve(self, query: Message) -> Message:
        try:
            return self.resolver.resolve(query)
        except Exception:
            log.exception("resolver failure")
            return make_response(query, RCODE_SERVFAIL)

    def _attach_opt(self, resp: Message, query: Message) -> None:
        if query.opt() is not None:
            resp.additionals.append(RR("", TYPE_OPT, EDNS_OUR_PAYLOAD, 0, b""))

    def _udp_limit(self, query: Message) -> int:
        opt = query.opt()
        if opt is None:
            return UDP_FALLBACK_LIMIT
        return max(UDP_FALLBACK_LIMIT, min(opt.rclass, EDNS_MAX_HONOURED))

    def _log(self, proto: str, client: str, query: Message, resp: Message) -> None:
        q = query.questions[0] if query.questions else None
        log.info(
            "%s %s  %s %s -> %s%s  an=%d ns=%d ar=%d",
            proto,
            client,
            (q.qname or ".") if q else "-",
            type_name(q.qtype) if q else "-",
            RCODE_TEXT.get(resp.rcode, str(resp.rcode)),
            " AA" if resp.aa else "",
            len(resp.answers),
            len(resp.authorities),
            len(resp.additionals),
        )

    # -- UDP ----------------------------------------------------------------

    def handle_udp(self, data: bytes, client: str):
        query, early = self._parse(data)
        if query is None:
            return early
        resp = self._resolve(query)
        self._attach_opt(resp, query)
        self._log("udp", client, query, resp)
        try:
            return build(resp, max_size=self._udp_limit(query))
        except WireError:
            log.exception("could not serialise response")
            return build(make_response(query, RCODE_SERVFAIL))

    # -- TCP ------------------------------------------------------------------

    def handle_tcp(self, data: bytes, client: str):
        """Yield one or more wire messages for one TCP query."""
        query, early = self._parse(data)
        if query is None:
            if early is not None:
                yield early
            return
        q = query.questions[0] if query.questions else None
        if q is not None and q.qtype == TYPE_AXFR:
            for wire in self._axfr(query, client):
                yield wire
            return
        resp = self._resolve(query)
        self._attach_opt(resp, query)
        self._log("tcp", client, query, resp)
        yield build(resp)

    def _axfr(self, query: Message, client: str):
        q = query.questions[0]
        zone = self.resolver.zones.get(q.qname)
        if zone is None or not self.allow_axfr:
            resp = make_response(query, RCODE_REFUSED)
            self._log("tcp", client, query, resp)
            yield build(resp)
            return
        total = 0
        messages = 0
        batch = []
        first = True
        for rr in zone.transfer_records():
            batch.append(rr)
            if len(batch) >= AXFR_RECORDS_PER_MESSAGE:
                yield self._axfr_message(query, batch, first)
                total += len(batch)
                messages += 1
                batch = []
                first = False
        if batch:
            yield self._axfr_message(query, batch, first)
            total += len(batch)
            messages += 1
        log.info("tcp %s  AXFR %s -> %d records in %d message(s)",
                 client, q.qname or ".", total, messages)

    @staticmethod
    def _axfr_message(query: Message, rrs, include_question: bool) -> bytes:
        resp = make_response(query, aa=True)
        if not include_question:
            resp.questions = []
        resp.answers = list(rrs)
        return build(resp)


# ---------------------------------------------------------------------------
# asyncio plumbing

class _UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self.transport = None

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        client = "%s#%d" % (addr[0], addr[1])
        try:
            wire = self.engine.handle_udp(data, client)
        except Exception:
            log.exception("unhandled error for UDP query from %s", client)
            return
        if wire:
            self.transport.sendto(wire, addr)


async def _tcp_session(engine: Engine, reader, writer) -> None:
    peer = writer.get_extra_info("peername")
    client = "%s#%d" % (peer[0], peer[1]) if peer else "?"
    try:
        while True:
            try:
                header = await asyncio.wait_for(reader.readexactly(2), TCP_IDLE_TIMEOUT)
            except asyncio.TimeoutError:
                break
            (length,) = struct.unpack("!H", header)
            data = await asyncio.wait_for(reader.readexactly(length), TCP_IDLE_TIMEOUT)
            for wire in engine.handle_tcp(data, client):
                writer.write(struct.pack("!H", len(wire)))
                writer.write(wire)
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionResetError, asyncio.TimeoutError):
        pass
    except Exception:
        log.exception("TCP session error with %s", client)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def serve(resolver: Resolver, host: str, port: int, allow_axfr: bool = True) -> None:
    engine = Engine(resolver, allow_axfr=allow_axfr)
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: _UDPProtocol(engine), local_addr=(host, port)
    )
    tcp_server = await asyncio.start_server(
        lambda r, w: _tcp_session(engine, r, w), host, port
    )
    for origin in sorted(resolver.zones):
        zone = resolver.zones[origin]
        log.info("zone %s loaded: serial %d, %d records, %d names",
                 origin or ".", zone.soa.rdata.serial, zone.record_count(), len(zone.nodes))
    log.info("master-dns-core %s listening on %s:%d (udp+tcp), axfr %s",
             __version__, host, port, "on" if allow_axfr else "off")
    try:
        await asyncio.Event().wait()  # serve forever
    finally:
        transport.close()
        tcp_server.close()
        await tcp_server.wait_closed()


# ---------------------------------------------------------------------------
# CLI

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="dnscore",
        description="Pure-Python authoritative master DNS server — "
                    "RFC 1035 wire format implemented from scratch.",
    )
    parser.add_argument("-z", "--zone", action="append", metavar="FILE",
                        help="zone file to load (repeatable); default: zones/*.zone")
    parser.add_argument("--host", default="0.0.0.0", help="address to bind (default 0.0.0.0)")
    parser.add_argument("-p", "--port", type=int, default=5353,
                        help="port to bind (default 5353; port 53 needs root)")
    parser.add_argument("--no-axfr", action="store_true", help="refuse AXFR zone transfers")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )

    paths = [Path(p) for p in args.zone] if args.zone else sorted(Path("zones").glob("*.zone"))
    if not paths:
        parser.error("no zone files found — pass --zone FILE or create zones/*.zone")

    zones = []
    for path in paths:
        try:
            zone, warnings = parse_zone_file(path)
        except (OSError, ZoneError) as exc:
            log.error("cannot load %s: %s", path, exc)
            return 1
        for warning in warnings:
            log.warning("%s: %s", path, warning)
        zones.append(zone)

    try:
        resolver = Resolver(zones)
    except ValueError as exc:
        log.error("%s", exc)
        return 1

    try:
        asyncio.run(serve(resolver, args.host, args.port, allow_axfr=not args.no_axfr))
    except KeyboardInterrupt:
        log.info("shutting down")
    except PermissionError:
        log.error("cannot bind port %d — ports below 1024 need root "
                  "(use sudo, or keep the default --port 5353)", args.port)
        return 1
    except OSError as exc:
        log.error("cannot bind %s:%d: %s", args.host, args.port, exc)
        return 1
    return 0
