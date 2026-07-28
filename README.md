# master-dns-core

A **pure-Python authoritative (master) DNS server** with the RFC 1035 wire
format implemented **from scratch** — no `dnslib`, no `dnspython`, no
dependencies at all. Just the standard library, readable enough to study the
protocol end to end.

```
$ dig @127.0.0.1 -p 5353 www.example.com A +norecurse

;; ANSWER SECTION:
www.example.com.  3600  IN  CNAME  example.com.
example.com.      3600  IN  A      192.0.2.10
```

## What's inside

| Layer | Module | What it does |
|---|---|---|
| Wire format | `dnscore/wire.py` | Header, flags, label encoding, **compression pointers** (loop-safe), case-preserving writer |
| Records | `dnscore/records.py` | RDATA codecs for `A AAAA NS CNAME SOA PTR MX TXT` (+opaque passthrough for unknown types) |
| Messages | `dnscore/message.py` | Parse/serialise full messages, EDNS0 OPT, TC truncation |
| Zones | `dnscore/zone.py` | Master-file parser: `$ORIGIN`, `$TTL`, `@`, relative names, owner inheritance, `( )` continuations, quoted strings, TTL units (`30m`, `2h`, `1d12h`) |
| Resolution | `dnscore/resolver.py` | AA answers, CNAME chasing, RFC 4592 **wildcards** via closest encloser, NXDOMAIN vs NODATA with SOA + RFC 2308 negative TTL, REFUSED outside authority, NS/MX glue in ADDITIONAL |
| Server | `dnscore/server.py` | asyncio **UDP + TCP** listeners, EDNS payload limits, truncate-to-TCP, **AXFR zone transfer** (the "master" role) |
| Client | `scripts/dnsq.py` | Tiny dig-like client built on the same codec (works where dig isn't installed) |

## Quick start — GitHub Codespaces

1. **Code ▾ → Codespaces → Create codespace on main** (the dev container
   auto-installs `dig`).
2. In the terminal:

```bash
make test          # 40+ unit tests
make run           # serves zones/*.zone on 0.0.0.0:5353 (udp+tcp)
```

3. In a **second terminal**:

```bash
dig @127.0.0.1 -p 5353 example.com A        +norecurse
dig @127.0.0.1 -p 5353 example.com AAAA     +norecurse
dig @127.0.0.1 -p 5353 ftp.example.com A    +norecurse   # CNAME chain
dig @127.0.0.1 -p 5353 anything.dev.example.com A        # wildcard
dig @127.0.0.1 -p 5353 example.com MX       +norecurse   # + glue
dig @127.0.0.1 -p 5353 10.2.0.192.in-addr.arpa PTR
dig @127.0.0.1 -p 5353 example.com AXFR                  # zone transfer (TCP)
```

Or run everything at once:

```bash
make smoke         # boots the server and verifies 13 live checks
```

Want the real port 53? `make run53` (uses sudo — works in Codespaces).

> **Note:** Codespaces port forwarding is TCP/HTTPS only, so external DNS
> clients can't reach the UDP listener from the internet — test with `dig`
> inside the codespace.

## Quick start — any machine with Python ≥ 3.9

```bash
git clone https://github.com/Spinel24x/master.D && cd master.D
python3 -m dnscore                    # default: zones/*.zone on :5353
python3 -m dnscore -z zones/example.com.zone -p 5353 -v
python3 scripts/dnsq.py @127.0.0.1 -p 5353 example.com ANY   # no dig needed
```

## Serving your own zone

Drop a standard master file into `zones/` (the origin is taken from
`$ORIGIN` or the file name):

```dns
$ORIGIN myzone.ir.
$TTL 1h
@     IN SOA ns1 hostmaster ( 2026072801 2h 1h 2w 5m )
@     IN NS  ns1
ns1   IN A   203.0.113.5
@     IN A   203.0.113.10
www   IN CNAME @
*.app IN A   203.0.113.99
```

```bash
python3 -m dnscore -z zones/myzone.ir.zone
```

## The "master" role: AXFR

A master is the primary that holds the zone and hands full copies to
secondaries. `dig AXFR` (always TCP) receives the stream bounded by the SOA
record on both ends:

```bash
dig @127.0.0.1 -p 5353 example.com AXFR
```

Large zones are chunked into multiple DNS messages automatically. Disable
transfers with `--no-axfr`.

## Tests

```bash
make test    # unit tests: wire codec, zone parser, resolution semantics
make smoke   # end-to-end: real UDP/TCP queries against a live instance
```

## Deliberate non-goals

Kept out to stay a readable core: DNSSEC, IXFR/NOTIFY, recursion/caching,
`$INCLUDE`, escaped label characters, and rate limiting. The negative-answer
rcode of a mid-chain CNAME miss follows the final target (like BIND), but
authority minimisation beyond that is not attempted.

## License

MIT — see [LICENSE](LICENSE).

---

## شروع سریع (فارسی)

سرور DNS معتبر (master) با پایتون خالص — کل پروتکل RFC 1035 از صفر و بدون
هیچ وابستگی پیاده‌سازی شده.

```bash
make test    # اجرای تست‌های واحد
make run     # اجرای سرور روی پورت 5353
```

در ترمینال دوم:

```bash
dig @127.0.0.1 -p 5353 example.com A +norecurse
dig @127.0.0.1 -p 5353 example.com AXFR        # انتقال کامل zone
```

برای zone خودتان یک فایل استاندارد داخل پوشه `zones/` بگذارید و سرور را
دوباره اجرا کنید. پورت واقعی 53 با `make run53` (نیازمند sudo) بالا می‌آید.
