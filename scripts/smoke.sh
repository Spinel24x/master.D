#!/usr/bin/env bash
# End-to-end smoke test: start the server, fire real queries, check answers.
# Uses dig when available, otherwise falls back to the bundled dnsq client.
set -euo pipefail

PORT="${1:-5353}"
cd "$(dirname "$0")/.."

python3 -m dnscore --port "$PORT" >/tmp/dnscore-smoke.log 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT
sleep 1

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "server failed to start:"; cat /tmp/dnscore-smoke.log; exit 1
fi

if command -v dig >/dev/null; then
    Q() { dig @127.0.0.1 -p "$PORT" +norecurse +time=2 +tries=1 "$@"; }
else
    echo "(dig not found — using bundled scripts/dnsq.py)"
    Q() {
        local name="$1" type="${2:-A}"; shift 2 || true
        if [ "$type" = "AXFR" ]; then
            python3 scripts/dnsq.py @127.0.0.1 -p "$PORT" "$name" AXFR
        else
            python3 scripts/dnsq.py @127.0.0.1 -p "$PORT" "$name" "$type"
        fi
    }
fi

PASS=0
check() {
    local desc="$1" pattern="$2"; shift 2
    if "$@" 2>&1 | grep -q "$pattern"; then
        echo "ok  $desc"
        PASS=$((PASS + 1))
    else
        echo "FAIL $desc"
        echo "--- output was:"; "$@" 2>&1 | sed 's/^/    /'
        exit 1
    fi
}

if command -v dig >/dev/null; then
    check "A     example.com"              "192\.0\.2\.10"     Q example.com A
    check "AAAA  example.com"              "2001:db8::10"      Q example.com AAAA
    check "CNAME www -> apex A"            "192\.0\.2\.10"     Q www.example.com A
    check "CNAME chain ftp -> www -> apex" "CNAME"             Q ftp.example.com A
    check "MX    example.com"              "mail\.example\.com" Q example.com MX
    check "TXT   example.com"              "v=spf1"            Q example.com TXT
    check "wildcard *.dev"                 "192\.0\.2\.99"     Q anything.dev.example.com A
    check "NXDOMAIN"                       "NXDOMAIN"          Q nope.example.com A
    check "NODATA has SOA in authority"    "SOA"               Q api.example.com MX
    check "REFUSED outside authority"      "REFUSED"           Q other.org A
    check "PTR   reverse zone"             "example\.com"      Q 10.2.0.192.in-addr.arpa PTR
    check "TCP works"                      "192\.0\.2\.10"     Q example.com A +tcp
    SOA_COUNT=$(Q example.com AXFR | grep -c "SOA" || true)
    if [ "$SOA_COUNT" = "2" ]; then
        echo "ok  AXFR bounded by two SOA records"; PASS=$((PASS + 1))
    else
        echo "FAIL AXFR (SOA count = $SOA_COUNT)"; exit 1
    fi
else
    check "A     example.com"              "192\.0\.2\.10"     Q example.com A
    check "AAAA  example.com"              "2001:db8::10"      Q example.com AAAA
    check "CNAME www -> apex A"            "192\.0\.2\.10"     Q www.example.com A
    check "MX    example.com"              "mail\.example\.com" Q example.com MX
    check "TXT   example.com"              "v=spf1"            Q example.com TXT
    check "wildcard *.dev"                 "192\.0\.2\.99"     Q anything.dev.example.com A
    check "NXDOMAIN"                       "NXDOMAIN"          Q nope.example.com A
    check "REFUSED outside authority"      "REFUSED"           Q other.org A
    check "PTR   reverse zone"             "example\.com"      Q 10.2.0.192.in-addr.arpa PTR
    SOA_COUNT=$(Q example.com AXFR | grep -c "SOA" || true)
    if [ "$SOA_COUNT" = "2" ]; then
        echo "ok  AXFR bounded by two SOA records"; PASS=$((PASS + 1))
    else
        echo "FAIL AXFR (SOA count = $SOA_COUNT)"; exit 1
    fi
fi

echo
echo "smoke: all $PASS checks passed"
