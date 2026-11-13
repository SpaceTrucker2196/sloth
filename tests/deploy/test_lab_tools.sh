#!/bin/sh
# tools/lab/lab_capture.sh and tools/lab/expect.sh (#199) against a
# hand-built /sys, /proc and /etc/default/sloth (LAB_SYS, LAB_PROC,
# LAB_DEFAULT_SLOTH) and stub tcpdump/ethtool on a PATH that holds only
# what the scripts need: no real interface is opened, nothing is
# captured, nothing transmits. The pcap the stub writes is made here at
# run time (tests/ holds no .pcap files), and slothweb's answers are
# JSON written here and read through --alerts-json / --incident-json.
set -u

top=$(pwd)
cap=$top/tools/lab/lab_capture.sh
exp=$top/tools/lab/expect.sh
if [ ! -f "$cap" ] || [ ! -f "$exp" ]; then
    echo "test_lab_tools: run from the top of the tree" >&2; exit 2
fi
command -v python3 >/dev/null || { echo "test_lab_tools: needs python3" >&2; exit 2; }

base=$(cd "$(mktemp -d "${TMPDIR:-/tmp}/sloth-labtools.XXXXXX")" && pwd)
trap 'chmod -R u+rwx "$base" 2>/dev/null; rm -rf "$base"' EXIT INT TERM HUP

pass=0
fail=0
ok()   { pass=$((pass + 1)); }
bad()  { fail=$((fail + 1)); echo "  FAIL $*"; }
check() {   # $1 = file, $2 = fixed string expected in it, $3 = what
    if grep -qF -- "$2" "$1" 2>/dev/null; then ok;
    else bad "$3: '$2' not in $(basename "$1")"; sed 's/^/    | /' "$1" 2>/dev/null | head -n 12; fi
}
rc_is() {   # $1 = got, $2 = want, $3 = what
    if [ "$1" -eq "$2" ]; then ok; else bad "$3: exit $1, want $2"; fi
}

# ── a PATH with only the tools the scripts use, and the stubs ──────────
bin=$base/bin
mkdir -p "$bin"
for t in sh cat date mkdir sleep kill readlink basename dirname tr sed grep awk wc \
         cut head tail ls rm mv cp id uname mktemp python3 sha256sum; do
    p=$(command -v "$t") || { echo "test_lab_tools: needs $t" >&2; exit 2; }
    ln -s "$p" "$bin/$t"
done
cat > "$bin/tcpdump" <<'EOF'
#!/bin/sh
# Stub: writes a pcap global header and one 802.11 radiotap record,
# then FAKE_TCPDUMP_BYTES of padding, then waits to be stopped.
case ${1:-} in --version) echo "tcpdump version 4.99.4-stub"; exit 0 ;; esac
w=
while [ $# -gt 0 ]; do [ "$1" = -w ] && w=$2; shift; done
[ -n "$w" ] || exit 64
trap 'exit 0' TERM
printf '\324\303\262\241\002\000\004\000\000\000\000\000\000\000\000\000\377\377\000\000\177\000\000\000' > "$w"
printf '\000\000\000\000\000\000\000\000\010\000\000\000\010\000\000\000\000\000\010\000\000\000\000\000' >> "$w"
[ -n "${FAKE_TCPDUMP_BYTES:-}" ] && head -c "$FAKE_TCPDUMP_BYTES" /dev/zero >> "$w"
while :; do sleep 1; done
EOF
cat > "$bin/ethtool" <<'EOF'
#!/bin/sh
case $1 in
    -i) printf 'driver: mt76x2u\nversion: 6.8.0-stub\nfirmware-version: %s\nbus-info: 1-1:1.0\n' \
               "${FAKE_FW-0.0.0.1-stub}" ;;
    -P) echo "Permanent address: 00:c0:ca:00:00:01" ;;
esac
EOF
chmod +x "$bin/tcpdump" "$bin/ethtool"

# ── the fixture host ───────────────────────────────────────────────────
sys=$base/sys
usbdev=$sys/devices/usb1/1-1
mkdir -p "$usbdev/1-1:1.0"
echo 0e8d > "$usbdev/idVendor"
echo 7612 > "$usbdev/idProduct"
echo "MediaTek Inc." > "$usbdev/manufacturer"
echo "WiFi" > "$usbdev/product"
netif() {   # $1 = name, $2 = type, $3 = ifindex
    mkdir -p "$sys/class/net/$1"
    echo "$2" > "$sys/class/net/$1/type"
    echo "$3" > "$sys/class/net/$1/ifindex"
    echo "00:c0:ca:00:00:$3" > "$sys/class/net/$1/address"
    # Every one a complete radio, so a refusal is the guard's and not a
    # later missing-hardware one.
    ln -s "$usbdev/1-1:1.0" "$sys/class/net/$1/device"
}
netif mon0 803 7            # the attacker's: free
netif alfa0 803 5           # sloth-sensor's radio, by /etc/default/sloth
netif mon1 803 8            # held by sloth's packet socket
netif mon2 803 9            # named by the running sloth's --iface
netif wlan0 801 3           # managed

dflt=$base/default-sloth
printf 'SLOTH_IFACE=alfa0\nSLOTH_ARGS=--site-label lab --iface eth0\n' > "$dflt"

mkproc() {  # $1 = proc root, $2 = cmdline args after argv0 (space-separated)
    d=$1/100
    mkdir -p "$d/fd" "$d/net"
    echo sloth > "$d/comm"
    # shellcheck disable=SC2086
    printf '%s\000' /usr/local/bin/sloth $2 > "$d/cmdline"
    ln -s 'socket:[5555]' "$d/fd/3"
    ln -s 'socket:[6666]' "$d/fd/4"
    ln -s /dev/null "$d/fd/0"
    cat > "$d/net/packet" <<'EOF'
sk               RefCnt Type Proto  Iface R Rmem   User   Inode
ffff000000000001 3      3    0003   8     1 0      0      5555
ffff000000000002 3      3    0003   7     1 0      0      9999
EOF
    # 9999 is on mon0 but is not sloth's socket. A slothweb next door:
    mkdir -p "$1/200"
    echo slothweb > "$1/200/comm"
    printf '%s\000' /usr/local/bin/slothweb --iface mon0 > "$1/200/cmdline"
}
proc=$base/proc
mkproc "$proc" "--headless --hop --iface mon2"

out=$base/lab
mkdir -p "$out"
run() {     # lab_capture with the fixture; output in $base/o
    env PATH="$bin" LAB_SYS="$sys" LAB_PROC="$proc" LAB_DEFAULT_SLOTH="$dflt" \
        sh "$cap" --out "$out" "$@" > "$base/o" 2>&1
}

# ── refusals ───────────────────────────────────────────────────────────
run alfa0 L2 "hostapd 2.10" 5/36 1; rc_is $? 2 "SLOTH_IFACE refused"
check "$base/o" "is SLOTH_IFACE in" "SLOTH_IFACE named"
run mon1 L2 "hostapd 2.10" 5/36 1; rc_is $? 2 "a sloth packet socket refused"
check "$base/o" "holds a packet socket of the running sloth (pid 100)" "socket holder named"
run mon2 L2 "hostapd 2.10" 5/36 1; rc_is $? 2 "a running sloth's --iface refused"
check "$base/o" "is an --iface of the running sloth (pid 100)" "--iface named"
# The shipped unit's --monitor-iface (3bdc8638) names the radio the same way.
rm -rf "$proc"; mkproc "$proc" "--headless --monitor-iface mon2"
run mon2 L2 "hostapd 2.10" 5/36 1; rc_is $? 2 "a running sloth's --monitor-iface refused"
check "$base/o" "is an --monitor-iface of the running sloth (pid 100)" "--monitor-iface named"
rm -rf "$proc"; mkproc "$proc" "--headless --hop --iface mon2"
run wlan0 L2 "hostapd 2.10" 5/36 1; rc_is $? 2 "managed mode refused"
check "$base/o" "is not in monitor mode (type 801" "managed named"
run nosuch0 L2 "hostapd 2.10" 5/36 1; rc_is $? 2 "missing interface refused"
run mon0 L9 "x 1" 5/36 1; rc_is $? 2 "test outside L1..L8 refused"
run mon0 L2 "x 1" 5/15 1; rc_is $? 2 "channel outside its band refused"
run mon0 L2 "x 1" 5/36 0; rc_is $? 2 "zero seconds refused"

mv "$bin/ethtool" "$base/ethtool.off"
run mon0 L2 "hostapd 2.10" 5/36 1; rc_is $? 2 "missing ethtool refused"
check "$base/o" "needs ethtool" "missing ethtool named"
mv "$base/ethtool.off" "$bin/ethtool"
mv "$bin/tcpdump" "$base/tcpdump.off"
run mon0 L2 "hostapd 2.10" 5/36 1; rc_is $? 2 "missing tcpdump refused"
check "$base/o" "needs tcpdump or dumpcap" "missing capture tool named"
mv "$base/tcpdump.off" "$bin/tcpdump"

FAKE_FW='' run mon0 L2 "hostapd 2.10" 5/36 1; rc_is $? 2 "no firmware refused"
check "$base/o" "pass --firmware" "no firmware named"
FAKE_FW='' run --firmware "mt7662u 1.0" --dry-run mon0 L2 "hostapd 2.10" 5/36 1
rc_is $? 0 "--firmware accepted"

# An unreadable socket table is a refusal, and so is an unwritable
# output directory; neither can be built when the suite runs as root.
if [ "$(id -u)" -ne 0 ]; then
    chmod 000 "$proc/100/fd"
    run mon0 L2 "hostapd 2.10" 5/36 1; rc_is $? 2 "unreadable sloth sockets refused"
    check "$base/o" "run as root" "unreadable sockets named"
    chmod 755 "$proc/100/fd"
    mkdir -p "$base/ro"
    chmod 555 "$base/ro"
    run --out "$base/ro" mon0 L2 "hostapd 2.10" 5/36 1; rc_is $? 2 "unwritable output refused"
    check "$base/o" "is not writable" "unwritable output named"
else
    echo "  (root: the unreadable-socket and unwritable-dir cases are skipped)"
fi

# ── dry run ────────────────────────────────────────────────────────────
run --dry-run mon0 L2 "hostapd 2.10" 5/36 1; rc_is $? 0 "dry run"
check "$base/o" "chipset MT7612U [usb-id]" "dry run names the chipset"
check "$base/o" "would run  tcpdump -i mon0" "dry run names the command"
n=$(find "$out" -type f | wc -l)
if [ "$n" -eq 0 ]; then ok; else bad "dry run wrote $n files"; fi

# ── a capture, its sidecar and its SHA-256 ─────────────────────────────
run --hw "Alfa AWUS036ACM" mon0 L2 "hostapd 2.10" 5/36 1; rc=$?
rc_is $rc 0 "capture"
pcap=$(find "$out" -name 'L2-*.pcap' | head -n 1)
side=${pcap%.pcap}.json
if [ -s "$pcap" ] && [ -s "$side" ]; then ok; else bad "no pcap/sidecar: $(cat "$base/o")"; fi
case ${pcap#"$out"/} in
    [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]/L2-[0-9]*T[0-9]*Z.pcap) ok ;;
    *) bad "pcap path ${pcap#"$out"/}" ;;
esac
python3 -I - "$side" "$(sha256sum "$pcap" | cut -d' ' -f1)" "$(wc -c < "$pcap")" > "$base/py" 2>&1 <<'EOF'
import json, re, sys
d = json.load(open(sys.argv[1]))
want = {
    ("test",): "L2", ("tool",): "hostapd 2.10", ("band_ghz",): "5", ("channel",): 36,
    ("hardware", "model"): "Alfa AWUS036ACM", ("hardware", "model_source"): "operator",
    ("hardware", "chipset"): "MT7612U", ("hardware", "id"): "0e8d:7612",
    ("driver", "name"): "mt76x2u", ("driver", "version"): "6.8.0-stub",
    ("driver", "firmware"): "0.0.0.1-stub", ("interface", "name"): "mon0",
    ("interface", "mac"): "00:c0:ca:00:00:01", ("capture", "sha256"): sys.argv[2],
    ("capture", "bytes"): int(sys.argv[3]), ("capture", "stopped_by"): "duration",
    ("capture", "tool"): "tcpdump", ("ruling",): "plan #145 ruling 2",
}
for path, v in want.items():
    x = d
    for k in path:
        x = x.get(k) if isinstance(x, dict) else None
    print("ok" if x == v else "bad %s=%r want %r" % (".".join(path), x, v))
t = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
for k in ("utc_start", "utc_end"):
    print("ok" if t.match(d.get(k) or "") else "bad %s=%r" % (k, d.get(k)))
print("ok" if d["utc_end"] >= d["utc_start"] else "bad end before start")
for k in ("host",):
    print("ok" if d.get(k) else "bad no %s" % k)
print("ok" if d["capture"]["version"].startswith("tcpdump version") else "bad capture version")
print("ok" if d["capture"]["file"] == sys.argv[1].rsplit("/", 1)[1][:-5] + ".pcap" else "bad file name")
EOF
while read -r l; do
    case $l in ok) ok ;; *) bad "sidecar: $l" ;; esac
done < "$base/py"
# The digest is of the bytes the stub wrote: its first 4 are the pcap magic.
m=$(head -c 4 "$pcap" | od -An -tx1 | tr -d ' \n')
if [ "$m" = d4c3b2a1 ]; then ok; else bad "pcap magic $m"; fi

# The size bound: 2 MiB written against --max-mb 1.
rm -rf "${out:?}"/*
FAKE_TCPDUMP_BYTES=2097152 run --hw x --max-mb 1 mon0 L4 "mdk4 4.2" 2.4/6 30; rc_is $? 0 "size-bounded capture"
check "$base/o" "stopped by size" "size bound stops the capture"
side=$(find "$out" -name 'L4-*.json' | head -n 1)
check "$side" '"stopped_by": "size"' "size bound in the sidecar"

# ── expect.sh ──────────────────────────────────────────────────────────
ej() {      # $1 = name, $2.. = alert type names for /api/alerts rows
    f=$base/$1.json; shift
    python3 -I -c '
import json, sys
rows = [{"id": "a%d" % i, "type": 0, "type_name": t} for i, t in enumerate(sys.argv[2:])]
json.dump({"now": 1, "rows": rows, "count": len(rows), "total": len(rows),
           "more": False, "next_offset": None}, open(sys.argv[1], "w"))' "$f" "$@"
}
ij() {      # $1 = name, $2.. = alert member type names
    f=$base/$1.json; shift
    python3 -I -c '
import json, sys
m = [{"member": i + 1, "kind": "alert", "id": "x", "type": t} for i, t in enumerate(sys.argv[2:])]
m.append({"member": 99, "kind": "filter", "type": None, "addr": "00:c0:ca:00:00:01"})
json.dump({"store": "open", "incident": {"id": 4, "title": "lab L2", "state": "incident",
           "open": True}, "members": m, "more": False}, open(sys.argv[1], "w"))' "$f" "$@"
}
ex() { env PATH="$bin" sh "$exp" "$@" > "$base/o" 2>&1; }

ej a_twin EVIL_TWIN DEAUTH_FLOOD
ij i_none
ex --alerts-json "$base/a_twin.json" --incident-json "$base/i_none.json" - 4 L2; rc_is $? 0 "L2 PASS"
check "$base/o" "PASS        EVIL_TWIN (alerts)" "L2 names EVIL_TWIN"
check "$base/o" "absent      EVIL_TWIN_PROXIMITY (optional)" "L2 optional type reported"
check "$base/o" "unexpected  DEAUTH_FLOOD" "L2 lists the unexpected type"
check "$base/o" 'incident 4: "lab L2"' "incident read"

ej a_karma KARMA_AP
ex --alerts-json "$base/a_karma.json" - 4 L3; rc_is $? 1 "L3 FAIL without KARMA_PROBE_FORGE"
check "$base/o" "FAIL        KARMA_PROBE_FORGE not raised" "L3 names the missing type"
check "$base/o" "RESULT      FAIL" "L3 result"

ej a_none
ij i_hs HANDSHAKE_HARVEST
ex --alerts-json "$base/a_none.json" --incident-json "$base/i_hs.json" - 4 L5; rc_is $? 0 "L5 PASS from members"
check "$base/o" "PASS        HANDSHAKE_HARVEST (members)" "L5 any-of from the incident's members"

ex --alerts-json "$base/a_none.json" --incident-json "$base/i_none.json" - 4 L1; rc_is $? 0 "L1 PASS on nothing"
ex --alerts-json "$base/a_karma.json" - 4 L1; rc_is $? 1 "L1 FAIL on anything"
check "$base/o" "unexpected  KARMA_AP" "L1 lists what it raised"
ex --alerts-json "$base/a_twin.json" - 4 L7; rc_is $? 3 "L7 not judged"
ex --alerts-json "$base/a_twin.json" - 4 L8; rc_is $? 3 "L8 not judged"

ex http://beta-site:8080 4 L2; rc_is $? 2 "host name URL refused"
check "$base/o" "literal address" "host name URL named"
ex http://192.0.2.10:8080 0 L2; rc_is $? 2 "incident 0 refused"
ex http://192.0.2.10:8080 4 L0; rc_is $? 2 "test L0 refused"
printf 'not json' > "$base/junk.json"
ex --alerts-json "$base/junk.json" - 4 L2; rc_is $? 2 "non-JSON answer refused"

# The paging loop over a stub curl that answers from the URL's offset:
# #200's answers (an empty page with more:true and the same next_offset)
# must end the loop, and a real second page must still be read.
cat > "$bin/curl" <<'STUB'
#!/bin/sh
out= url=
while [ $# -gt 0 ]; do
    case $1 in -o) out=$2; shift 2 ;; http*) url=$1; shift ;; *) shift ;; esac
done
exec python3 -I -c '
import json, os, re, sys
url, out = sys.argv[1:]
mode = os.environ.get("LAB_STUB_MODE", "")
if "/api/frrs/incidents" in url:
    json.dump({"store": "open", "incident": {"id": 4, "title": "lab", "state": "incident",
               "open": True}, "members": [], "more": False}, open(out, "w")); sys.exit(0)
off = int(re.search(r"offset=(\d+)", url).group(1))
def page(types, more, nxt):
    rows = [{"id": "a%d" % i, "type": 0, "type_name": t} for i, t in enumerate(types)]
    return {"now": 1, "rows": rows, "count": len(rows), "total": 2, "more": more, "next_offset": nxt}
if mode == "loop200":
    d = page(["EVIL_TWIN", "EVIL_TWIN_PROXIMITY"], True, 2) if off == 0 else page([], True, 2)
else:
    d = page(["EVIL_TWIN"], True, 1) if off == 0 else page(["DEAUTH_FLOOD"], False, None)
json.dump(d, open(out, "w"))' "$url" "$out"
STUB
chmod +x "$bin/curl"
env PATH="$bin" LAB_STUB_MODE=loop200 sh "$exp" http://192.0.2.10:8080 4 L2 > "$base/o" 2>&1
rc_is $? 0 "#200 answers end the paging loop"
check "$base/o" "PASS        EVIL_TWIN (alerts)" "#200 first page still read"
env PATH="$bin" LAB_STUB_MODE=two sh "$exp" http://192.0.2.10:8080 4 L2 > "$base/o" 2>&1
rc_is $? 0 "two pages read"
check "$base/o" "unexpected  DEAUTH_FLOOD" "second page read"
rm -f "$bin/curl"

echo "lab-tools-test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
