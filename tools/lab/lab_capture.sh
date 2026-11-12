#!/bin/sh
# lab_capture.sh — one bench capture for #199, saved the way plan #145
# ruling 2 wants it: the pcap, its SHA-256 and a sidecar naming the
# hardware, chipset, driver and firmware, band and channel, the tool and
# its version, the test number and the UTC start and end.
#
#   usage: tools/lab/lab_capture.sh [options] IFACE TEST TOOL BAND/CHANNEL SECONDS
#
#     IFACE          a monitor-mode interface sloth is NOT capturing on
#     TEST           L1..L8, the row of #199's matrix
#     TOOL           the attack tool and its version, one argument:
#                    "mdk4 4.2", "hostapd-mana 2.6.5", "none" for L1
#     BAND/CHANNEL   2.4/6, 5/36, 6/37 — what the radio is tuned to
#     SECONDS        capture length, 1..3600
#
#   options:
#     --hw MODEL        name the adapter ("Alfa AWUS036ACM"); default is
#                       the USB/PCI strings sysfs gives
#     --chipset NAME    the chipset ("MT7612U"); default from the USB id
#                       or the driver, refused when neither is known
#     --firmware VER    when the driver reports none (dmesg names it)
#     --max-mb N        stop at N MiB of pcap (default 256)
#     --out DIR         default: lab/ at the top of this tree
#     --dry-run, -n     check everything, print what would run, capture nothing
#
# Writes <out>/YYYY-MM-DD/<TEST>-<YYYYMMDDTHHMMSSZ>.pcap and .json beside
# it. Captures are evidence for #151/#156 and are never committed
# (.gitignore has /lab/).
#
# It only listens: tcpdump (dumpcap when installed) on an interface
# already in monitor mode. It never changes the interface's mode,
# channel, power or link state, and never transmits.
#
# Exit 2, with the reason, and nothing captured, when:
#   - a required tool is missing (tcpdump or dumpcap, ethtool, python3,
#     sha256sum or shasum);
#   - IFACE is one sloth captures on: named by --iface in a running
#     sloth's command line, SLOTH_IFACE or an --iface in /etc/default/sloth,
#     or holding one of a running sloth's packet sockets. sloth with no
#     --iface takes the first type-803 interface /sys/class/net lists, so
#     the sockets are the only proof; when they cannot be read (not
#     root), that is a refusal too;
#   - IFACE is not in monitor mode (/sys/class/net/IFACE/type 803 or 804);
#   - chipset or firmware cannot be named and was not given;
#   - the output directory cannot be written, or the pcap already exists.
#
# Test seams: LAB_SYS (default /sys), LAB_PROC (/proc) and
# LAB_DEFAULT_SLOTH (/etc/default/sloth) are read in place of the real
# ones; tests/deploy/test_lab_tools.sh uses them.
set -u

SYS=${LAB_SYS:-/sys}
PROC=${LAB_PROC:-/proc}
DEFAULT_SLOTH=${LAB_DEFAULT_SLOTH:-/etc/default/sloth}

me=lab_capture
die()    { echo "$me: $*" >&2; exit 1; }
refuse() { echo "$me: refused: $*" >&2; exit 2; }
usage()  { sed -n '6,25p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }

hw=
chipset=
firmware=
max_mb=256
here=$(cd "$(dirname "$0")" && pwd)
out=$here/../../lab
dry=0

while [ $# -gt 0 ]; do
    case $1 in
        --hw)       [ $# -ge 2 ] || usage; hw=$2; shift 2 ;;
        --chipset)  [ $# -ge 2 ] || usage; chipset=$2; shift 2 ;;
        --firmware) [ $# -ge 2 ] || usage; firmware=$2; shift 2 ;;
        --max-mb)   [ $# -ge 2 ] || usage; max_mb=$2; shift 2 ;;
        --out)      [ $# -ge 2 ] || usage; out=$2; shift 2 ;;
        --dry-run|-n) dry=1; shift ;;
        -h|--help)  usage ;;
        --)         shift; break ;;
        -*)         echo "$me: unknown option $1" >&2; usage ;;
        *)          break ;;
    esac
done
[ $# -eq 5 ] || usage
iface=$1 test_id=$2 tool=$3 bandch=$4 dur=$5

# ── arguments ──────────────────────────────────────────────────────────
case $iface in
    ''|*/*|.*|*[!A-Za-z0-9_.-]*) refuse "bad interface name '$iface'" ;;
esac
[ "${#iface}" -le 15 ] || refuse "bad interface name '$iface'"
case $test_id in
    L[1-8]) ;;
    *) refuse "test must be L1..L8 (#199's matrix), not '$test_id'" ;;
esac
case $tool in
    ''|*"
"*) refuse "tool + version is one non-empty line" ;;
esac
band=${bandch%%/*}
chan=${bandch#*/}
case $bandch in */*) ;; *) refuse "band/channel is BAND/CHANNEL, e.g. 5/36" ;; esac
case $chan in ''|*[!0-9]*) refuse "channel '$chan' is not a number" ;; esac
case $band in
    2.4) lo=1;  hi=14 ;;
    5)   lo=32; hi=177 ;;
    6)   lo=1;  hi=233 ;;
    *)   refuse "band is 2.4, 5 or 6, not '$band'" ;;
esac
chan=$((chan + 0))
if [ "$chan" -lt "$lo" ] || [ "$chan" -gt "$hi" ]; then refuse "channel $chan is not in the $band GHz band"; fi
case $dur in ''|*[!0-9]*) refuse "seconds '$dur' is not a number" ;; esac
dur=$((dur + 0))
if [ "$dur" -lt 1 ] || [ "$dur" -gt 3600 ]; then refuse "seconds must be 1..3600"; fi
case $max_mb in ''|*[!0-9]*) refuse "--max-mb '$max_mb' is not a number" ;; esac
max_mb=$((max_mb + 0))
if [ "$max_mb" -lt 1 ] || [ "$max_mb" -gt 4096 ]; then refuse "--max-mb must be 1..4096"; fi
max_bytes=$((max_mb * 1048576))

# ── tools ──────────────────────────────────────────────────────────────
if command -v dumpcap >/dev/null 2>&1; then cap=dumpcap
elif command -v tcpdump >/dev/null 2>&1; then cap=tcpdump
else refuse "needs tcpdump or dumpcap"; fi
command -v ethtool >/dev/null 2>&1 || refuse "needs ethtool (driver and firmware come from ethtool -i)"
command -v python3 >/dev/null 2>&1 || refuse "needs python3 (writes the sidecar)"
if command -v sha256sum >/dev/null 2>&1; then sha() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
else refuse "needs sha256sum or shasum"; fi

# ── the interface ──────────────────────────────────────────────────────
net=$SYS/class/net/$iface
[ -d "$net" ] || refuse "no interface $iface ($net)"
iftype=$(cat "$net/type" 2>/dev/null) || refuse "cannot read $net/type"
case $iftype in
    803|804) ;;
    *) refuse "$iface is not in monitor mode (type $iftype, want 803); this script never changes a mode" ;;
esac
ifindex=$(cat "$net/ifindex" 2>/dev/null) || refuse "cannot read $net/ifindex"

# ── is it sloth's? ─────────────────────────────────────────────────────
# /etc/default/sloth: SLOTH_IFACE is the radio sloth-monitor-up readies,
# and SLOTH_ARGS may carry --iface.
if [ -r "$DEFAULT_SLOTH" ]; then
    conf_if=$(sed -n 's/^[[:space:]]*SLOTH_IFACE=//p' "$DEFAULT_SLOTH" | tr -d "\"'" | tail -n 1)
    [ "$conf_if" = "$iface" ] && refuse "$iface is SLOTH_IFACE in $DEFAULT_SLOTH: sloth-sensor's radio"
    conf_args=$(sed -n 's/^[[:space:]]*SLOTH_ARGS=//p' "$DEFAULT_SLOTH" | tr -d "\"'" | tail -n 1)
    # shellcheck disable=SC2086 # word splitting is how systemd reads it
    set -- $conf_args
    while [ $# -gt 0 ]; do
        if [ "$1" = --iface ] && [ "${2:-}" = "$iface" ]; then
            refuse "$iface is an --iface in $DEFAULT_SLOTH's SLOTH_ARGS"
        fi
        shift
    done
    if [ -n "$conf_if" ] && [ "$conf_if" != "$iface" ] &&
       [ "$(cat "$SYS/class/net/$conf_if/type" 2>/dev/null)" = 803 ]; then
        echo "$me: note: $conf_if (sloth-sensor's radio) and $iface are both monitor-mode;" \
             "a sloth (re)started now takes the first type-803 entry /sys/class/net lists" >&2
    fi
fi

slothpids=
for d in "$PROC"/[0-9]*; do
    [ -r "$d/cmdline" ] || continue
    comm=$(cat "$d/comm" 2>/dev/null) || continue
    argv0=$(tr '\0' '\n' < "$d/cmdline" 2>/dev/null | head -n 1)
    [ "$comm" = sloth ] || [ "${argv0##*/}" = sloth ] || continue
    pid=${d##*/}
    slothpids="$slothpids $pid"
    prev=
    for a in $(tr '\0' '\n' < "$d/cmdline" | tr -c '[:alnum:]_.:/=\n-' '_'); do
        [ "$prev" = --iface ] && [ "$a" = "$iface" ] &&
            refuse "$iface is an --iface of the running sloth (pid $pid)"
        prev=$a
    done
    # The packet sockets: /proc/PID/net/packet's Iface (ifindex) per
    # Inode, against the socket inodes in /proc/PID/fd.
    if [ ! -r "$d/fd" ] || [ ! -x "$d/fd" ]; then
        refuse "cannot read sloth (pid $pid)'s open sockets; run as root so $iface can be checked against them"
    fi
    inodes=
    for f in "$d"/fd/*; do
        l=$(readlink "$f" 2>/dev/null) || continue
        case $l in socket:\[*\]) inodes="$inodes ${l#socket:\[}" ;; esac
    done
    inodes=$(echo "$inodes" | tr -d ']')
    [ -r "$d/net/packet" ] ||
        refuse "cannot read $d/net/packet; run as root so $iface can be checked against sloth's sockets"
    hit=$(awk -v want="$ifindex" -v list="$inodes" '
        BEGIN { n = split(list, a, " "); for (i = 1; i <= n; i++) s[a[i]] = 1 }
        NR > 1 && $5 == want && ($9 in s) { print $9; exit }' "$d/net/packet")
    [ -n "$hit" ] && refuse "$iface (ifindex $ifindex) holds a packet socket of the running sloth (pid $pid)"
done

# ── hardware, driver, firmware ─────────────────────────────────────────
dev=$net/device
usb_id=''
sys_name=''
if [ -r "$dev/../idVendor" ]; then              # a USB interface's parent
    usb_id="$(cat "$dev/../idVendor"):$(cat "$dev/../idProduct")"
    sys_name="$(cat "$dev/../manufacturer" 2>/dev/null) $(cat "$dev/../product" 2>/dev/null)"
elif [ -r "$dev/vendor" ]; then                 # PCI
    usb_id="$(sed 's/^0x//' "$dev/vendor"):$(sed 's/^0x//' "$dev/device")"
fi
sys_name=$(echo "$sys_name" | sed 's/^ *//; s/ *$//')
if [ -z "$sys_name" ] && [ -n "$usb_id" ] && command -v lsusb >/dev/null 2>&1; then
    sys_name=$(lsusb -d "$usb_id" 2>/dev/null | head -n 1 | sed 's/^.*ID [0-9a-f:]* //')
fi

ei=$(ethtool -i "$iface" 2>/dev/null) || refuse "ethtool -i $iface failed"
field() { echo "$ei" | sed -n "s/^$1: *//p" | head -n 1; }
driver=$(field driver)
drv_version=$(field version)
fw=$(field firmware-version)
bus=$(field bus-info)
[ -n "$driver" ] || driver=$(basename "$(readlink "$dev/driver" 2>/dev/null)" 2>/dev/null)
[ -n "$driver" ] || refuse "cannot name $iface's driver"
perm=$(ethtool -P "$iface" 2>/dev/null | sed -n 's/^Permanent address: *//p')
[ -n "$perm" ] || perm=$(cat "$net/address" 2>/dev/null)

model_src=operator
if [ -z "$hw" ]; then
    hw=$sys_name
    model_src=sysfs
    [ -n "$hw" ] || refuse "cannot name $iface's hardware; pass --hw \"<model>\""
fi
chip_src=operator
if [ -z "$chipset" ]; then
    chip_src=usb-id
    case $usb_id in
        0e8d:7612) chipset=MT7612U ;;
        0e8d:7961) chipset=MT7921AU ;;
        0e8d:7610) chipset=MT7610U ;;
        148f:5572) chipset=RT5572 ;;
        148f:3070) chipset=RT3070 ;;
        0bda:8812) chipset=RTL8812AU ;;
    esac
    if [ -z "$chipset" ]; then
        chip_src=driver
        case $driver in
            mt76x2u) chipset=MT7612U ;;
            mt7921u) chipset=MT7921AU ;;
            mt76x0u) chipset=MT7610U ;;
            mt7601u) chipset=MT7601U ;;
        esac
    fi
    [ -n "$chipset" ] || refuse "cannot name $iface's chipset (usb id '${usb_id:-none}', driver $driver); pass --chipset"
fi
case $chipset in RTL8812AU|rtl8812au) echo "$me: note: #199 says avoid RTL8812AU (out-of-tree driver)" >&2 ;; esac
fw_src=ethtool
case $fw in ''|N/A|n/a) fw= ;; esac
if [ -n "$firmware" ]; then fw=$firmware; fw_src=operator; fi
[ -n "$fw" ] || refuse "$driver reports no firmware version for $iface; read it from dmesg and pass --firmware"

chan_seen=
if command -v iw >/dev/null 2>&1; then
    chan_seen=$(iw dev "$iface" info 2>/dev/null | sed -n 's/^[[:space:]]*channel \([0-9]*\).*/\1/p' | head -n 1)
    if [ -n "$chan_seen" ] && [ "$chan_seen" != "$chan" ]; then
        echo "$me: warning: $iface is on channel $chan_seen, not $chan; the sidecar records both" >&2
    fi
fi

# ── output ─────────────────────────────────────────────────────────────
day=$(date -u +%Y-%m-%d)
stamp=$(date -u +%Y%m%dT%H%M%SZ)
dir=$out/$day
pcap=$dir/$test_id-$stamp.pcap
side=$dir/$test_id-$stamp.json
probe=$dir
while [ ! -d "$probe" ]; do probe=$(dirname "$probe"); done
[ -w "$probe" ] || refuse "output directory $dir is not writable ($probe)"
[ -e "$pcap" ] && refuse "$pcap already exists"

uid=$(id -u)
if [ "$cap" = dumpcap ]; then
    # No -I: that asks dumpcap to set monitor mode, and this script never
    # changes the interface. Its own autostops back up the watchdog below.
    set -- dumpcap -q -i "$iface" -w "$pcap" -a "duration:$dur" -a "filesize:$((max_bytes / 1000))"
    capver=$(dumpcap -v 2>/dev/null | head -n 1)
else
    set -- tcpdump -i "$iface" -n -U -s 0 -w "$pcap"
    [ "$uid" -eq 0 ] && set -- "$@" -Z root
    capver=$(tcpdump --version 2>&1 | head -n 1)
fi

if [ "$dry" -eq 1 ]; then
    echo "$me: dry run, nothing captured"
    echo "  interface  $iface (ifindex $ifindex, type $iftype, mac ${perm:-?})"
    echo "  hardware   $hw [$model_src], chipset $chipset [$chip_src], usb ${usb_id:-?}"
    echo "  driver     $driver $drv_version, firmware $fw [$fw_src]"
    echo "  test       $test_id, tool '$tool', band $band channel $chan${chan_seen:+ (seen $chan_seen)}"
    echo "  sloth      pids:${slothpids:- none}; $iface is not theirs"
    echo "  would run  $* (stop at ${dur}s or $max_mb MiB)"
    echo "  would write $pcap and $side"
    exit 0
fi

mkdir -p "$dir" || refuse "cannot create $dir"
[ -w "$dir" ] || refuse "output directory $dir is not writable"

t0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
s0=$(date -u +%s)
"$@" >"$dir/.$test_id-$stamp.log" 2>&1 &
cpid=$!
trap 'kill -TERM "$cpid" 2>/dev/null' INT TERM HUP
stopped=tool-exit
while kill -0 "$cpid" 2>/dev/null; do
    now=$(date -u +%s)
    if [ "$((now - s0))" -ge "$dur" ]; then stopped=duration; break; fi
    if [ -f "$pcap" ] && [ "$(wc -c < "$pcap")" -ge "$max_bytes" ]; then stopped=size; break; fi
    sleep 1
done
kill -TERM "$cpid" 2>/dev/null
wait "$cpid"
rc=$?
trap - INT TERM HUP
t1=$(date -u +%Y-%m-%dT%H:%M:%SZ)
if [ "$stopped" = tool-exit ] && [ "$rc" -ne 0 ]; then
    sed 's/^/  /' "$dir/.$test_id-$stamp.log" >&2
    die "$cap exited $rc before the capture ended; no sidecar written"
fi
rm -f "$dir/.$test_id-$stamp.log"
[ -s "$pcap" ] || die "$cap wrote no $pcap; no sidecar written"
bytes=$(wc -c < "$pcap" | tr -d ' ')
digest=$(sha "$pcap")
host=$(uname -n)
kernel=$(uname -r)

python3 -I -c '
import json, sys
(side, test, host, iface, ifindex, mac, hw, msrc, chip, csrc, usb, bus, drv, dver, fw,
 fsrc, kernel, band, chan, seen, tool, cap, capver, pcap, nbytes, sha, maxb, dur,
 stopped, t0, t1) = sys.argv[1:]
doc = {
    "schema": "sloth-lab-capture/1",
    "ruling": "plan #145 ruling 2",
    "test": test,
    "host": host,
    "interface": {"name": iface, "ifindex": int(ifindex), "mac": mac or None},
    "hardware": {"model": hw, "model_source": msrc, "chipset": chip,
                 "chipset_source": csrc, "id": usb or None, "bus": bus or None},
    "driver": {"name": drv, "version": dver or None, "firmware": fw,
               "firmware_source": fsrc, "kernel": kernel},
    "band_ghz": band,
    "channel": int(chan),
    "channel_observed": int(seen) if seen else None,
    "tool": tool,
    "capture": {"tool": cap, "version": capver, "file": pcap, "bytes": int(nbytes),
                "sha256": sha, "max_bytes": int(maxb), "duration_s": int(dur),
                "stopped_by": stopped},
    "utc_start": t0,
    "utc_end": t1,
}
with open(side + ".tmp", "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
' "$side" "$test_id" "$host" "$iface" "$ifindex" "$perm" "$hw" "$model_src" "$chipset" \
  "$chip_src" "$usb_id" "$bus" "$driver" "$drv_version" "$fw" "$fw_src" "$kernel" \
  "$band" "$chan" "$chan_seen" "$tool" "$cap" "$capver" "${pcap##*/}" "$bytes" "$digest" \
  "$max_bytes" "$dur" "$stopped" "$t0" "$t1" || die "could not write $side"
mv "$side.tmp" "$side" || die "could not write $side"
echo "$pcap"
echo "$side"
echo "sha256 $digest  $bytes bytes  $t0 .. $t1  stopped by $stopped"
