#!/bin/sh
# sloth-rf refuses what sloth refuses, in the same words (#213).
#
#   sh tests/replay/rf_refusals.sh ./sloth ./sloth-rf
#
# Both daemons take the receiver's flags (--location, --gps,
# --gps-allow-remote, --gps-baud), the decoders' (--adsb, --aprs,
# --aprs-freq, --aprs-silent-hours, --rtl433, --victron) and --tune, --ticks,
# --strict with --data-socket, --user and --no-privdrop. Each command
# line below is one the flag's own check refuses. It is run through both
# binaries, and three things must hold: sloth-rf exits 2, sloth exits 2,
# and what the two print on stderr is the same bytes.
#
# The unit suite (tests/test_rf_args.c) pins the words against what
# src/main.c printed before the checks were shared; this is the other
# half, the two linked binaries side by side, which only a run can
# show. Nothing here opens a device: every case exits at the flag check,
# before the privilege plan, and --gps is only ever parsed.
#
# The last group is sloth-rf's alone: a capture flag is an unknown
# argument to it, exit 2, where sloth takes the flag.
set -u
sloth=$1
rf=$2
fail=0
n=0

same() {
    n=$((n + 1))
    a=$("$sloth" "$@" 2>&1 >/dev/null </dev/null); ra=$?
    b=$("$rf" "$@" 2>&1 >/dev/null </dev/null); rb=$?
    if [ "$rb" -ne 2 ]; then
        echo "rf-refusals: sloth-rf $* exited $rb, want 2 (refused)" >&2; fail=1
    fi
    if [ "$ra" -ne 2 ]; then
        echo "rf-refusals: sloth $* exited $ra, want 2 (refused)" >&2; fail=1
    fi
    if [ "$a" != "$b" ]; then
        echo "rf-refusals: $* is refused in different words:" >&2
        echo "  sloth:    $a" >&2
        echo "  sloth-rf: $b" >&2
        fail=1
    fi
    if [ -z "$b" ]; then
        echo "rf-refusals: sloth-rf $* gave no reason" >&2; fail=1
    fi
}

same --location 91,0
same --location nonsense
same --gps nonsense
same --gps gpsd://192.0.2.1
same --strict --gps-allow-remote --gps gpsd://192.0.2.1
same --gps-baud 1234
same --gps-baud 9600
same --gps gpsd://127.0.0.1 --gps-baud 9600
same --adsb relative.json
same --adsb sbs://192.0.2.1
same --aprs relative.log
same --aprs-freq 5
same --aprs-freq 144390000
same --aprs-silent-hours 999
same --aprs-silent-hours 3
same --rtl433 relative.jsonl
same --victron relative.jsonl
same --tune
same --tune nope=1
same --ticks 0
same --strict --data-socket tcp:192.0.2.1:9 --data-socket-allow-remote
same --user root --no-privdrop

# The capture's flags are not sloth-rf's.
for flag in --hop --allow-active --monitor-only --bt-monitor --headless; do
    n=$((n + 1))
    out=$("$rf" "$flag" 2>&1 >/dev/null </dev/null); rc=$?
    if [ "$rc" -ne 2 ]; then
        echo "rf-refusals: sloth-rf $flag exited $rc, want 2 (unknown argument)" >&2; fail=1
    fi
    case "$out" in
        "unknown argument: $flag"*) ;;
        *) echo "rf-refusals: sloth-rf $flag was not refused as unknown" >&2; fail=1 ;;
    esac
done

[ "$fail" -eq 0 ] || exit 1
echo "rf-refusals: $n command lines refused alike by $sloth and $rf"
