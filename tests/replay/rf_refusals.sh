#!/bin/sh
# What the two daemons refuse (#213, #216).
#
#   sh tests/replay/rf_refusals.sh ./sloth-wifi ./sloth-rf [./sloth]
#
# Three groups, each a command line run through the linked binaries:
#
#   refused alike    both take the receiver's flags (--location, --gps,
#                    --gps-allow-remote, --gps-baud) and --tune, --ticks,
#                    --strict with --data-socket, --user and
#                    --no-privdrop. Each line is one the flag's own check
#                    refuses: both exit 2, and what they print on stderr
#                    is the same bytes (one copy of the check,
#                    src/gnss_flags.c and src/daemon_start.c).
#   sloth-wifi only  the six decoder flags (--adsb, --aprs, --aprs-freq,
#                    --aprs-silent-hours, --rtl433, --victron). Since the
#                    cutover they are sloth-rf's: sloth-wifi exits 2 on
#                    each, with a value or without, good value or bad,
#                    with one line that names the flag, sloth-rf and
#                    sloth-migrate-rf. sloth-rf, given the same flag with
#                    a value it accepts, does not refuse it; given one it
#                    does not accept, it refuses in its own words, which
#                    are not sloth-wifi's.
#   sloth-rf only    a capture flag is an unknown argument to it, exit 2,
#                    where sloth-wifi takes the flag.
#
# Until #216 the first two were one group: the one binary took the
# decoder flags and the two refused a bad SPEC in the same words.
#
# The third argument, when given, is the `sloth` symlink: it must answer
# exactly as sloth-wifi does, because it is the same program.
#
# The unit suites (tests/test_rf_args.c, tests/test_rf_moved.c) pin the
# words; this is the other half, the linked binaries side by side, which
# only a run can show. Nothing here opens a device: every case exits at
# the flag check, before the privilege plan, and --gps is only parsed.
set -u
sloth=$1
rf=$2
alias=${3:-}
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
        echo "rf-refusals: sloth-wifi $* exited $ra, want 2 (refused)" >&2; fail=1
    fi
    if [ "$a" != "$b" ]; then
        echo "rf-refusals: $* is refused in different words:" >&2
        echo "  sloth-wifi: $a" >&2
        echo "  sloth-rf:   $b" >&2
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
same --tune
same --tune nope=1
same --ticks 0
same --strict --data-socket tcp:192.0.2.1:9 --data-socket-allow-remote
same --user root --no-privdrop

# --jsonl is neither daemon's (owner ruling 2026-11-15; sloth-rf took
# it as a spelling of -o until then). Each prints its own usage after
# the first line, so that line and the exit code are what is compared.
n=$((n + 1))
a=$("$sloth" --jsonl /nonexistent/x.jsonl 2>&1 >/dev/null </dev/null); ra=$?
b=$("$rf" --jsonl /nonexistent/x.jsonl 2>&1 >/dev/null </dev/null); rb=$?
if [ "$ra" -ne 2 ] || [ "$rb" -ne 2 ]; then
    echo "rf-refusals: --jsonl exited $ra (sloth-wifi) and $rb (sloth-rf), want 2 and 2" >&2; fail=1
fi
if [ "$(printf '%s\n' "$a" | head -n 1)" != "unknown argument: --jsonl" ] ||
   [ "$(printf '%s\n' "$b" | head -n 1)" != "unknown argument: --jsonl" ]; then
    echo "rf-refusals: --jsonl was not refused as unknown by both" >&2; fail=1
fi

# The decoders' flags are not sloth-wifi's (#216). $1 the flag, $2 a
# value sloth-rf refuses, $3 one it accepts ("" when the flag alone is
# the case). sloth-wifi refuses all three shapes with the one line.
moved() {
    flag=$1
    want="sloth-wifi: $flag is sloth-rf's flag since the split (JSONL 2.0.0): this daemon reads no SDR decoder. Run 'sloth-migrate-rf --apply' to move it from /etc/default/sloth to /etc/default/sloth-rf, then start sloth-rf (docs/wiki/deployment.md section 11.4)"
    for val in "$2" "$3" ""; do
        n=$((n + 1))
        if [ -n "$val" ]; then
            out=$("$sloth" --headless "$flag" "$val" 2>&1 >/dev/null </dev/null); rc=$?
        else
            out=$("$sloth" --headless "$flag" 2>&1 >/dev/null </dev/null); rc=$?
        fi
        if [ "$rc" -ne 2 ]; then
            echo "rf-refusals: sloth-wifi $flag $val exited $rc, want 2 (the flag is sloth-rf's)" >&2; fail=1
        fi
        if [ "$out" != "$want" ]; then
            echo "rf-refusals: sloth-wifi $flag $val did not give the one guidance line:" >&2
            echo "  got:  $out" >&2
            fail=1
        fi
    done
    # sloth-rf: its own refusal of the bad value, in other words.
    n=$((n + 1))
    out=$("$rf" "$flag" "$2" 2>&1 >/dev/null </dev/null); rc=$?
    if [ "$rc" -ne 2 ] || [ -z "$out" ]; then
        echo "rf-refusals: sloth-rf $flag $2 exited $rc, want 2 with a reason" >&2; fail=1
    fi
    case "$out" in
        *"sloth-rf's flag since the split"*)
            echo "rf-refusals: sloth-rf $flag $2 gave sloth-wifi's line" >&2; fail=1 ;;
    esac
}
moved --adsb relative.json /nonexistent/aircraft.json
moved --aprs relative.log /nonexistent/aprs.log
moved --aprs-freq 5 144390000
moved --aprs-silent-hours 999 3
moved --rtl433 relative.jsonl /nonexistent/events.jsonl
moved --victron relative.jsonl /nonexistent/victron.jsonl

# And sloth-rf takes them: one run with every decoder flag and a value
# it accepts gets past the flag checks (no file is opened by a check; a
# decoder's file that is not there is a state). --ticks 1, no sink, no
# privilege drop: it starts, ticks once and exits 0.
n=$((n + 1))
out=$("$rf" --no-privdrop --ticks 1 --adsb /nonexistent/aircraft.json \
      --aprs /nonexistent/aprs.log --aprs-freq 144390000 --aprs-silent-hours 3 \
      --rtl433 /nonexistent/events.jsonl --victron /nonexistent/victron.jsonl \
      2>&1 >/dev/null </dev/null); rc=$?
if [ "$rc" -ne 0 ]; then
    echo "rf-refusals: sloth-rf with the six decoder flags exited $rc, want 0:" >&2
    echo "  $out" >&2
    fail=1
fi

# The receiver's flags stay sloth-wifi's: none of them gets the line.
for flag in --gps --location --gps-baud; do
    n=$((n + 1))
    out=$("$sloth" --headless "$flag" nonsense 2>&1 >/dev/null </dev/null); rc=$?
    case "$out" in
        *"sloth-rf's flag"*)
            echo "rf-refusals: sloth-wifi refused $flag as sloth-rf's" >&2; fail=1 ;;
    esac
    [ "$rc" -eq 2 ] || { echo "rf-refusals: sloth-wifi $flag nonsense exited $rc, want 2" >&2; fail=1; }
done

# `sloth` is sloth-wifi: the same refusal and the same --version.
if [ -n "$alias" ]; then
    n=$((n + 1))
    a=$("$sloth" --adsb /x 2>&1 >/dev/null </dev/null); ra=$?
    b=$("$alias" --adsb /x 2>&1 >/dev/null </dev/null); rb=$?
    if [ "$ra" -ne 2 ] || [ "$rb" -ne 2 ] || [ "$a" != "$b" ]; then
        echo "rf-refusals: $alias --adsb answered ($rb) other than $sloth ($ra)" >&2; fail=1
    fi
    va=$("$sloth" --version 2>&1); vb=$("$alias" --version 2>&1)
    if [ -z "$va" ] || [ "$va" != "$vb" ]; then
        echo "rf-refusals: $alias --version differs from $sloth --version" >&2; fail=1
    fi
    if [ ! -L "$alias" ] || [ "$(readlink "$alias")" != "${sloth##*/}" ]; then
        echo "rf-refusals: $alias is not a symlink to ${sloth##*/}" >&2; fail=1
    fi
fi

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
echo "rf-refusals: $n command lines checked on $sloth and $rf"
