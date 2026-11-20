#!/bin/sh
# One host, three packages (#236, #184 Stage 5): sloth, sloth-mesh and
# sloth-comint built from their checkouts, installed side by side, their
# units verified, the one `sloth` account checked, and the five degraded
# modes run with the binaries started directly (there is no systemd
# inside the container, and none is needed: every unit only orders
# against the others, After= and Wants=, never Requires=).
#
#   tests/deploy/test_three_repos.sh SLOTH MESH COMINT
#
# SLOTH, MESH and COMINT are the three checkouts. Each is cloned at its
# HEAD into a work directory and built there, so a checkout is never
# written to (sloth-mesh's `make update-contract` rewrites its tree).
#
# Where it installs:
#   - THREE_REPOS_SYSTEM=1, as root (CI's debian:trixie container): into
#     / itself, `make install` and `make install-service` as an operator
#     runs them, then the real systemd-sysusers, and the modes run as the
#     `sloth` account (setpriv);
#   - otherwise (a developer's machine, never root's /): into a scratch
#     DESTDIR under the work directory, systemd-sysusers --root on it
#     where that works without privilege, and the modes as the caller.
#
# The modes, and the test that holds each in the repository that owns it:
#   1. sensor alone: sloth-wifi --headless replays the synthetic captures
#      (sloth's tests/replay, `make replay-check`) into JSONL and
#      sloth.db, nothing else running.
#   2. dash alone: slothweb with no sensor on its socket and that sloth.db
#      copied elsewhere: never connected, sensor state "unknown" (no
#      sensor_health; "not_observing" is the word for a sensor that says
#      it has no handle open, sloth-mesh tests/test_live.c), and the copy
#      browses (sloth-mesh tests/deploy/test_degraded.sh).
#   3. comint alone: sloth-comintd serves /v1/health and /v1/pack, the
#      tar byte for byte (sloth-comint tests/run_shell.sh, test_server.c).
#   4. dash without comint: a --comintd nothing listens on; intel_source
#      "snapshot" and the snapshot's OUI answer (sloth-mesh
#      tests/test_intel.c, test_degraded.sh).
#   5. dash with comint: the real sloth-comintd; intel_source "comintd",
#      its pack's version and hash in /api/health, the OUI answer from it
#      (sloth-mesh tests/test_intel.c, with a fake).
# Everything listens on loopback or a unix socket in the run directory.
#
# Environment: THREE_REPOS_WORK (a directory to use, kept, its clones
# reused when already at the same commit; default a new
# one under TMPDIR, removed), THREE_REPOS_KEEP=1 (keep the default one),
# THREE_REPOS_JOBS (make -j, default 2: the reference host is a live
# sensor), EXTRA_CFLAGS (passed through to every build, as CI's -Werror).
#
# SC2015: ok() always returns 0, so `A && ok || no` is if-then-else here.
# SC2086: $units and $frags are lists of paths with no blank in them
# (the work directory is mktemp's or one without), split on purpose.
# shellcheck disable=SC2015,SC2086
set -u

[ "$#" -eq 3 ] || { echo "usage: $0 SLOTH MESH COMINT" >&2; exit 2; }
abs() { (cd "$1" 2> /dev/null && pwd); }
sloth_src=$(abs "$1") && mesh_src=$(abs "$2") && comint_src=$(abs "$3") ||
    { echo "test_three_repos: a checkout is not a directory" >&2; exit 2; }
for t in git make cc curl python3; do
    command -v "$t" > /dev/null || { echo "test_three_repos: needs $t" >&2; exit 2; }
done
jobs=${THREE_REPOS_JOBS:-2}

pass=0
fail=0
skip=0
ok() { pass=$((pass + 1)); }
no() { fail=$((fail + 1)); echo "  FAIL $*"; }
skipped() { skip=$((skip + 1)); echo "  SKIP $*"; }
step() { echo "── $*"; }

if [ -n "${THREE_REPOS_WORK:-}" ]; then
    work=$THREE_REPOS_WORK
    mkdir -p "$work" || exit 2
    keep=1
else
    work=$(mktemp -d "${TMPDIR:-/tmp}/three-repos.XXXXXX") || exit 2
    keep=${THREE_REPOS_KEEP:-0}
fi
pids=
cleanup() {
    for p in $pids; do kill "$p" 2> /dev/null; done
    for p in $pids; do wait "$p" 2> /dev/null; done
    if [ "$keep" = 1 ]; then echo "test_three_repos: kept $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

system=0
if [ "${THREE_REPOS_SYSTEM:-0}" = 1 ]; then
    [ "$(id -u)" = 0 ] || { echo "test_three_repos: THREE_REPOS_SYSTEM=1 needs root" >&2; exit 2; }
    system=1
    root=
    # The modes run as sloth, which must reach the built tree and the run
    # directory under it; mktemp made it 0700.
    chmod 755 "$work"
    echo "test_three_repos: installing into / (THREE_REPOS_SYSTEM=1)"
else
    root=$work/root
    rm -rf "$root"
    # Laid out as Debian 13 is (merged /usr): /lib, /bin and /sbin are
    # links into /usr, so sloth-comint's /lib/systemd/system lands where
    # systemd looks (it no longer searches /lib on its own).
    mkdir -p "$root/usr/lib" "$root/usr/bin" "$root/usr/sbin"
    ln -s usr/lib "$root/lib"
    ln -s usr/bin "$root/bin"
    ln -s usr/sbin "$root/sbin"
    echo "test_three_repos: installing into DESTDIR=$root"
fi

# A field of the JSON document on stdin, by dotted path; MISSING when it
# is not there. python3 -I: nothing from the run directory is imported.
field() {
    python3 -I -c '
import json, sys
try:
    v = json.load(sys.stdin)
except ValueError:
    print("NOTJSON"); sys.exit(0)
for k in sys.argv[1].split("."):
    if not isinstance(v, dict) or k not in v:
        print("MISSING"); sys.exit(0)
    v = v[k]
print(json.dumps(v) if not isinstance(v, str) else v)' "$1"
}

# ── Build: sloth, its contract; sloth-mesh against it; sloth-comint ───
mk() { d=$1; shift; make -C "$work/src/$d" -j"$jobs" "$@" > "$work/log/$d.$(echo "$*" | tr ' /=' '___').log" 2>&1; }
mkdir -p "$work/src" "$work/log"
for pair in "sloth:$sloth_src" "mesh:$mesh_src" "comint:$comint_src"; do
    name=${pair%%:*} src=${pair#*:}
    head=$(git -C "$src" rev-parse HEAD) || { no "$src is not a git checkout"; exit 1; }
    # A clone already at that commit (a kept THREE_REPOS_WORK) is built
    # again incrementally rather than cloned afresh.
    if [ "$(git -C "$work/src/$name" rev-parse HEAD 2> /dev/null)" != "$head" ]; then
        rm -rf "$work/src/$name"
        git clone -q "$src" "$work/src/$name" && git -C "$work/src/$name" checkout -q "$head" ||
            { no "clone $src"; exit 1; }
    fi
    echo "test_three_repos: $name at $head"
done

step "build sloth and its contract"
if mk sloth && mk sloth contract; then ok; else no "sloth: make, make contract (see $work/log)"; exit 1; fi
tar=
for f in "$work"/src/sloth/dist/sloth-contract-*.tar; do [ -f "$f" ] && tar=$f; done
[ -n "$tar" ] && ok || { no "no contract tar"; exit 1; }
# The sensor's synthetic captures (tests/replay/gen_replay.c), for mode 1.
mk sloth build/replay/gen_replay && ok || no "sloth: the replay generator"

step "build sloth-mesh against that contract"
if mk mesh update-contract TAR="$tar" && mk mesh && mk mesh build/web/slothweb-demo; then ok;
else no "sloth-mesh: update-contract, make (see $work/log)"; exit 1; fi

step "build sloth-comint and its database"
if mk comint && mk comint db; then ok; else no "sloth-comint: make, make db (see $work/log)"; exit 1; fi
pack=
for f in "$work"/src/comint/dist/sloth-intel-pack-*.tar; do [ -f "$f" ] && pack=$f; done
[ -n "$pack" ] && [ -f "$work/src/comint/build/comint.db" ] && ok || { no "no pack tar or comint.db"; exit 1; }

# ── Install all three ───────────────────────────────────────────────────
step "install"
mk sloth install DESTDIR="$root" && mk sloth install-service DESTDIR="$root" && ok || no "sloth: install, install-service"
mk mesh install DESTDIR="$root" && mk mesh install-service DESTDIR="$root" && ok || no "sloth-mesh: install, install-service"
mk comint install DESTDIR="$root" && ok || no "sloth-comint: install"
# What the comint README says to put where its unit reads it.
install -d "$root/var/lib/sloth-comint" &&
    install -m 644 "$work/src/comint/build/comint.db" "$root/var/lib/sloth-comint/comint.db" &&
    install -m 644 "$pack" "$root/var/lib/sloth-comint/sloth-intel-pack.tar" && ok || no "the comint database and pack"
bin=$root/usr/local/bin
for b in sloth-wifi sloth-rf slothweb sloth-comintd; do
    [ -x "$bin/$b" ] && ok || no "$bin/$b not installed"
done

# ── The units ───────────────────────────────────────────────────────────
# Every unit the three installed, as the path an operator would name.
units=
for f in "$root"/etc/systemd/system/*.service "$root"/etc/systemd/system/*.path \
         "$root"/etc/systemd/system/*.timer "$root"/usr/lib/systemd/system/sloth-comintd.service; do
    [ -f "$f" ] && units="$units ${f#"$root"}"
done
for u in sloth-sensor.service slothweb.service sloth-comintd.service; do
    printf '%s\n' $units | grep -q "/$u\$" && ok || no "$u not installed"
done
# No unit of one package Requires= (or BindsTo=, Requisite=, PartOf=) a
# unit of another: each degrades alone (#184 C8, ADR 0005). Within sloth
# a helper may be PartOf= the sensor; slothweb's and comintd's units name
# no unit in those keys at all, and sloth's name neither of theirs.
for u in $units; do
    hard=$(grep -E '^(Requires|BindsTo|Requisite|PartOf)=' "$root$u")
    case $(basename "$u") in
        slothweb.service|sloth-comintd.service)
            hard=$(printf '%s\n' "$hard" | grep -E 'sloth') ;;
        *)  hard=$(printf '%s\n' "$hard" | grep -E 'slothweb|sloth-comintd') ;;
    esac
    [ -z "$hard" ] && ok || no "$(basename "$u") requires another package's unit: $hard"
done

step "systemd-analyze verify"
# Offline: it loads each unit with a test manager and needs no running
# systemd, so it works in a container. Against a DESTDIR it is pointed
# at the staged tree with --root, which resolves the units' commands
# there too: the system commands they name outside /usr/local (/bin/rm)
# are copied in from this host, and said. A unit outside the three
# packages that one of them names (bluetooth.service, for sloth-va's
# Requires=) is given an empty stub under /run/systemd/system, and said,
# so what is verified is these units, not the image's package set; a
# missing unit of the three is a failure.
verify() {
    if [ "$system" = 1 ]; then systemd-analyze verify $units; else systemd-analyze verify --root="$root" $units; fi
}
verified=0
if command -v systemd-analyze > /dev/null 2>&1; then
    if [ "$system" = 0 ]; then
        for u in $units; do
            sed -n 's/^Exec[A-Za-z]*=[-+!@:]*\(\/[^ ]*\).*/\1/p' "$root$u"
        done | sort -u > "$work/log/execs"
        while IFS= read -r x; do
            case $x in /usr/local/*) continue ;; esac
            [ -e "$root$x" ] || [ ! -x "$x" ] || { cp "$x" "$root$x" && echo "  (copied $x into the staged root for verify)"; }
        done < "$work/log/execs"
    fi
    verify > "$work/log/verify.log" 2>&1
    rc=$?
    sed -n 's/.*Unit \([^ ]*\) not found\.$/\1/p' "$work/log/verify.log" | sort -u > "$work/log/missing"
    stubbed=0
    while IFS= read -r n; do
        case " $units " in *"/$n "*) continue ;; esac
        mkdir -p "$root/run/systemd/system"
        printf '[Unit]\nDescription=stub for systemd-analyze verify (not one of the three packages)\n[Service]\nType=oneshot\nExecStart=/bin/true\n' \
            > "$root/run/systemd/system/$n"
        [ "$system" = 1 ] || [ -e "$root/bin/true" ] || cp /bin/true "$root/bin/true"
        echo "  ($n is not one of the three packages' units; stubbed for verify)"
        stubbed=1
    done < "$work/log/missing"
    if [ "$stubbed" = 1 ]; then verify > "$work/log/verify.log" 2>&1; rc=$?; fi
    if [ "$rc" -eq 0 ]; then ok; verified=1;
    elif grep -qiE 'Failed to (initialize|set up|create) .*manager|Operation not permitted|Permission denied' "$work/log/verify.log"; then
        skipped "systemd-analyze verify cannot run here ($(head -n 1 "$work/log/verify.log")); the units' syntax is checked below instead"
    else
        no "systemd-analyze verify: $(cat "$work/log/verify.log")"
        verified=1
    fi
else
    skipped "no systemd-analyze; the units' syntax is checked below instead"
fi
# Where verify could not run: every unit has its sections, each key
# line is KEY=VALUE inside one, and every ExecStart= names an installed
# executable.
if [ "$verified" = 0 ]; then
    for u in $units; do
        bad=$(awk '
            /^[ \t]*([#;]|$)/ { next }
            cont { cont = /\\$/; next }
            /^\[(Unit|Service|Install|Path|Timer)\]$/ { sec = 1; next }
            /^\[/ { print "unknown section " $0; next }
            !sec { print "key before any section: " $0; next }
            !/^[A-Za-z][A-Za-z0-9]*=/ { print "not KEY=VALUE: " $0 }
            { cont = /\\$/ }' "$root$u")
        [ -z "$bad" ] && ok || no "$(basename "$u"): $bad"
        sed -n 's/^ExecStart=[-+!@:]*\([^ ]*\).*/\1/p' "$root$u" > "$work/log/exec"
        while IFS= read -r x; do
            [ -x "$root$x" ] && ok || no "$(basename "$u"): ExecStart $x is not installed"
        done < "$work/log/exec"
    done
fi

# ── One sloth account ───────────────────────────────────────────────────
step "the sloth account"
frags=$(ls "$root"/usr/lib/sysusers.d/*.conf 2> /dev/null)
lines=$(for f in "$root/usr/lib/sysusers.d/sloth.conf" "$root/usr/lib/sysusers.d/slothweb.conf" \
                 "$root/usr/lib/sysusers.d/sloth-comint.conf"; do
            grep -E '^u[[:space:]]+sloth[[:space:]]' "$f" 2> /dev/null || echo "MISSING in $f"
        done)
[ "$(printf '%s\n' "$lines" | sort -u | wc -l)" -eq 1 ] && ! printf '%s\n' "$lines" | grep -q MISSING && ok ||
    no "the three packages' sloth lines differ: $lines"
if command -v systemd-sysusers > /dev/null 2>&1; then
    if [ "$system" = 1 ]; then
        systemd-sysusers > "$work/log/sysusers.log" 2>&1; rc=$?
        passwd=/etc/passwd group=/etc/group
    else
        mkdir -p "$root/etc"
        systemd-sysusers --root="$root" $frags > "$work/log/sysusers.log" 2>&1; rc=$?
        passwd=$root/etc/passwd group=$root/etc/group
    fi
    if [ "$rc" -eq 0 ] && [ -f "$passwd" ]; then
        n=$(grep -c '^sloth:' "$passwd")
        [ "$n" -eq 1 ] && ok || no "$n sloth accounts in $passwd"
        n=$(grep -c '^sloth:' "$group")
        [ "$n" -eq 1 ] && ok || no "$n sloth groups in $group"
        grep '^sloth:' "$passwd" | grep -q ':/var/lib/sloth:/usr/sbin/nologin$' && ok || no "the sloth account: $(grep '^sloth:' "$passwd")"
    elif [ "$system" = 0 ]; then
        skipped "systemd-sysusers --root needs privilege here ($(head -n 1 "$work/log/sysusers.log"))"
    else
        no "systemd-sysusers: $(cat "$work/log/sysusers.log")"
    fi
else
    skipped "no systemd-sysusers"
fi

# ── The five modes ──────────────────────────────────────────────────────
run=$work/run
rm -rf "$run"
mkdir -p "$run"
# As root, everything runs as the account the units name.
as_sloth() {
    if [ "$system" = 1 ]; then
        setpriv --reuid=sloth --regid=sloth --init-groups --reset-env -- "$@"
    else
        "$@"
    fi
}
# The same in the background, $! the daemon itself (setpriv execs it),
# not a subshell around it, so a kill reaches it. Output to $1.
started=
bg_sloth() {
    out=$1
    shift
    if [ "$system" = 1 ]; then
        setpriv --reuid=sloth --regid=sloth --init-groups --reset-env -- "$@" > "$out" 2>&1 &
    else
        "$@" > "$out" 2>&1 &
    fi
    started=$!
    pids="$pids $started"
}
[ "$system" = 0 ] || chown -R sloth:sloth "$run"
cd "$run" || exit 1
port=$((20000 + $$ % 20000))
web_port=$port comint_port=$((port + 1)) dead_port=$((port + 2))
web=http://127.0.0.1:$web_port
wait_http() {   # URL: up within 10 s
    i=0
    until curl -fs "$1" > /dev/null 2>&1; do
        i=$((i + 1))
        [ "$i" -lt 100 ] || return 1
        sleep 0.1
    done
}
stop_all() {
    for p in $pids; do kill "$p" 2> /dev/null; done
    for p in $pids; do wait "$p" 2> /dev/null; done
    pids=
}

step "1. sensor alone"
mkdir -p sensor
[ "$system" = 0 ] || chown sloth:sloth sensor
as_sloth "$work/src/sloth/build/replay/gen_replay" "$run/sensor" > /dev/null 2>&1 && ok || no "the replay captures"
as_sloth "$bin/sloth-wifi" --headless \
    --replay "$run/sensor/wired.pcap,$run/sensor/monitor.pcap,$run/sensor/bt.pcap" \
    -o "$run/sensor/out.jsonl" --db "$run/sensor/sloth.db" --ticks 3 --refresh-ms 100 \
    > sensor/sloth.log 2>&1
rc=$?
[ "$rc" -eq 0 ] && ok || no "sloth-wifi --replay exited $rc: $(tail -n 3 sensor/sloth.log)"
grep -q '"type":"sensor_health"' sensor/out.jsonl 2> /dev/null && ok || no "no sensor_health in the JSONL"
n=$(python3 -I -c 'import sqlite3,sys; print(sqlite3.connect("file:"+sys.argv[1]+"?mode=ro", uri=True).execute("select count(*) from devices").fetchone()[0])' "$run/sensor/sloth.db" 2> /dev/null)
[ "${n:-0}" -gt 0 ] 2> /dev/null && ok || no "sloth.db has no devices ($n)"

step "2. dash alone (no sensor, a copied sloth.db)"
mkdir -p copied
cp sensor/sloth.db copied/sloth.db
[ "$system" = 0 ] || chown -R sloth:sloth copied
web_pid=
start_web() {
    # A relative socket path: the run directory's own may pass the
    # 107-byte limit of a unix socket's name.
    bg_sloth "$run/web.log" "$bin/slothweb" --socket unix:none.sock --sloth-db "$run/copied/sloth.db" \
        --store "$run/web.db" --web-bind "127.0.0.1:$web_port" "$@"
    web_pid=$started
    wait_http "$web/api/health" || { no "slothweb did not answer: $(tail -n 5 "$run/web.log")"; return 1; }
}
stop_web() {
    [ -n "$web_pid" ] || return 0
    kill "$web_pid" 2> /dev/null
    wait "$web_pid" 2> /dev/null
    pids=$(for p in $pids; do [ "$p" = "$web_pid" ] || printf '%s ' "$p"; done)
    web_pid=
}
if start_web; then
    h=$(curl -s "$web/api/health")
    s=$(printf '%s' "$h" | field socket)
    [ "$s" != connected ] && [ "$s" != MISSING ] && ok || no "dash alone: socket '$s'"
    st=$(curl -s "$web/api/live" | field sensor.state)
    [ "$st" = unknown ] && ok || no "dash alone: sensor state '$st', want unknown"
    [ "$(printf '%s' "$h" | field intel_source)" = snapshot ] && ok || no "dash alone: intel_source $(printf '%s' "$h" | field intel_source)"
    n=$(curl -s "$web/api/devices?limit=5" | field count)
    [ "$n" -gt 0 ] 2> /dev/null && ok || no "dash alone: the copied sloth.db does not browse ($n)"
    # The bundle names every version (#184 C7).
    for k in mesh sensor sloth_commit jsonl db_schema intel_pack; do
        [ "$(printf '%s' "$h" | field "contract.$k")" != MISSING ] && ok || no "/api/health contract.$k missing"
    done
fi
stop_web

step "3. comint alone"
bg_sloth comintd.log "$bin/sloth-comintd" --db "$root/var/lib/sloth-comint/comint.db" \
    --pack "$root/var/lib/sloth-comint/sloth-intel-pack.tar" \
    --listen "127.0.0.1:$comint_port"
comint=http://127.0.0.1:$comint_port
if wait_http "$comint/v1/health"; then
    ch=$(curl -s "$comint/v1/health")
    [ "$(printf '%s' "$ch" | field service)" = sloth-comintd ] && ok || no "comint alone: /v1/health $ch"
    curl -s -o comint-pack.tar "$comint/v1/pack"
    cmp -s comint-pack.tar "$root/var/lib/sloth-comint/sloth-intel-pack.tar" && ok || no "comint alone: /v1/pack is not the pack"
else
    no "sloth-comintd did not answer: $(tail -n 5 comintd.log)"
    ch=
fi

step "4. dash without comint"
if start_web --comintd "http://127.0.0.1:$dead_port"; then
    h=$(curl -s "$web/api/health")
    [ "$(printf '%s' "$h" | field intel_source)" = snapshot ] && ok || no "no comint: intel_source $(printf '%s' "$h" | field intel_source)"
    [ "$(printf '%s' "$h" | field comintd.state)" = down ] && ok || no "no comint: comintd.state $(printf '%s' "$h" | field comintd.state)"
    [ "$(curl -s "$web/api/lookup?q=b8:27:eb:00:53:01" | field oui.intel)" = snapshot ] && ok || no "no comint: the lookup is not the snapshot's"
fi
stop_web

step "5. dash with comint"
if [ -n "$ch" ] && start_web --comintd "$comint"; then
    h=$(curl -s "$web/api/health")
    [ "$(printf '%s' "$h" | field intel_source)" = comintd ] && ok || no "with comint: intel_source $(printf '%s' "$h" | field intel_source): $(printf '%s' "$h" | field comintd)"
    for k in version sha256; do
        want=$(printf '%s' "$ch" | field "pack.$k")
        got=$(printf '%s' "$h" | field "comintd.pack.$k")
        [ "$got" = "$want" ] && [ "$got" != MISSING ] && ok || no "with comint: comintd.pack.$k '$got', /v1/health says '$want'"
    done
    lk=$(curl -s "$web/api/lookup?q=b8:27:eb:00:53:01")
    [ "$(printf '%s' "$lk" | field oui.intel)" = comintd ] && ok || no "with comint: the lookup did not ask comintd: $(printf '%s' "$lk" | field oui)"
    [ "$(printf '%s' "$lk" | field oui.found)" = true ] && ok || no "with comint: the lookup found nothing"
fi
stop_all

echo "three-repos: $pass passed, $fail failed, $skip skipped"
[ "$fail" -eq 0 ]
