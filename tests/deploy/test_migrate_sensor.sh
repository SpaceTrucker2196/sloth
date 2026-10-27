#!/bin/sh
# Tests for packaging/bin/sloth-migrate-sensor (#153). Run by `make deploy-test`.
#
# Everything runs unprivileged against a scratch root: a fake build-tree
# unit written here (never read from /etc), a fake data dir, a fake
# /proc/<pid>/status, and stub systemctl / systemd-sysusers / getent /
# chown / socat that log every call. Nothing outside the scratch dir is
# read or written, and no real service is touched.
#
# The absence assertions here (a dry run changes nothing, a refusal changes
# nothing, a bad copy never installs the unit, a rollback leaves no trace
# of the hardened unit or of a defaults file it wrote, a second run changes
# nothing, --no-privdrop is not carried, the source data is not modified,
# the copy keeps no group/other bits, a signal leaves no hardened unit and
# no socket reader behind, an unstable rollback is not reported as done)
# were each seen to fail under a mutation of the tool before this file
# claimed them: docs/wiki/log.md, the #153 entries, names each one.
#
# check() evals its first argument, so the single-quoted expressions are
# meant not to expand here (SC2016), the variables they read look unused
# to shellcheck (SC2034), and the extra ExecStart lines passed to setup()
# end in a literal backslash (SC1003).
# shellcheck disable=SC2016,SC2034,SC1003
set -u

REPO=$(cd "$(dirname "$0")/../.." && pwd)
TOOL=$REPO/packaging/bin/sloth-migrate-sensor
# The shell the tool runs under: TOOL_SH="busybox sh" or "bash --posix"
# checks it stays POSIX.
TOOL_SH=${TOOL_SH:-sh}
SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/sloth-deploy-test.XXXXXX") || exit 1
# KEEP=1 leaves the scratch tree behind for inspection.
[ -n "${KEEP:-}" ] || trap 'rm -rf "$SCRATCH"' EXIT INT TERM

PASS=0
FAIL=0
CASE=""
ok()    { PASS=$((PASS + 1)); }
bad()   { FAIL=$((FAIL + 1)); echo "FAIL [$CASE]: $*" >&2; }
check() { if eval "$1"; then ok; else bad "$2"; fi; }

# The shape of the reference host's unit (#139 log, #153 body): root, out
# of a uid-1000 checkout, state under data/, --no-privdrop added on
# 2026-10-21. The site identity is invented, never the real site's.
old_unit() {
    cat <<UNIT
# hand-written build-tree unit
[Unit]
Description=sloth sensor (build tree)
ConditionPathExists=/home/op/sloth/sloth

[Service]
User=root
WorkingDirectory=/home/op/sloth
ExecStartPre=/usr/local/sbin/sloth-monitor-up alfa0
ExecStart=/home/op/sloth/sloth --headless --hop \\
    --db data/sloth.db --db-interval-secs 1 --db-retain-days 30 \\
    --pcap-dir /home/op/sloth/data/pcap \\
    --data-socket unix:/run/sloth.sock --no-discovery \\
    --with-research /home/op/sloth/research.db \\
    --report data/report.md --report-json ./data/report.json \\
    --snapshot-out data/snapshot.txt --baseline-in data/snapshot.txt \\
${1:-}
    --my-ssid TestNet --my-bssid 02:00:00:00:00:01 --site-label test-sensor \\
    --no-privdrop
Restart=always

[Install]
WantedBy=multi-user.target
UNIT
}

setup() {   # setup NAME [extra ExecStart line, ending in a backslash]
    W=$SCRATCH/$1
    ROOT=$W/root STUB=$W/stub STATE=$W/state LOG=$W/log
    # Exported as well as passed, so no slip in run()'s prefix can let the
    # tool see an empty ROOT and resolve host paths.
    export ROOT
    mkdir -p "$ROOT/etc/systemd/system" "$ROOT/home/op/sloth/data/pcap" \
             "$ROOT/home/op/sloth/data/eapol" "$ROOT/usr/local/bin" \
             "$ROOT/usr/local/sbin" "$ROOT/usr/local/share/sloth" \
             "$ROOT/proc/4242" "$ROOT/run/sloth" "$ROOT/var/lib" "$STUB" "$STATE"
    : > "$LOG"
    old_unit "${2:-    \\}" > "$ROOT/etc/systemd/system/sloth-sensor.service"
    D=$ROOT/home/op/sloth/data
    # The modes the real sensor leaves (UMask=0077, secure_file.c): a
    # copy that kept anything looser would be refused at start.
    chmod 700 "$D" "$D/pcap" "$D/eapol"
    printf 'SQLite format 3\000rows' > "$D/sloth.db"
    printf 'v5 backup' > "$D/sloth.db.v5.bak"
    printf 'pcap bytes' > "$D/pcap/alert-1.pcap"
    printf 'WPA*02*...' > "$D/eapol/eapol.22000"
    printf '# report' > "$D/report.md"
    printf '{}' > "$D/report.json"
    printf 'snapshot' > "$D/snapshot.txt"
    find "$D" -type f -exec chmod 600 {} +
    printf '#!/bin/sh\n' > "$ROOT/usr/local/bin/sloth"
    printf '#!/bin/sh\n' > "$ROOT/usr/local/bin/slothweb"
    printf '#!/bin/sh\n' > "$ROOT/usr/local/sbin/sloth-monitor-up"
    chmod 755 "$ROOT/usr/local/bin/sloth" "$ROOT/usr/local/bin/slothweb" \
              "$ROOT/usr/local/sbin/sloth-monitor-up"
    printf 'research' > "$ROOT/usr/local/share/sloth/research.db"
    printf 'Name:\tsloth\nCapEff:\t0000000000001000\nNoNewPrivs:\t1\n' \
        > "$ROOT/proc/4242/status"
    chmod 750 "$ROOT/run/sloth"
    : > "$ROOT/run/sloth/sloth.sock"
    echo active > "$STATE/active"
    health_line 6 0 > "$STATE/health"
    web_health wal connected > "$STATE/web_health"

    # Knobs, each a file in \$STATE: new_dies (the hardened unit never
    # comes up), old_loops (the old unit restart-loops: a new MainPID on
    # every show), pids (MainPIDs to report in turn, the last repeated),
    # rundir (systemd's RuntimeDirectory=: stopping the hardened unit
    # removes run/sloth, starting it makes it, and the old unit fails to
    # start without it, as its bind would).
    # slothweb.service keeps its own state: web_active, web_enabled,
    # web_dies (it never comes up).
    cat > "$STUB/systemctl" <<STUBEOF
#!/bin/sh
echo "systemctl \$*" >> "$LOG"
hardened() { grep -q '^User=sloth' "$ROOT/$UNIT_REL"; }
for u; do :; done
if [ "\$u" = slothweb.service ]; then
    case "\$1" in
        is-active) [ -e "$STATE/web_active" ] ;;
        is-enabled) [ -e "$STATE/web_enabled" ] ;;
        enable|reenable) : > "$STATE/web_enabled" ;;
        disable) rm -f "$STATE/web_enabled" ;;
        stop) rm -f "$STATE/web_active" ;;
        start|restart) [ -e "$STATE/web_dies" ] || : > "$STATE/web_active" ;;
        show) echo 777 ;;
        *) exit 0 ;;
    esac
    exit
fi
case "\$1" in
    is-active) [ "\$(cat "$STATE/active")" = active ] ;;
    is-enabled) exit 0 ;;
    stop)
        [ -e "$STATE/rundir" ] && hardened && rm -rf "$ROOT/run/sloth"
        echo inactive > "$STATE/active" ;;
    start|restart)
        if [ -e "$STATE/rundir" ] && hardened; then
            mkdir -p "$ROOT/run/sloth" && : > "$ROOT/run/sloth/sloth.sock"
        fi
        if [ -e "$STATE/new_dies" ] && hardened; then echo failed
        elif [ -e "$STATE/rundir" ] && ! hardened && [ ! -d "$ROOT/run/sloth" ]; then echo failed
        else echo active; fi > "$STATE/active" ;;
    show)
        n=\$(cat "$STATE/show_calls" 2>/dev/null || echo 0)
        n=\$((n + 1)); echo \$n > "$STATE/show_calls"
        if [ -e "$STATE/old_loops" ] && ! hardened; then echo \$((5000 + n))
        elif [ -e "$STATE/pids" ]; then
            sed -n "\${n}p" "$STATE/pids" | grep . || tail -n 1 "$STATE/pids"
        else echo 4242; fi ;;
    *) exit 0 ;;
esac
STUBEOF
    cat > "$STUB/systemd-sysusers" <<STUBEOF
#!/bin/sh
echo "systemd-sysusers \$*" >> "$LOG"
: > "$STATE/user"
STUBEOF
    cat > "$STUB/getent" <<STUBEOF
#!/bin/sh
[ -e "$STATE/user" ]
STUBEOF
    cat > "$STUB/chown" <<STUBEOF
#!/bin/sh
echo "chown \$*" >> "$LOG"
STUBEOF
    # The first connect is refused, as a stale socket left by the old unit
    # would be: the tool has to reconnect, not give up.
    cat > "$STUB/socat" <<STUBEOF
#!/bin/sh
echo "socat \$*" >> "$LOG"
# The tool kills its reader at the end of a verify window; a plain
# "echo > file" killed between its truncate and its write leaves the
# counter empty (seen in CI on 2214b59), so it is written aside and
# renamed into place, which a kill cannot tear.
n=\$(cat "$STATE/socat_calls" 2>/dev/null); n=\${n:-0}
echo \$((n + 1)) > "$STATE/socat_calls.\$\$" && mv "$STATE/socat_calls.\$\$" "$STATE/socat_calls"
[ "\$n" -eq 0 ] && exit 1
echo '{"type":"heartbeat","ts":1}'
cat "$STATE/health"
# A record the sensor emits later in the run, as a retune failure would be.
[ -e "$STATE/health_late" ] && { sleep 2; cat "$STATE/health_late"; }
# Held open, as a real socat on a live socket is.
[ -e "$STATE/socat_holds" ] && exec sleep 8
exit 0
STUBEOF
    # slothweb's /api/health, as $STATE/web_health holds it; no file, no
    # answer. ss reports a listener when $STATE/ss holds one.
    cat > "$STUB/curl" <<STUBEOF
#!/bin/sh
echo "curl \$*" >> "$LOG"
[ -e "$STATE/web_active" ] && [ -f "$STATE/web_health" ] || exit 7
cat "$STATE/web_health"
STUBEOF
    cat > "$STUB/ss" <<STUBEOF
#!/bin/sh
echo "ss \$*" >> "$LOG"
[ -f "$STATE/ss" ] && cat "$STATE/ss"
exit 0
STUBEOF
    chmod 755 "$STUB"/*
}

run() {   # run [args]; output to $W/out, status in $RC
    case "$ROOT" in "$SCRATCH"/*) ;; *) echo "deploy-test: ROOT '$ROOT' is outside the scratch dir" >&2; exit 1 ;; esac
    # shellcheck disable=SC2086  # TOOL_SH may be "busybox sh": split it
    ROOT=$ROOT STAMP=${STAMP:-T1} AVAIL_KB=${AVAIL_KB:-10000000} \
    VERIFY_SECS=2 HEALTH_SECS=${HEALTH_T:-2} SETTLE_SECS=${SETTLE_T:-2} \
    ROLLBACK_SETTLE_SECS=1 TMPDIR=$W \
    SYSTEMCTL=$STUB/systemctl SYSUSERS=$STUB/systemd-sysusers \
    GETENT=$STUB/getent CHOWN=$STUB/chown SOCAT=$STUB/socat \
    CURL=$STUB/curl SS=$STUB/ss WEB_VERIFY_SECS=2 \
    CP=${CP_CMD:-cp} \
    $TOOL_SH "$TOOL" "$@" > "$W/out" 2>&1 &
    TOOL_PID=$!
    [ -n "${BG:-}" ] && return 0
    wait "$TOOL_PID"
    RC=$?
}

# One sensor_health line: chan_confirmed, chan_retune_failures and
# chan_retune_reason (default: none for 0 failures, else EPERM, what a
# missing CAP_NET_ADMIN returns). A reason of '-' leaves the field out.
health_line() {
    r=${3:-}
    [ -n "$r" ] || { [ "$2" -eq 0 ] && r=none || r=EPERM; }
    rk=",\"chan_retune_reason\":\"$r\""
    [ "$r" = - ] && rk=""
    printf '{"type":"sensor_health","ts":2,"chan_requested":6,"chan_confirmed":%s,"chan_confirmed_ok":1,"chan_retune_failures":%s%s,"hop_channels":13}\n' "$1" "$2" "$rk"
}

# One /api/health body: db_mode (wal, immutable, or null) and socket
# (connected, retrying, ...), the members step 6 reads.
web_health() {
    m="\"$1\""; [ "$1" = null ] && m=null
    db='"db":"open","db_schema":7,"db_rows":9,"db_path":"/var/lib/sloth/sloth.db"'
    [ "$1" = null ] && db='"db":"error","db_schema":null,"db_rows":null,"db_path":"/var/lib/sloth/sloth.db"'
    printf '{"service":"slothweb","milestone":"M6","uptime_s":3,"socket":"%s","socket_spec":"unix:/run/sloth/sloth.sock",%s,"db_mode":%s,"db_error":null}\n' "$2" "$db" "$m"
}

tree_hash() {
    (cd "$1" && { find . -printf '%p %y %m %s\n' | LC_ALL=C sort;
                  find . -type f -exec sha256sum {} + | LC_ALL=C sort -k2; }) \
        | sha256sum | cut -d' ' -f1
}

# The unit's ExecStart as systemd reads it: continuations joined.
logical_execstart() {
    awk '{ if (sub(/\\$/, "")) printf "%s ", $0; else print }' "$1" | grep '^ExecStart='
}

file_sums() { (cd "$1" && find . -type f -exec sha256sum {} + | LC_ALL=C sort -k2); }

mutating_calls() {
    grep -E '^(systemctl (stop|start|restart|try-restart|reload|reload-or-restart|try-reload-or-restart|kill|mask|unmask|daemon-reload|reenable|enable|disable)|systemd-sysusers|chown)' "$LOG"
}

UNIT_REL=etc/systemd/system/sloth-sensor.service
EXPECT_ARGS='SLOTH_ARGS=--db-interval-secs 1 --db-retain-days 30 --my-ssid TestNet --my-bssid 02:00:00:00:00:01 --site-label test-sensor'

# ── 1. a dry run changes nothing ─────────────────────────────────────────
CASE=dry-run
setup dry
h0=$(tree_hash "$ROOT")
run --dry-run
check '[ "$RC" -eq 0 ]' "exit $RC: $(cat "$W/out")"
check '[ "$(tree_hash "$ROOT")" = "$h0" ]' "the scratch root changed under --dry-run"
check '[ -z "$(mutating_calls)" ]' "mutating calls under --dry-run: $(mutating_calls)"
check 'grep -q "would: .*systemctl stop" "$W/out"' "stop not announced"
check 'grep -q "would: copy " "$W/out"' "copy not announced"
check 'grep -q "would: install the hardened unit" "$W/out"' "unit install not announced"
check 'grep -q "would: verify active, CapEff 0000000000001000" "$W/out"' "verify not announced"
check 'grep -q "SLOTH_ARGS:  --db-interval-secs 1 --db-retain-days 30 --my-ssid TestNet" "$W/out"' "SLOTH_ARGS not shown"

# ── 1b. keys the hardened unit replaces are named, not dropped silently ──
CASE=not-carried
setup not-carried
sed -i "s|^Restart=always|Environment=TZ=UTC\nNice=5\nExecStartPre=/bin/true\nRestart=always|" "$ROOT/$UNIT_REL"
run --dry-run
check '[ "$RC" -eq 0 ]' "exit $RC: $(cat "$W/out")"
for k in "Environment=TZ=UTC" "Nice=5" "ExecStartPre=/bin/true"; do
    K=$k
    check 'grep -qF "note: not carried (the hardened unit has its own): $K" "$W/out"' "$K not named as dropped: $(cat "$W/out")"
done
check '! grep -q "not carried.*sloth-monitor-up" "$W/out"' "the monitor-up ExecStartPre was listed as dropped"

# ── 1c. a carried --iface list that includes the bound radio is kept ─────
CASE=iface-carried
setup iface-carried '    --iface eth0 --iface alfa0 \'
run
check '[ "$RC" -eq 0 ]' "exit $RC: $(cat "$W/out")"
check 'grep -q "^SLOTH_ARGS=.*--iface eth0 --iface alfa0" "$ROOT/etc/default/sloth"' "--iface not carried: $(grep SLOTH_ARGS= "$ROOT/etc/default/sloth" 2>&1)"

# ── 1d. --bt-monitor is carried, not refused ─────────────────────────────
# The hardened unit lists AF_BLUETOOTH for it; before that it was an
# unknown flag and the migration refused the whole unit.
CASE=bt-monitor-carried
setup bt-monitor-carried '    --bt-monitor \'
run
check '[ "$RC" -eq 0 ]' "exit $RC: $(cat "$W/out")"
check 'grep -q "^SLOTH_ARGS=.*--bt-monitor" "$ROOT/etc/default/sloth"' "--bt-monitor not carried: $(grep SLOTH_ARGS= "$ROOT/etc/default/sloth" 2>&1)"

# ── 2. apply: flag carry-over, copy, unit, verify ────────────────────────
CASE=apply
setup apply
# Left by an older build or a hand copy: the copy must not keep them.
chmod 644 "$ROOT/home/op/sloth/data/report.md"
chmod 755 "$ROOT/home/op/sloth/data/pcap"
src_h=$(tree_hash "$ROOT/home/op/sloth/data")
cp "$ROOT/$UNIT_REL" "$W/old.unit"
run
check '[ "$RC" -eq 0 ]' "exit $RC: $(cat "$W/out")"
check 'grep -qx -- "$EXPECT_ARGS" "$ROOT/etc/default/sloth"' "SLOTH_ARGS line: $(grep SLOTH_ARGS= "$ROOT/etc/default/sloth" 2>&1)"
check '[ "$(grep -c "^SLOTH_ARGS=" "$ROOT/etc/default/sloth")" -eq 1 ]' "SLOTH_ARGS appears more than once"
check 'grep -qx "SLOTH_IFACE=alfa0" "$ROOT/etc/default/sloth"' "SLOTH_IFACE missing"
check '! grep -q -- "--no-privdrop" "$ROOT/etc/default/sloth"' "--no-privdrop carried into the defaults"
check '! grep -q -- "/home/" "$ROOT/etc/default/sloth"' "a /home path was carried into the defaults"
check 'cmp -s "$REPO/packaging/systemd/sloth-sensor.service" "$ROOT/$UNIT_REL"' "installed unit differs from packaging/"
check 'cmp -s "$W/old.unit" "$ROOT/$UNIT_REL.bak-migrate-T1"' "old unit not backed up"
check '[ "$(tree_hash "$ROOT/home/op/sloth/data")" = "$src_h" ]' "the source data dir was modified"
check '[ "$(file_sums "$ROOT/home/op/sloth/data")" = "$(file_sums "$ROOT/var/lib/sloth")" ]' "copy differs from source"
check '[ "$(file_sums "$ROOT/var/lib/sloth" | grep -c .)" -eq 7 ]' "copy is missing files"
check '[ "$(stat -c %a "$ROOT/var/lib/sloth")" = 700 ]' "target is not 0700"
check '[ -z "$(find "$ROOT/var/lib/sloth" -perm /077)" ]' "the copy kept group/other bits: $(find "$ROOT/var/lib/sloth" -perm /077 -printf '%m %p ')"
check '[ "$(find "$ROOT/var/lib/sloth" -type f ! -perm 600 | grep -c .)" -eq 0 ]' "a copied file is not 0600"
check '[ "$(find "$ROOT/var/lib/sloth" -type d ! -perm 700 | grep -c .)" -eq 0 ]' "a copied dir is not 0700"
check '[ "$(stat -c %a "$ROOT/home/op/sloth/data/report.md")" = 644 ]' "the source's modes were changed"
check 'grep -q "note: 2 entries under /home/op/sloth/data have group/other bits" "$W/out"' "loose modes not noted: $(cat "$W/out")"
check 'grep -qx "chown -R sloth:sloth $ROOT/var/lib/sloth" "$LOG"' "no chown -R sloth:sloth"
check 'cmp -s "$REPO/packaging/systemd/sloth.sysusers.conf" "$ROOT/usr/lib/sysusers.d/sloth.conf"' "sysusers fragment not installed"
check 'grep -q "^systemd-sysusers " "$LOG"' "systemd-sysusers not run"
# Stopped before the copy, switched before the start.
order=$(grep -E "^systemctl (stop|daemon-reload|start)" "$LOG" | tr '\n' ,)
check '[ "$order" = "systemctl stop sloth-sensor.service,systemctl daemon-reload,systemctl start sloth-sensor.service," ]' "unexpected order: $order"
check '[ "$(cat "$STATE/active")" = active ]' "service not active after apply"
check 'grep -q "note: the data socket moves from /run/sloth.sock" "$W/out"' "socket relocation not noted"
check 'grep -q "verify: [0-9]* sensor_health records over 2s, chan_retune_failures 0 in every one" "$W/out"' "health not verified: $(cat "$W/out")"
check '[ "$(cat "$STATE/socat_calls")" -ge 2 ]' "the reader did not reconnect after a refused connect"

# ── 3. a second run is idempotent ────────────────────────────────────────
CASE=idempotent
h1=$(tree_hash "$ROOT")
: > "$LOG"
STAMP=T2 run
check '[ "$RC" -eq 0 ]' "exit $RC: $(cat "$W/out")"
check 'grep -q "already the hardened unit; verifying only" "$W/out"' "second run did not detect the migration"
check 'grep -q "already migrated and verified" "$W/out"' "second run did not verify"
check '[ "$(tree_hash "$ROOT")" = "$h1" ]' "second run changed the scratch root"
check '[ -z "$(mutating_calls)" ]' "second run made mutating calls: $(mutating_calls)"
# A dry run on a migrated host must not touch the live sensor either.
: > "$LOG"
STAMP=T3 run --dry-run
check '[ "$RC" -eq 0 ] && [ "$(tree_hash "$ROOT")" = "$h1" ]' "dry run after migration changed something"
check '[ -z "$(mutating_calls)" ]' "dry run after migration made mutating calls: $(mutating_calls)"

# ── 4. refusals change nothing ───────────────────────────────────────────
refusal() {   # refusal NAME EXPECTED-FRAGMENT [extra ExecStart line]
    CASE=refuse-$1
    setup "refuse-$1" "${3:-    \\}"
    [ -n "${PREP:-}" ] && eval "$PREP"
    h=$(tree_hash "$ROOT")
    run
    check '[ "$RC" -eq 2 ]' "exit $RC, want 2: $(cat "$W/out")"
    # Not "$2" inside the eval: that is check()'s own $2, the failure
    # text, which embeds the whole output and so always matched.
    WANT=$2
    check 'grep -qF -- "$WANT" "$W/out"' "message lacks '$WANT': $(cat "$W/out")"
    check '[ "$(tree_hash "$ROOT")" = "$h" ]' "a refusal changed the scratch root"
    check '[ -z "$(mutating_calls)" ]' "a refusal made mutating calls: $(mutating_calls)"
}
refusal unknown-flag "flag '--frobnicate'"           '    --frobnicate 7 \'
refusal jsonl-out    "flag '-o'"                     '    -o /home/op/sloth/data/out.jsonl \'
refusal tcp-socket   "--data-socket tcp:127.0.0.1:9" '    --data-socket tcp:127.0.0.1:9 \'
refusal quoted       "has quoting"                   '    --site-label "attic sensor" \'
refusal db-name      "--db /home/op/sloth/data/other.db" '    --db data/other.db \'
refusal dotdot       "contains '..'"                 '    --pcap-dir data/../data/pcap \'
refusal eapol        "flag '--eapol-dir'"            '    --eapol-dir data/eapol --collect-handshakes \'
AVAIL_KB=1 refusal low-space "KiB free"
PREP='mkdir -p "$ROOT/var/lib/sloth" && echo x > "$ROOT/var/lib/sloth/stale"'
refusal target-busy "already has contents"
PREP='rm "$ROOT/usr/local/share/sloth/research.db"'
refusal no-install "sudo make install"
PREP='mkdir -p "$ROOT/$UNIT_REL.d" && echo "[Service]" > "$ROOT/$UNIT_REL.d/x.conf"'
refusal drop-in "drop-ins"
PREP='sed -i "s|^Restart=always|ExecStart=/home/op/sloth/sloth --headless\nRestart=always|" "$ROOT/$UNIT_REL"'
refusal two-execstart "expected exactly one ExecStart= in"
PREP='sed -i "s|^ExecStart=/home/op/sloth/sloth |ExecStart=/usr/bin/python3 |" "$ROOT/$UNIT_REL"'
refusal not-sloth "runs '/usr/bin/python3', not a sloth binary"
PREP='ln -s sloth.db "$ROOT/home/op/sloth/data/sloth-link.db"'
refusal data-symlink "sloth-link.db is not a regular file or directory"
PREP='mkdir "$ROOT/elsewhere" && ln -s ../../elsewhere "$ROOT/var/lib/sloth"'
refusal target-symlink "/var/lib/sloth is a symlink"
PREP='mv "$ROOT/var/lib" "$ROOT/var/lib.real" && ln -s lib.real "$ROOT/var/lib"'
refusal target-parent-symlink "/var/lib is a symlink"
# `make install-service` before the tool: the unit is byte-identical to
# the hardened one, but nothing was copied. Re-verifying would pass on an
# empty /var/lib/sloth and call the evidence migrated.
PREP='cp "$REPO/packaging/systemd/sloth-sensor.service" "$ROOT/$UNIT_REL"'
refusal install-service-first "so the data was never copied to /var/lib/sloth"
# A backup but no copied db (an interrupted hand migration).
PREP='cp "$ROOT/$UNIT_REL" "$ROOT/$UNIT_REL.bak-migrate-T0" && cp "$REPO/packaging/systemd/sloth-sensor.service" "$ROOT/$UNIT_REL"'
refusal backup-no-db "used --db data/sloth.db (WorkingDirectory /home/op/sloth)"
# The monitor radio has to be the one the hardened unit binds to.
PREP='sed -i "s|sloth-monitor-up alfa0|sloth-monitor-up wlan1|" "$ROOT/$UNIT_REL"'
refusal other-radio "puts 'wlan1' into monitor mode, but the hardened unit binds to alfa0"
PREP='sed -i "s|sloth-monitor-up alfa0|sloth-monitor-up \${SLOTH_IFACE}|" "$ROOT/$UNIT_REL"'
refusal radio-variable "not a plain interface name"
PREP=''
MON_IFACE=wlan1 refusal mon-iface-override "MON_IFACE=wlan1, but the hardened unit binds to alfa0"
refusal iface-list "--iface list ( eth0 ) does not include alfa0" '    --iface eth0 \'
PREP='sed -i "s|^Restart=always|ExecStartPre=/usr/local/sbin/sloth-monitor-up wlan1\nRestart=always|" "$ROOT/$UNIT_REL"'
refusal second-radio "puts 'wlan1' into monitor mode"
PREP='sed -i "s|unix:/run/sloth.sock|unix:/run/sloth/sub/s.sock|" "$ROOT/$UNIT_REL"'
refusal socket-below-rundir "is below /run/sloth, which the hardened unit's RuntimeDirectory= removes"
PREP=''

# ── 5. the copy is verified before the switch ────────────────────────────
# A cp that corrupts one byte of the copy: the tool must notice by
# checksum, never install the hardened unit, and restart the old one.
CASE=copy-verify
setup copy
cat > "$STUB/cp" <<'STUBEOF'
#!/bin/sh
cp "$@" || exit 1
for last; do :; done
printf 'X' >> "$last/snapshot.txt"
STUBEOF
chmod 755 "$STUB/cp"
cp "$ROOT/$UNIT_REL" "$W/old.unit"
src_h=$(tree_hash "$ROOT/home/op/sloth/data")
CP_CMD=$STUB/cp run
check '[ "$RC" -eq 1 ]' "exit $RC, want 1: $(cat "$W/out")"
check 'grep -q "does not match .* by checksum" "$W/out"' "mismatch not reported: $(cat "$W/out")"
check '! grep -q "^+ install the hardened unit" "$W/out"' "the unit was switched after a bad copy"
check '! grep -q "^+ write " "$W/out"' "the defaults were written after a bad copy"
check 'cmp -s "$W/old.unit" "$ROOT/$UNIT_REL"' "the old unit is not in place"
check '[ ! -e "$ROOT/etc/default/sloth" ]' "a defaults file was left where there was none"
check '[ ! -e "$ROOT/var/lib/sloth" ] && [ -d "$ROOT/var/lib/sloth.rolled-back-T1" ]' "the bad copy was not set aside"
check '[ "$(tree_hash "$ROOT/home/op/sloth/data")" = "$src_h" ]' "the source data dir was modified"
check '[ "$(cat "$STATE/active")" = active ]' "the old service was not restarted"

# ── 6. a failed verify rolls back ────────────────────────────────────────
CASE=rollback
setup rollback
mkdir -p "$ROOT/etc/default"
printf 'ORIGINAL defaults\n' > "$ROOT/etc/default/sloth"
health_line 6 3 > "$STATE/health"
cp "$ROOT/$UNIT_REL" "$W/old.unit"
src_h=$(tree_hash "$ROOT/home/op/sloth/data")
run
check '[ "$RC" -eq 1 ]' "exit $RC, want 1: $(cat "$W/out")"
check 'grep -q "chan_retune_failures is .3." "$W/out"' "the verify failure is not named: $(cat "$W/out")"
check 'cmp -s "$W/old.unit" "$ROOT/$UNIT_REL"' "the hardened unit was left installed"
check '[ "$(cat "$ROOT/etc/default/sloth")" = "ORIGINAL defaults" ]' "the migrated defaults were left in place"
check '[ ! -e "$ROOT/var/lib/sloth" ] && [ -d "$ROOT/var/lib/sloth.rolled-back-T1" ]' "the copy was not set aside"
check '[ "$(tree_hash "$ROOT/home/op/sloth/data")" = "$src_h" ]' "the source data dir was modified"
check '[ "$(cat "$STATE/active")" = active ]' "the old service was not restarted"
last_start=$(grep -n "^systemctl start" "$LOG" | tail -n 1 | cut -d: -f1)
last_reload=$(grep -n "^systemctl daemon-reload" "$LOG" | tail -n 1 | cut -d: -f1)
check '[ -n "$last_start" ] && [ -n "$last_reload" ] && [ "$last_start" -gt "$last_reload" ]' "the old unit was not reloaded before its restart: $(tr '\n' , < "$LOG")"
check 'grep -q "rolled back; sloth-sensor.service runs the previous unit" "$W/out"' "rollback not reported: $(cat "$W/out")"
last_reenable=$(grep -n "^systemctl reenable" "$LOG" | tail -n 1 | cut -d: -f1)
check '[ -n "$last_reenable" ] && [ "$last_reenable" -gt "$last_reload" ]' "the old unit was not re-enabled after its restore: $(tr '\n' , < "$LOG")"
check '[ ! -e "$ROOT/$UNIT_REL.bak-migrate-T1" ] && cmp -s "$W/old.unit" "$ROOT/$UNIT_REL.rolled-back-T1"' "the restored backup still reads as a migration"

# ── 7. a rerun after the rollback succeeds ───────────────────────────────
CASE=rerun-after-rollback
health_line 6 0 > "$STATE/health"
STAMP=T4 run
check '[ "$RC" -eq 0 ]' "exit $RC: $(cat "$W/out")"
check 'cmp -s "$REPO/packaging/systemd/sloth-sensor.service" "$ROOT/$UNIT_REL"' "unit not installed on rerun"
check 'cmp -s "$W/old.unit" "$ROOT/$UNIT_REL.bak-migrate-T4"' "rerun backed up the wrong unit"
check 'grep -qx "SLOTH_ARGS=.*" "$ROOT/etc/default/sloth" && grep -q "^# Written by sloth-migrate-sensor" "$ROOT/etc/default/sloth"' "rerun did not write the defaults"
check 'cmp -s "$ROOT/etc/default/sloth.bak-migrate-T4" /dev/stdin <<X
ORIGINAL defaults
X' "rerun did not back up the original defaults"

# ── 8. each verify check can fail, and each failure rolls back ───────────
# No prior /etc/default/sloth here, the reference host's likely state: the
# rollback must remove the one it wrote, not leave it.
verify_fails() {   # verify_fails NAME EXPECTED-FRAGMENT (PREP sets it up)
    CASE=verify-$1
    setup "verify-$1"
    eval "$PREP"
    cp "$ROOT/$UNIT_REL" "$W/old.unit"
    src_h=$(tree_hash "$ROOT/home/op/sloth/data")
    SETTLE_T=${SETTLE_FOR:-2} run
    check '[ "$RC" -eq 1 ]' "exit $RC, want 1: $(cat "$W/out")"
    # Not "$2" inside the eval: that is check()'s own $2, the failure
    # text, which embeds the whole output and so always matched.
    WANT=$2
    check 'grep -qF -- "$WANT" "$W/out"' "message lacks '$WANT': $(cat "$W/out")"
    check 'cmp -s "$W/old.unit" "$ROOT/$UNIT_REL"' "the hardened unit was left installed"
    check '[ ! -e "$ROOT/etc/default/sloth" ]' "a defaults file was left where there was none"
    check '[ ! -e "$ROOT/var/lib/sloth" ] && [ -d "$ROOT/var/lib/sloth.rolled-back-T1" ]' "the copy was not set aside"
    check '[ "$(tree_hash "$ROOT/home/op/sloth/data")" = "$src_h" ]' "the source data dir was modified"
    check '[ "$(cat "$STATE/active")" = active ]' "the old service was not restarted"
    check 'grep -q "rolled back; sloth-sensor.service runs the previous unit" "$W/out"' "rollback not reported: $(cat "$W/out")"
}
PREP='printf "Name:\tsloth\nCapEff:\t0000000000003000\nNoNewPrivs:\t1\n" > "$ROOT/proc/4242/status"'
verify_fails capeff "CapEff '0000000000003000' (want 0000000000001000)"
PREP='printf "Name:\tsloth\nCapEff:\t0000000000001000\nNoNewPrivs:\t0\n" > "$ROOT/proc/4242/status"'
verify_fails nnp "NoNewPrivs '0' (want 1)"
PREP='printf "4242\n4343\n" > "$STATE/pids"'
verify_fails restarted "restarted during verification (pid 4242 -> 4343)"
PREP=': > "$STATE/new_dies"'
verify_fails never-active "sloth-sensor.service is not active after 2s"
# The first record is the one a connect emits, before any retune; the
# EPERM a missing CAP_NET_ADMIN causes shows only in a later one, here
# 2 s after it, inside a 5 s window.
PREP='health_line 0 0 > "$STATE/health" && health_line 0 5 > "$STATE/health_late"'
SETTLE_FOR=5 verify_fails retune-later "chan_retune_failures is '5', chan_retune_reason 'EPERM'"
PREP='health_line 6 2 EACCES > "$STATE/health"'
verify_fails eacces "chan_retune_reason 'EACCES'"
# A binary that does not say why cannot be told apart from EPERM.
PREP='health_line 6 2 - > "$STATE/health"'
verify_fails no-reason "chan_retune_reason 'absent'"
# EINVAL first, EPERM later: the privilege refusal still fails it.
PREP='health_line 6 1 EINVAL > "$STATE/health" && health_line 6 9 EPERM > "$STATE/health_late"'
SETTLE_FOR=5 verify_fails eperm-after-einval "chan_retune_reason 'EPERM'"
PREP='health_line 0 0 > "$STATE/health"'
verify_fails never-confirmed "showed a confirmed channel"
PREP=''

# ── 8b. a channel the regdomain refuses is not a hardening failure ───────
# EINVAL on a hop-list channel happens under the root unit too
# (src/jsonl.c, #91); failing on it would roll back a healthy sensor on
# every attempt.
CASE=einval-passes
setup einval-passes
health_line 6 4 EINVAL > "$STATE/health"
run
check '[ "$RC" -eq 0 ]' "exit $RC: $(cat "$W/out")"
check 'grep -q "no privilege refusal (EPERM/EACCES)" "$W/out"' "verify did not pass on EINVAL: $(cat "$W/out")"
check 'grep -q "refused some hop channels with EINVAL" "$W/out"' "the EINVAL refusals were not reported: $(cat "$W/out")"
check 'cmp -s "$REPO/packaging/systemd/sloth-sensor.service" "$ROOT/$UNIT_REL"' "the hardened unit is not installed"

# ── 8c. a rollback recreates the old socket's /run/sloth ─────────────────
# The hardened unit's RuntimeDirectory=sloth removes /run/sloth on stop,
# and an old unit whose socket is there cannot bind without it.
CASE=rollback-rundir
setup rollback-rundir
sed -i "s|unix:/run/sloth.sock|unix:/run/sloth/sloth.sock|" "$ROOT/$UNIT_REL"
: > "$STATE/rundir"
printf 'Name:\tsloth\nCapEff:\t0000000000003000\nNoNewPrivs:\t1\n' > "$ROOT/proc/4242/status"
cp "$ROOT/$UNIT_REL" "$W/old.unit"
run
check '[ "$RC" -eq 1 ]' "exit $RC, want 1: $(cat "$W/out")"
check 'grep -q "rolled back; sloth-sensor.service runs the previous unit" "$W/out"' "rollback not reported: $(cat "$W/out")"
check '[ "$(cat "$STATE/active")" = active ]' "the old service did not come back"
check '[ -d "$ROOT/run/sloth" ] && [ "$(stat -c %a "$ROOT/run/sloth")" = 750 ]' "run/sloth not recreated 0750: $(stat -c %a "$ROOT/run/sloth" 2>&1)"
check 'cmp -s "$W/old.unit" "$ROOT/$UNIT_REL"' "the hardened unit was left installed"

# ── 9. a rollback whose old unit will not stay up says so ────────────────
CASE=rollback-unstable
setup rollback-unstable
printf 'Name:\tsloth\nCapEff:\t0000000000003000\nNoNewPrivs:\t1\n' > "$ROOT/proc/4242/status"
: > "$STATE/old_loops"
run
check '[ "$RC" -eq 1 ]' "exit $RC, want 1: $(cat "$W/out")"
check 'grep -q "the previous unit did not stay up for 1s" "$W/out"' "the restart loop was not noticed: $(cat "$W/out")"
check 'grep -q "ROLLBACK INCOMPLETE" "$W/out"' "an unstable old unit was reported as rolled back: $(cat "$W/out")"
check '! grep -q "rolled back; sloth-sensor.service runs" "$W/out"' "success claimed for an unstable rollback"

# ── 10. a signal mid-verify rolls back ───────────────────────────────────
# A dropped SSH session HUPs the tool while it waits for sensor_health.
CASE=signal
setup signal
mkdir -p "$ROOT/etc/default"
printf 'ORIGINAL defaults\n' > "$ROOT/etc/default/sloth"
: > "$STATE/health"
: > "$STATE/socat_holds"
cp "$ROOT/$UNIT_REL" "$W/old.unit"
src_h=$(tree_hash "$ROOT/home/op/sloth/data")
BG=1 HEALTH_T=60 run
i=0
until grep -q "^sloth-migrate-sensor: verify: pid" "$W/out" 2>/dev/null; do
    i=$((i + 1)); [ "$i" -le 100 ] || break
    sleep 0.2
done
kill -HUP "$TOOL_PID"
# The rest of a dropped session: a second HUP while the rollback runs
# must not start it again or cut it short.
i=0
until grep -q "rolling back" "$W/out" 2>/dev/null; do
    i=$((i + 1)); [ "$i" -le 50 ] || break
    sleep 0.1
done
kill -HUP "$TOOL_PID" 2>/dev/null
wait "$TOOL_PID"
RC=$?
check '[ "$RC" -eq 1 ]' "exit $RC, want 1: $(cat "$W/out")"
check 'grep -q "FAILED: interrupted by signal" "$W/out"' "the signal was not handled: $(cat "$W/out")"
check '[ "$(grep -c "rolling back" "$W/out")" -eq 1 ]' "rollback did not run exactly once: $(cat "$W/out")"
check 'cmp -s "$W/old.unit" "$ROOT/$UNIT_REL"' "the hardened unit was left installed"
check '[ "$(cat "$ROOT/etc/default/sloth")" = "ORIGINAL defaults" ]' "the migrated defaults were left in place"
check '[ ! -e "$ROOT/var/lib/sloth" ] && [ -d "$ROOT/var/lib/sloth.rolled-back-T1" ]' "the copy was not set aside"
check '[ "$(tree_hash "$ROOT/home/op/sloth/data")" = "$src_h" ]' "the source data dir was modified"
check '[ "$(cat "$STATE/active")" = active ]' "the old service was not restarted"
sleep 1
# By open file, not by name: the reader and its socat hold this case's
# health file, and a name match also finds a reader some earlier run
# left behind (a mutation that drops stop_health_reader does).
holders() {
    for p in /proc/[0-9]*; do
        for fd in "$p"/fd/*; do
            case "$(readlink "$fd" 2>/dev/null)" in
                "$W/"*) echo "${p#/proc/} $(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)"; break ;;
            esac
        done
    done
}
check '[ -z "$(holders)" ]' "the socket reader outlived the tool: $(holders)"

# ── 11. --data-socket-unix: the owner's tcp: -> unix: move (#153) ────────
# The reference host streams on tcp:127.0.0.1:8765 for slothweb. Without
# the flag that stays a refusal, word for word (the refusal cases above,
# and this one on the real spec); with it the hardened unit's unix socket
# replaces it and a rollback brings the tcp: unit back byte for byte.
TCP_PREP='sed -i "s|--data-socket unix:/run/sloth.sock --no-discovery|--data-socket tcp:127.0.0.1:8765 --no-discovery|" "$ROOT/$UNIT_REL"'
PREP=$TCP_PREP
refusal tcp-live-spec "REFUSED: --data-socket tcp:127.0.0.1:8765: the hardened unit allows AF_UNIX only (RestrictAddressFamilies); a tcp: socket is an owner decision, not a migration"
PREP=''

CASE=tcp-dry-run
setup tcp-dry
eval "$TCP_PREP"
h0=$(tree_hash "$ROOT")
run --dry-run --data-socket-unix
check '[ "$RC" -eq 0 ]' "exit $RC: $(cat "$W/out")"
check '[ "$(tree_hash "$ROOT")" = "$h0" ]' "the scratch root changed under --dry-run --data-socket-unix"
check '[ -z "$(mutating_calls)" ]' "mutating calls under --dry-run: $(mutating_calls)"
check 'grep -qF "data socket: --data-socket tcp:127.0.0.1:8765 becomes --data-socket unix:/run/sloth/sloth.sock --no-discovery (--data-socket-unix)" "$W/out"' "the conversion is not printed: $(cat "$W/out")"
check 'grep -qF "socket:      tcp:127.0.0.1:8765 -> unix:/run/sloth/sloth.sock" "$W/out"' "the preflight summary lacks the socket move: $(cat "$W/out")"

CASE=tcp-convert
setup tcp-convert
eval "$TCP_PREP"
cp "$ROOT/$UNIT_REL" "$W/old.unit"
run --data-socket-unix
check '[ "$RC" -eq 0 ]' "exit $RC: $(cat "$W/out")"
check 'cmp -s "$REPO/packaging/systemd/sloth-sensor.service" "$ROOT/$UNIT_REL"' "installed unit differs from packaging/"
check 'logical_execstart "$ROOT/$UNIT_REL" | grep -qF -- "--data-socket unix:/run/sloth/sloth.sock --no-discovery"' "the hardened ExecStart lacks the unix socket and --no-discovery"
check '! logical_execstart "$ROOT/$UNIT_REL" | grep -q "tcp:" && ! grep -v "^#" "$ROOT/etc/default/sloth" | grep -q "tcp:"' "a tcp: spec was carried: $(grep -v "^#" "$ROOT/etc/default/sloth" | grep "tcp:")"
check 'grep -qx -- "$EXPECT_ARGS" "$ROOT/etc/default/sloth"' "SLOTH_ARGS line: $(grep SLOTH_ARGS= "$ROOT/etc/default/sloth" 2>&1)"
check 'cmp -s "$W/old.unit" "$ROOT/$UNIT_REL.bak-migrate-T1"' "the tcp: unit was not backed up verbatim"
# Verified on the new unix socket, as the invoking user, never on tcp:.
check 'grep -qx "socat -u UNIX-CONNECT:$ROOT/run/sloth/sloth.sock STDOUT" "$LOG"' "verify did not read the unix socket: $(grep ^socat "$LOG")"
check '! grep -q "^socat .*TCP" "$LOG"' "verify read a tcp: socket: $(grep ^socat "$LOG")"
check 'grep -q "verify: [0-9]* sensor_health records over 2s" "$W/out"' "health not verified: $(cat "$W/out")"
check 'grep -qF "must become --socket unix:/run/sloth/sloth.sock and run as sloth or root" "$W/out"' "the reader move is not said: $(cat "$W/out")"

CASE=tcp-idempotent
h1=$(tree_hash "$ROOT")
: > "$LOG"
STAMP=T2 run --data-socket-unix
check '[ "$RC" -eq 0 ]' "exit $RC: $(cat "$W/out")"
check 'grep -q "already migrated and verified" "$W/out"' "second run did not verify: $(cat "$W/out")"
check '[ "$(tree_hash "$ROOT")" = "$h1" ]' "second run changed the scratch root"
check '[ -z "$(mutating_calls)" ]' "second run made mutating calls: $(mutating_calls)"

CASE=tcp-rollback
setup tcp-rollback
eval "$TCP_PREP"
health_line 6 3 > "$STATE/health"
cp "$ROOT/$UNIT_REL" "$W/old.unit"
run --data-socket-unix
check '[ "$RC" -eq 1 ]' "exit $RC, want 1: $(cat "$W/out")"
check 'cmp -s "$W/old.unit" "$ROOT/$UNIT_REL"' "the tcp: unit was not restored verbatim"
check 'grep -qF -- "--data-socket tcp:127.0.0.1:8765" "$ROOT/$UNIT_REL"' "the restored unit lost its tcp: socket"
check '[ ! -e "$ROOT/etc/default/sloth" ]' "a defaults file was left where there was none"
check '[ "$(cat "$STATE/active")" = active ]' "the old service was not restarted"
check 'grep -q "rolled back; sloth-sensor.service runs the previous unit" "$W/out"' "rollback not reported: $(cat "$W/out")"

# ── 12. --with-slothweb (#153 part B) ────────────────────────────────────
WEB_REL=etc/systemd/system/slothweb.service
web_calls() { grep -E '^systemctl [a-z-]+ .*slothweb\.service' "$LOG"; }
sensor_after_verify() {   # sensor unit calls after its verify passed
    awk '/^systemctl show -p MainPID/ { seen = 1 } seen' "$LOG" \
        | grep -E '^systemctl (stop|start|restart|daemon-reload|reenable|enable|disable) sloth-sensor\.service'
}

CASE=web-dry-run
setup web-dry
eval "$TCP_PREP"
# An old slothweb running, so a health request the dry run made would
# be answered and logged; with none running it would never reach curl
# and the check below would pass for nothing.
mkdir -p "$ROOT/etc/systemd/system"
printf '[Service]\nExecStart=/opt/old/slothweb\n' > "$ROOT/$WEB_REL"
: > "$STATE/web_active"; : > "$STATE/web_enabled"
h0=$(tree_hash "$ROOT")
run --dry-run --data-socket-unix --with-slothweb
check '[ "$RC" -eq 0 ]' "exit $RC: $(cat "$W/out")"
check '[ "$(tree_hash "$ROOT")" = "$h0" ]' "the scratch root changed under --dry-run --with-slothweb"
check '[ -z "$(mutating_calls)" ]' "mutating calls under --dry-run: $(mutating_calls)"
check 'grep -q "would: install the slothweb unit at $ROOT/$WEB_REL" "$W/out"' "slothweb install not announced: $(cat "$W/out")"
check 'grep -q "would: install $ROOT/etc/default/slothweb from" "$W/out"' "slothweb defaults not announced"
check 'grep -qF "would: verify slothweb.service active and http://127.0.0.1:8770/api/health (asked from 127.0.0.1)" "$W/out"' "slothweb verify not announced: $(cat "$W/out")"
check '! grep -q "^curl" "$LOG"' "a dry run asked slothweb"

CASE=web-apply
setup web-apply
eval "$TCP_PREP"
run --data-socket-unix --with-slothweb
check '[ "$RC" -eq 0 ]' "exit $RC: $(cat "$W/out")"
check 'cmp -s "$REPO/packaging/systemd/sloth-sensor.service" "$ROOT/$UNIT_REL"' "the sensor unit is not the hardened one"
check 'cmp -s "$REPO/packaging/systemd/slothweb.service" "$ROOT/$WEB_REL"' "installed slothweb unit differs from packaging/"
check 'cmp -s "$REPO/packaging/default/slothweb" "$ROOT/etc/default/slothweb"' "slothweb defaults not installed from packaging/"
check '[ -e "$STATE/web_active" ] && [ -e "$STATE/web_enabled" ]' "slothweb not enabled and active"
check 'grep -qx "curl -fsS --max-time 5 --interface 127.0.0.1 http://127.0.0.1:8770/api/health" "$LOG"' "health not asked on the loopback bind: $(grep ^curl "$LOG")"
check 'grep -q "slothweb: slothweb.service runs as sloth; http://127.0.0.1:8770/api/health answers, sloth.db wal, stream connected" "$W/out"' "slothweb not verified: $(cat "$W/out")"
# The sensor first: slothweb is touched only after the sensor verified.
first_web=$(grep -n "slothweb.service" "$LOG" | grep -v "is-active\|is-enabled" | head -n 1 | cut -d: -f1)
sensor_start=$(grep -n "^systemctl start sloth-sensor.service" "$LOG" | tail -n 1 | cut -d: -f1)
check '[ -n "$first_web" ] && [ -n "$sensor_start" ] && [ "$first_web" -gt "$sensor_start" ]' "slothweb changed before the sensor started: $(tr '\n' , < "$LOG")"

CASE=web-idempotent
h1=$(tree_hash "$ROOT")
: > "$LOG"
STAMP=T2 run --data-socket-unix --with-slothweb
check '[ "$RC" -eq 0 ]' "exit $RC: $(cat "$W/out")"
check 'grep -q "already the hardened slothweb unit, enabled and active; verifying only" "$W/out"' "second run did not detect slothweb: $(cat "$W/out")"
check 'grep -q "slothweb: verified: " "$W/out"' "second run did not verify slothweb: $(cat "$W/out")"
check '[ "$(tree_hash "$ROOT")" = "$h1" ]' "second run changed the scratch root"
check '[ -z "$(mutating_calls)" ]' "second run made mutating calls: $(mutating_calls)"

# A failed slothweb is rolled back alone: its unit and the defaults this
# run wrote go, it is left disabled and stopped as it was, and the
# sensor, verified already, is neither stopped nor restarted.
web_fails() {   # web_fails NAME EXPECTED-FRAGMENT (PREP sets it up)
    CASE=web-fails-$1
    setup "web-fails-$1"
    eval "$PREP"
    run --with-slothweb
    check '[ "$RC" -eq 3 ]' "exit $RC, want 3: $(cat "$W/out")"
    WANT=$2
    check 'grep -qF -- "$WANT" "$W/out"' "message lacks '$WANT': $(cat "$W/out")"
    check 'grep -q "rolling back slothweb only; sloth-sensor.service stays migrated and verified" "$W/out"' "not a slothweb-only rollback: $(cat "$W/out")"
    check 'cmp -s "$REPO/packaging/systemd/sloth-sensor.service" "$ROOT/$UNIT_REL"' "the sensor's hardened unit was rolled back too"
    check '[ "$(cat "$STATE/active")" = active ]' "the sensor is not running"
    check '[ -z "$(sensor_after_verify)" ]' "the sensor was touched after it verified: $(sensor_after_verify)"
    check '[ ! -e "$ROOT/$WEB_REL" ]' "a slothweb unit was left where there was none"
    check '[ ! -e "$ROOT/etc/default/slothweb" ]' "a slothweb defaults file was left where there was none"
    check '[ ! -e "$STATE/web_active" ] && [ ! -e "$STATE/web_enabled" ]' "slothweb left enabled or running"
    check 'grep -q "slothweb rolled back to its state before this run" "$W/out"' "slothweb rollback not reported: $(cat "$W/out")"
}
PREP='web_health null connected > "$STATE/web_health"'
web_fails db-not-open "sloth.db is not open (db \"error\""
PREP='web_health wal retrying > "$STATE/web_health"'
web_fails stream-down "the stream is not connected (socket \"retrying\""
PREP='web_health rollback connected > "$STATE/web_health"'
web_fails db-mode "db_mode \"rollback\", not wal or immutable"
PREP=': > "$STATE/web_dies"'
web_fails never-active "slothweb.service is not active after 2s"
PREP='rm "$STATE/web_health"'
web_fails no-answer "http://127.0.0.1:8770/api/health after 2s: no answer"
PREP=''

# An operator's slothweb unit and defaults are put back, and the defaults
# are never replaced, in success or failure. The Tailscale bind is asked
# on its own address, from loopback.
CASE=web-keeps-defaults
setup web-keeps
mkdir -p "$ROOT/etc/default"
printf 'SLOTHWEB_ARGS=--web-bind 100.64.0.10:8770 --web-allow-remote --web-allow 100.64.0.20/32\n' > "$ROOT/etc/default/slothweb"
printf '[Service]\nExecStart=/opt/old/slothweb\n' > "$ROOT/$WEB_REL"
cp "$ROOT/etc/default/slothweb" "$W/old.defaults"
cp "$ROOT/$WEB_REL" "$W/old.web"
: > "$STATE/web_active"; : > "$STATE/web_enabled"
web_health wal retrying > "$STATE/web_health"
run --with-slothweb
check '[ "$RC" -eq 3 ]' "exit $RC, want 3: $(cat "$W/out")"
check 'grep -qx "curl -fsS --max-time 5 --interface 127.0.0.1 http://100.64.0.10:8770/api/health" "$LOG"' "health not asked on the bound address from loopback: $(grep ^curl "$LOG")"
check 'cmp -s "$W/old.web" "$ROOT/$WEB_REL"' "the previous slothweb unit was not restored"
check 'cmp -s "$W/old.defaults" "$ROOT/etc/default/slothweb"' "the operator's slothweb defaults were changed"
check '[ -e "$STATE/web_active" ] && [ -e "$STATE/web_enabled" ]' "the previous slothweb was not started again"
check '[ -f "$ROOT/$WEB_REL.rolled-back-T1" ] && [ ! -e "$ROOT/$WEB_REL.bak-migrate-T1" ]' "the slothweb backup was not renamed once restored"
CASE=web-keeps-defaults-rerun
web_health immutable connected > "$STATE/web_health"
: > "$LOG"
STAMP=T5 run --with-slothweb
check '[ "$RC" -eq 0 ]' "exit $RC: $(cat "$W/out")"
check 'cmp -s "$W/old.defaults" "$ROOT/etc/default/slothweb"' "the operator's slothweb defaults were replaced"
check 'grep -qF "keeping $ROOT/etc/default/slothweb as it is (SLOTHWEB_ARGS=--web-bind 100.64.0.10:8770" "$W/out"' "keeping the defaults not said: $(cat "$W/out")"
check 'cmp -s "$REPO/packaging/systemd/slothweb.service" "$ROOT/$WEB_REL"' "slothweb unit not installed on the rerun"
check 'cmp -s "$W/old.web" "$ROOT/$WEB_REL.bak-migrate-T5"' "the previous slothweb unit was not backed up"
check 'grep -q "sloth.db immutable, stream connected" "$W/out"' "immutable not accepted: $(cat "$W/out")"

# A backup of the operator's slothweb unit that fails comes before the
# unit is replaced: the rollback leaves the unit as it is and says so,
# rather than finding no backup and calling itself incomplete. The
# backup path is a dangling link, which cp refuses as root too.
CASE=web-backup-fails
setup web-backup-fails
printf '[Service]\nExecStart=/opt/old/slothweb\n' > "$ROOT/$WEB_REL"
cp "$ROOT/$WEB_REL" "$W/old.web"
: > "$STATE/web_active"; : > "$STATE/web_enabled"
ln -s "$W/no-such-dir/unit" "$ROOT/$WEB_REL.bak-migrate-T1"
run --with-slothweb
check '[ "$RC" -eq 3 ]' "exit $RC, want 3: $(cat "$W/out")"
check 'grep -qF "slothweb FAILED: could not back up $ROOT/$WEB_REL" "$W/out"' "the failed backup not said: $(cat "$W/out")"
check 'cmp -s "$W/old.web" "$ROOT/$WEB_REL"' "the operator's slothweb unit changed"
check '! grep -q "ROLLBACK INCOMPLETE" "$W/out"' "an untouched unit was reported as an incomplete rollback: $(cat "$W/out")"
check 'grep -q "slothweb rolled back to its state before this run" "$W/out"' "slothweb rollback not reported: $(cat "$W/out")"
check '[ -e "$STATE/web_active" ] && [ -e "$STATE/web_enabled" ]' "the previous slothweb was not started again"
check '[ ! -e "$ROOT/$WEB_REL.rolled-back-T1" ]' "a unit never replaced was renamed as rolled back"

# Refused in preflight, before the sensor is touched.
web_refusal() {   # web_refusal NAME EXPECTED-FRAGMENT (PREP sets it up)
    CASE=web-refuse-$1
    setup "web-refuse-$1"
    eval "$PREP"
    h=$(tree_hash "$ROOT")
    run --with-slothweb
    check '[ "$RC" -eq 2 ]' "exit $RC, want 2: $(cat "$W/out")"
    WANT=$2
    check 'grep -qF -- "$WANT" "$W/out"' "message lacks '$WANT': $(cat "$W/out")"
    check '[ "$(tree_hash "$ROOT")" = "$h" ]' "a refusal changed the scratch root"
    check '[ -z "$(mutating_calls)" ]' "a refusal made mutating calls: $(mutating_calls)"
}
PREP='rm "$ROOT/usr/local/bin/slothweb"'
web_refusal no-binary "no executable $SCRATCH/web-refuse-no-binary/root/usr/local/bin/slothweb"
PREP='echo "LISTEN 0 64 127.0.0.1:8770 0.0.0.0:*" > "$STATE/ss"'
web_refusal port-busy "port 8770 already has a listener and slothweb.service is not running"
PREP='mkdir -p "$ROOT/etc/default" && echo "SLOTHWEB_ARGS=--socket tcp:127.0.0.1:8765" > "$ROOT/etc/default/slothweb"'
web_refusal fixed-path "gives --socket; slothweb.service fixes it"
PREP='mkdir -p "$ROOT/etc/default" && echo "SLOTHWEB_ARGS=\"--web-bind 127.0.0.1:8770\"" > "$ROOT/etc/default/slothweb"'
web_refusal quoted "has quoting, a variable or a specifier"
PREP=''

# The dry run comes before the hand-started slothweb is stopped
# (deployment.md §4.4): a busy port is said, as the refusal the real run
# would make, and the dry run goes on, changing nothing.
CASE=web-dry-port-busy
setup web-dry-port-busy
eval "$TCP_PREP"
echo "LISTEN 0 64 127.0.0.1:8770 0.0.0.0:*" > "$STATE/ss"
h0=$(tree_hash "$ROOT")
run --dry-run --data-socket-unix --with-slothweb
check '[ "$RC" -eq 0 ]' "exit $RC: $(cat "$W/out")"
check 'grep -qF "note: a real run would REFUSE: port 8770 already has a listener and slothweb.service is not running" "$W/out"' "the busy port is not said: $(cat "$W/out")"
check 'grep -q "dry run complete; nothing was changed" "$W/out"' "the dry run did not finish: $(cat "$W/out")"
check '[ "$(tree_hash "$ROOT")" = "$h0" ]' "the scratch root changed under --dry-run with the port busy"
check '[ -z "$(mutating_calls)" ]' "mutating calls under --dry-run: $(mutating_calls)"

echo "deploy-test: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
