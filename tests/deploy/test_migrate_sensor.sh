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
# of the hardened unit, a second run changes nothing, --no-privdrop is not
# carried, the source data is not modified) were each seen to fail under a
# mutation of the tool before this file claimed them: docs/wiki/log.md,
# the #153 entry, names each one.
set -u

REPO=$(cd "$(dirname "$0")/../.." && pwd)
TOOL=$REPO/packaging/bin/sloth-migrate-sensor
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
    mkdir -p "$ROOT/etc/systemd/system" "$ROOT/home/op/sloth/data/pcap" \
             "$ROOT/home/op/sloth/data/eapol" "$ROOT/usr/local/bin" \
             "$ROOT/usr/local/sbin" "$ROOT/usr/local/share/sloth" \
             "$ROOT/proc/4242" "$ROOT/run/sloth" "$ROOT/var/lib" "$STUB" "$STATE"
    : > "$LOG"
    old_unit "${2:-    \\}" > "$ROOT/etc/systemd/system/sloth-sensor.service"
    D=$ROOT/home/op/sloth/data
    printf 'SQLite format 3\000rows' > "$D/sloth.db"
    printf 'v5 backup' > "$D/sloth.db.v5.bak"
    printf 'pcap bytes' > "$D/pcap/alert-1.pcap"
    printf 'WPA*02*...' > "$D/eapol/eapol.22000"
    printf '# report' > "$D/report.md"
    printf '{}' > "$D/report.json"
    printf 'snapshot' > "$D/snapshot.txt"
    printf '#!/bin/sh\n' > "$ROOT/usr/local/bin/sloth"
    printf '#!/bin/sh\n' > "$ROOT/usr/local/sbin/sloth-monitor-up"
    chmod 755 "$ROOT/usr/local/bin/sloth" "$ROOT/usr/local/sbin/sloth-monitor-up"
    printf 'research' > "$ROOT/usr/local/share/sloth/research.db"
    printf 'Name:\tsloth\nCapEff:\t0000000000001000\nNoNewPrivs:\t1\n' \
        > "$ROOT/proc/4242/status"
    : > "$ROOT/run/sloth/sloth.sock"
    echo active > "$STATE/active"
    echo 0 > "$STATE/retune"

    cat > "$STUB/systemctl" <<STUBEOF
#!/bin/sh
echo "systemctl \$*" >> "$LOG"
case "\$1" in
    is-active) [ "\$(cat "$STATE/active")" = active ] ;;
    is-enabled) exit 0 ;;
    stop) echo inactive > "$STATE/active" ;;
    start|restart) echo active > "$STATE/active" ;;
    show) echo 4242 ;;
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
n=\$(cat "$STATE/socat_calls" 2>/dev/null || echo 0)
echo \$((n + 1)) > "$STATE/socat_calls"
[ "\$n" -eq 0 ] && exit 1
echo '{"type":"heartbeat","ts":1}'
echo "{\"type\":\"sensor_health\",\"ts\":2,\"chan_retune_failures\":\$(cat "$STATE/retune"),\"hop_channels\":13}"
STUBEOF
    chmod 755 "$STUB"/*
}

run() {   # run [args]; output to $W/out, status in $RC
    ROOT=$ROOT STAMP=${STAMP:-T1} AVAIL_KB=${AVAIL_KB:-10000000} \
    VERIFY_SECS=2 HEALTH_SECS=2 TMPDIR=$W \
    SYSTEMCTL=$STUB/systemctl SYSUSERS=$STUB/systemd-sysusers \
    GETENT=$STUB/getent CHOWN=$STUB/chown SOCAT=$STUB/socat \
    CP=${CP_CMD:-cp} \
    sh "$TOOL" "$@" > "$W/out" 2>&1
    RC=$?
}

tree_hash() {
    (cd "$1" && { find . -printf '%p %y %m %s\n' | LC_ALL=C sort;
                  find . -type f -exec sha256sum {} + | LC_ALL=C sort -k2; }) \
        | sha256sum | cut -d' ' -f1
}

file_sums() { (cd "$1" && find . -type f -exec sha256sum {} + | LC_ALL=C sort -k2); }

mutating_calls() {
    grep -E '^(systemctl (stop|start|restart|daemon-reload|reenable|enable|disable)|systemd-sysusers|chown)' "$LOG"
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

# ── 2. apply: flag carry-over, copy, unit, verify ────────────────────────
CASE=apply
setup apply
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
check 'grep -qx "chown -R sloth:sloth $ROOT/var/lib/sloth" "$LOG"' "no chown -R sloth:sloth"
check 'cmp -s "$REPO/packaging/systemd/sloth.sysusers.conf" "$ROOT/usr/lib/sysusers.d/sloth.conf"' "sysusers fragment not installed"
check 'grep -q "^systemd-sysusers " "$LOG"' "systemd-sysusers not run"
# Stopped before the copy, switched before the start.
order=$(grep -E "^systemctl (stop|daemon-reload|start)" "$LOG" | tr '\n' ,)
check '[ "$order" = "systemctl stop sloth-sensor.service,systemctl daemon-reload,systemctl start sloth-sensor.service," ]' "unexpected order: $order"
check '[ "$(cat "$STATE/active")" = active ]' "service not active after apply"
check 'grep -q "note: the data socket moves from /run/sloth.sock" "$W/out"' "socket relocation not noted"
check 'grep -q "verify: sensor_health arrived, chan_retune_failures 0" "$W/out"' "health not verified"
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
STAMP=T3 run --dry-run
check '[ "$RC" -eq 0 ] && [ "$(tree_hash "$ROOT")" = "$h1" ]' "dry run after migration changed something"

# ── 4. refusals change nothing ───────────────────────────────────────────
refusal() {   # refusal NAME EXPECTED-FRAGMENT [extra ExecStart line]
    CASE=refuse-$1
    setup "refuse-$1" "${3:-    \\}"
    [ -n "${PREP:-}" ] && eval "$PREP"
    h=$(tree_hash "$ROOT")
    run
    check '[ "$RC" -eq 2 ]' "exit $RC, want 2: $(cat "$W/out")"
    check 'grep -qF -- "$2" "$W/out"' "message lacks '$2': $(cat "$W/out")"
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
echo 3 > "$STATE/retune"
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

# ── 7. a rerun after the rollback succeeds ───────────────────────────────
CASE=rerun-after-rollback
echo 0 > "$STATE/retune"
STAMP=T4 run
check '[ "$RC" -eq 0 ]' "exit $RC: $(cat "$W/out")"
check 'cmp -s "$REPO/packaging/systemd/sloth-sensor.service" "$ROOT/$UNIT_REL"' "unit not installed on rerun"
check 'cmp -s "$W/old.unit" "$ROOT/$UNIT_REL.bak-migrate-T4"' "rerun backed up the wrong unit"
check 'grep -qx "SLOTH_ARGS=.*" "$ROOT/etc/default/sloth" && grep -q "^# Written by sloth-migrate-sensor" "$ROOT/etc/default/sloth"' "rerun did not write the defaults"
check 'cmp -s "$ROOT/etc/default/sloth.bak-migrate-T4" /dev/stdin <<X
ORIGINAL defaults
X' "rerun did not back up the original defaults"

echo "deploy-test: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
