#!/bin/sh
# Tests for packaging/bin/sloth-migrate-rf (#215). Run by `make deploy-test`.
#
# Everything runs unprivileged against a scratch root: an
# /etc/default/sloth written here (never read from /etc), a stub
# sloth-rf binary and unit, and a stub systemctl first on PATH that logs
# every call. Nothing outside the scratch dir is read or written, and no
# real service is touched.
#
# The absence assertions here (a dry run writes nothing, a refusal
# writes nothing, a moved flag is gone from SLOTH_ARGS, a copied flag is
# not, a second run changes nothing and makes no backup, a failed write
# or rename leaves both files and no litter, a commented example is not
# read as the value, no systemctl is ever run, a file-only move prints
# no AF_INET step, nothing to migrate creates no file) were each seen to
# fail under a mutation of the tool before this file claimed them:
# docs/wiki/log.md, the #215 entry, names each one.
#
# check() evals its first argument, so the single-quoted expressions are
# meant not to expand here (SC2016) and the variables they read look
# unused to shellcheck (SC2034).
# shellcheck disable=SC2016,SC2034
set -u

REPO=$(cd "$(dirname "$0")/../.." && pwd)
TOOL=$REPO/packaging/bin/sloth-migrate-rf
# The shell the tool runs under: TOOL_SH="busybox sh" or "bash --posix"
# checks it stays POSIX.
TOOL_SH=${TOOL_SH:-sh}
SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/sloth-rf-deploy-test.XXXXXX") || exit 1
# KEEP=1 leaves the scratch tree behind for inspection.
[ -n "${KEEP:-}" ] || trap 'chmod -R u+w "$SCRATCH" 2>/dev/null; rm -rf "$SCRATCH"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

PASS=0
FAIL=0
CASE=""
ok()    { PASS=$((PASS + 1)); }
bad()   { FAIL=$((FAIL + 1)); echo "FAIL [$CASE]: $*" >&2; }
check() { if eval "$1"; then ok; else bad "$2"; fi; }

# Invented paths and an invented position, never a real site's.
ADSB=/run/readsb/aircraft.json
APRS=/var/lib/direwolf/packets.log
R433=/var/lib/rtl_433/events.json
GPSD=gpsd://127.0.0.1:2947
LOC=10.5,-20.25,30

# The shape of the shipped /etc/default/sloth: comments that mention the
# flags, a commented example line, then the one live line.
sloth_defaults() {   # sloth_defaults 'the SLOTH_ARGS line'
    cat <<EOF
# /etc/default/sloth — site configuration for sloth-sensor.service (#139).
SLOTH_IFACE=alfa0

#   --adsb PATH           a local readsb's aircraft.json
# Example:
#   SLOTH_ARGS=--my-ssid HomeNet --adsb /nowhere/example.json
# SLOTH_ARGS=--rtl433 /nowhere/commented.json
$1
EOF
}

setup() {   # setup NAME 'the SLOTH_ARGS line'
    CASE=$1
    W=$SCRATCH/$1
    ROOT=$W/root
    LOG=$W/log
    # Exported, so no slip in run() can let the tool see an empty ROOT
    # and read the host's /etc/default.
    export ROOT
    mkdir -p "$ROOT/etc/default" "$ROOT/etc/systemd/system" \
             "$ROOT/usr/local/bin" "$W/stub"
    : > "$LOG"
    S=$ROOT/etc/default/sloth
    R=$ROOT/etc/default/sloth-rf
    sloth_defaults "$2" > "$S"
    chmod 640 "$S"      # not the 644 a new file gets: the mode must survive
    printf '#!/bin/sh\n' > "$ROOT/usr/local/bin/sloth-rf"
    chmod 755 "$ROOT/usr/local/bin/sloth-rf"
    printf '[Service]\nUser=sloth\n' > "$ROOT/etc/systemd/system/sloth-rf.service"
    # Anything that would touch a service is a failure of the tool.
    for c in systemctl service; do
        printf '#!/bin/sh\necho "%s $*" >> "%s"\n' "$c" "$LOG" > "$W/stub/$c"
        chmod 755 "$W/stub/$c"
    done
    STAMP=20261115-120000
    MVSTUB=
    CPSTUB=
}

rf_defaults() {   # an /etc/default/sloth-rf as `make install-service` leaves it, or edited
    cat > "$R" <<EOF
# /etc/default/sloth-rf — site configuration for sloth-rf.service (#215).
#   --adsb PATH           a local readsb's aircraft.json
$1
EOF
}

run() {
    # shellcheck disable=SC2086  # TOOL_SH may be two words
    env PATH="$W/stub:$PATH" ROOT="$ROOT" STAMP="$STAMP" \
        ${MVSTUB:+MV="$MVSTUB"} ${CPSTUB:+CP="$CPSTUB"} \
        $TOOL_SH "$TOOL" "$@" > "$W/out" 2>&1
    RC=$?
}

# Every file under the root: path, mode and content.
tree_hash() {
    (cd "$1" && find . \( -type f -o -type d \) -exec ls -ld {} + | awk '{ print $1, $NF }' | LC_ALL=C sort
     find . -type f -exec sha256sum {} + | LC_ALL=C sort) | sha256sum
}
args_of() {   # args_of FILE VAR -> the value of its one live line
    sed -n "s/^$2=//p" "$1"
}
has_tok() {   # has_tok 'args' 'flag value' -> the words appear, in order, as whole words
    case " $1 " in *" $2 "*) return 0 ;; esac
    return 1
}
litter() { find "$ROOT/etc/default" -name '*.tmp.*' | head -n 1; }
backups() { find "$ROOT/etc/default" -name '*.bak.*' | LC_ALL=C sort | tr '\n' ' '; }

ALL="SLOTH_ARGS=--site-label test-sensor --adsb $ADSB --aprs $APRS --aprs-freq 144390000 --aprs-silent-hours 12 --rtl433 $R433 --gps $GPSD --gps-allow-remote --location $LOC --my-ssid TestNet"

# ── Dry run is the default and writes nothing ────────────────────────────
setup dry "$ALL"
h=$(tree_hash "$ROOT")
run
check '[ "$RC" -eq 0 ]' "exit $RC: $(cat "$W/out")"
check '[ "$(tree_hash "$ROOT")" = "$h" ]' "a dry run changed the scratch root"
check '[ ! -e "$R" ]' "a dry run created $R"
check '[ -z "$(backups)" ]' "a dry run made a backup: $(backups)"
check 'grep -qF "dry run; nothing was changed" "$W/out"' "the dry run does not say so: $(cat "$W/out")"
check 'grep -qF "  before: $ALL" "$W/out"' "no before line for /etc/default/sloth: $(cat "$W/out")"
check 'grep -qF "  after:  SLOTH_ARGS=--site-label test-sensor --gps $GPSD --gps-allow-remote --location $LOC --my-ssid TestNet" "$W/out"' "no after line for /etc/default/sloth: $(cat "$W/out")"
check 'grep -qF "  before: (no file)" "$W/out"' "no before line for /etc/default/sloth-rf: $(cat "$W/out")"
check 'grep -qF "  after:  SLOTH_RF_ARGS=--adsb $ADSB --aprs $APRS --aprs-freq 144390000 --aprs-silent-hours 12 --rtl433 $R433 --gps $GPSD --gps-allow-remote --location $LOC" "$W/out"' "no after line for /etc/default/sloth-rf: $(cat "$W/out")"
# --dry-run spelled out, and after --apply: the last one wins.
run --apply --dry-run
check '[ "$RC" -eq 0 ] && [ "$(tree_hash "$ROOT")" = "$h" ]' "--apply --dry-run wrote: $(cat "$W/out")"
check '[ ! -s "$LOG" ]' "a dry run ran: $(cat "$LOG")"

# ── --apply: move, copy, backup ──────────────────────────────────────────
setup apply "$ALL"
cp -p "$S" "$W/sloth.orig"
run --apply
check '[ "$RC" -eq 0 ]' "exit $RC: $(cat "$W/out")"
sa=$(args_of "$S" SLOTH_ARGS)
ra=$(args_of "$R" SLOTH_RF_ARGS)
check '[ "$sa" = "--site-label test-sensor --gps $GPSD --gps-allow-remote --location $LOC --my-ssid TestNet" ]' "SLOTH_ARGS after: $sa"
check '[ "$ra" = "--adsb $ADSB --aprs $APRS --aprs-freq 144390000 --aprs-silent-hours 12 --rtl433 $R433 --gps $GPSD --gps-allow-remote --location $LOC" ]' "SLOTH_RF_ARGS after: $ra"
# Moved: gone from the sensor's line. Each flag by name, so one that
# stayed behind is named.
for f in --adsb --aprs --aprs-freq --aprs-silent-hours --rtl433; do
    check '! has_tok "$sa" "$f"' "$f is still in SLOTH_ARGS: $sa"
    check 'case " $ra " in *" $f "*) true ;; *) false ;; esac' "$f did not reach SLOTH_RF_ARGS: $ra"
done
# Copied: in both.
for f in "--gps $GPSD" "--gps-allow-remote" "--location $LOC"; do
    check 'has_tok "$sa" "$f"' "'$f' left SLOTH_ARGS: $sa"
    check 'has_tok "$ra" "$f"' "'$f' is not in SLOTH_RF_ARGS: $ra"
done
# Not the tool's to move: they stay, and do not travel.
check 'has_tok "$sa" "--site-label test-sensor" && has_tok "$sa" "--my-ssid TestNet"' "an unrelated flag left SLOTH_ARGS: $sa"
check '! has_tok "$ra" "--my-ssid TestNet" && ! has_tok "$ra" "--site-label test-sensor"' "an unrelated flag travelled: $ra"
# The backup is the file as it was; no backup of a file that was not there.
check '[ "$(backups)" = "$S.bak.20261115-120000 " ]' "backups: $(backups)"
check 'cmp -s "$S.bak.20261115-120000" "$W/sloth.orig"' "the backup is not the original"
# Everything but the one line is as it was, comments and example included.
check '[ "$(grep -v "^SLOTH_ARGS=" "$S")" = "$(grep -v "^SLOTH_ARGS=" "$W/sloth.orig")" ]' "lines other than SLOTH_ARGS= changed"
check '[ "$(grep -c "^SLOTH_ARGS=" "$S")" -eq 1 ]' "not exactly one SLOTH_ARGS= line"
check 'grep -qxF "# SLOTH_ARGS=--rtl433 /nowhere/commented.json" "$S"' "the commented example was rewritten"
check '[ -n "$(find "$S" -perm 640)" ]' "the mode of $S changed from 0640"
check '[ -n "$(find "$R" -perm 644)" ]' "the new $R is not 0644"
# The new file is the shipped template with its line filled in.
check 'grep -qF "Written by sloth-migrate-rf (20261115-120000)" "$R"' "no provenance line in $R"
check 'grep -qF -- "--aprs-silent-hours N" "$R"' "$R is not from the template"
check '[ "$(grep -c "^SLOTH_RF_ARGS=" "$R")" -eq 1 ]' "not exactly one SLOTH_RF_ARGS= line"
check '[ -z "$(litter)" ]' "a temporary was left: $(litter)"
# It restarts nothing and says what to run.
check '[ ! -s "$LOG" ]' "the tool ran: $(cat "$LOG")"
for l in "systemctl daemon-reload" "systemctl enable --now sloth-rf.service" \
         "systemctl restart sloth-sensor.service" "systemctl restart slothweb.service"; do
    check 'grep -qxF "  $l" "$W/out"' "the next steps do not name '$l': $(cat "$W/out")"
done
# gpsd is a TCP socket: the AF_INET drop-in is named.
check 'grep -qF "sloth-rf-gps.conf /etc/systemd/system/sloth-rf.service.d/gps.conf" "$W/out"' "no AF_INET step for --gps gpsd://: $(cat "$W/out")"

# ── Idempotent: the second run is a no-op and says so ────────────────────
h=$(tree_hash "$ROOT")
STAMP=20261115-120500
run --apply
check '[ "$RC" -eq 0 ]' "second run: exit $RC: $(cat "$W/out")"
check 'grep -qF "already migrated" "$W/out" && grep -qF "nothing to do; nothing was changed" "$W/out"' "the second run does not say it is a no-op: $(cat "$W/out")"
check '[ "$(tree_hash "$ROOT")" = "$h" ]' "the second run changed the scratch root (backups: $(backups))"
check '[ ! -s "$LOG" ]' "the second run ran: $(cat "$LOG")"
run
check '[ "$RC" -eq 0 ] && grep -qF "already migrated" "$W/out"' "a dry run after the migration: $(cat "$W/out")"

# ── Both argument forms ──────────────────────────────────────────────────
setup forms "SLOTH_ARGS=--adsb=$ADSB --hop-dwell-ms 250 --aprs $APRS --aprs-freq=144390000 --aprs-silent-hours=12 --rtl433=$R433 --gps=$GPSD --gps-baud=9600 --location=$LOC"
run --apply
check '[ "$RC" -eq 0 ]' "exit $RC: $(cat "$W/out")"
sa=$(args_of "$S" SLOTH_ARGS)
ra=$(args_of "$R" SLOTH_RF_ARGS)
check '[ "$sa" = "--hop-dwell-ms 250 --gps=$GPSD --gps-baud=9600 --location=$LOC" ]' "SLOTH_ARGS after: $sa"
check '[ "$ra" = "--adsb=$ADSB --aprs $APRS --aprs-freq=144390000 --aprs-silent-hours=12 --rtl433=$R433 --gps=$GPSD --gps-baud=9600 --location=$LOC" ]' "SLOTH_RF_ARGS after: $ra"
# A flag that only starts like one of these is not one of them.
setup lookalike "SLOTH_ARGS=--adsb-extra 1 --aprsx=2 --gpsd 3 --adsb $ADSB"
run --apply
sa=$(args_of "$S" SLOTH_ARGS)
ra=$(args_of "$R" SLOTH_RF_ARGS)
check '[ "$sa" = "--adsb-extra 1 --aprsx=2 --gpsd 3" ]' "a look-alike flag moved: $sa"
check '[ "$ra" = "--adsb $ADSB" ]' "SLOTH_RF_ARGS after: $ra"
# A file-only move opens no TCP socket: no AF_INET step.
check '! grep -qF "sloth-rf-gps.conf" "$W/out"' "an AF_INET step for a file-only move: $(cat "$W/out")"
# sbs:// does.
setup sbs "SLOTH_ARGS=--adsb sbs://127.0.0.1:30003"
run --apply
check 'grep -qF "sloth-rf-gps.conf" "$W/out"' "no AF_INET step for --adsb sbs://: $(cat "$W/out")"

# ── A value in one pair of quotes ────────────────────────────────────────
setup quoted "SLOTH_ARGS=\"--site-label test-sensor --adsb $ADSB\""
run --apply
check '[ "$RC" -eq 0 ]' "exit $RC: $(cat "$W/out")"
check 'grep -qxF "SLOTH_ARGS=\"--site-label test-sensor\"" "$S"' "the quotes were not kept: $(args_of "$S" SLOTH_ARGS)"
check 'grep -qxF "SLOTH_RF_ARGS=--adsb $ADSB" "$R"' "SLOTH_RF_ARGS: $(args_of "$R" SLOTH_RF_ARGS)"

# ── An /etc/default/sloth-rf that is already there ───────────────────────
# As install-service leaves it: empty. Edited in place, and backed up.
setup rf-empty "SLOTH_ARGS=--adsb $ADSB --gps $GPSD"
rf_defaults "SLOTH_RF_ARGS="
cp -p "$R" "$W/rf.orig"
run --apply
check '[ "$RC" -eq 0 ]' "exit $RC: $(cat "$W/out")"
check '[ "$(args_of "$R" SLOTH_RF_ARGS)" = "--adsb $ADSB --gps $GPSD" ]' "SLOTH_RF_ARGS: $(args_of "$R" SLOTH_RF_ARGS)"
check 'cmp -s "$R.bak.20261115-120000" "$W/rf.orig"' "no backup of the existing $R"
check '[ "$(grep -v "^SLOTH_RF_ARGS=" "$R")" = "$(grep -v "^SLOTH_RF_ARGS=" "$W/rf.orig")" ]' "lines other than SLOTH_RF_ARGS= changed"
check '! grep -qF "Written by sloth-migrate-rf" "$R"' "an existing file was replaced by the template"
# Flags of its own are kept; a flag both have, with the same value, is
# there once.
setup rf-own "SLOTH_ARGS=--adsb $ADSB --gps $GPSD"
rf_defaults "SLOTH_RF_ARGS=--site-label rf-test --gps $GPSD --strict"
run --apply
check '[ "$RC" -eq 0 ]' "exit $RC: $(cat "$W/out")"
check '[ "$(args_of "$R" SLOTH_RF_ARGS)" = "--site-label rf-test --gps $GPSD --strict --adsb $ADSB" ]' "SLOTH_RF_ARGS: $(args_of "$R" SLOTH_RF_ARGS)"

# ── Refusals: exit 2, nothing changed, nothing run ───────────────────────
refusal() {   # refusal NAME 'SLOTH_ARGS line' 'expected text' [tool args...]
    name=$1 line=$2 want=$3
    shift 3
    setup "refuse-$name" "$line"
    eval "${PREP:-:}"
    h=$(tree_hash "$ROOT")
    run "$@"
    check '[ "$RC" -eq 2 ]' "exit $RC, want 2: $(cat "$W/out")"
    check 'grep -qF -- "$want" "$W/out"' "the refusal does not say '$want': $(cat "$W/out")"
    check 'grep -qF "nothing was changed" "$W/out"' "the refusal does not say nothing was changed"
    check '[ "$(tree_hash "$ROOT")" = "$h" ]' "a refusal changed the scratch root"
    check '[ ! -s "$LOG" ]' "a refusal ran: $(cat "$LOG")"
}
PREP=
# A serial GPS: both daemons would want the one device. Refused in a dry
# run too, so the operator learns it before --apply; the fix is named.
refusal serial "SLOTH_ARGS=--adsb $ADSB --gps /dev/ttyACM0 --gps-baud 9600" "names the serial device /dev/ttyACM0" --apply
check 'grep -qF "The fix is gpsd" "$W/out" && grep -qF -- "--gps gpsd://127.0.0.1:2947" "$W/out"' "the serial refusal does not name gpsd as the fix: $(cat "$W/out")"
refusal serial-dry "SLOTH_ARGS=--gps=/dev/ttyUSB0" "names the serial device /dev/ttyUSB0"
# The existing file has another value for a flag being moved or copied.
PREP='rf_defaults "SLOTH_RF_ARGS=--adsb sbs://127.0.0.1:30003"'
refusal conflict-value "SLOTH_ARGS=--adsb $ADSB" "already carries different RF flags" --apply
check 'grep -qF "has \"--adsb sbs://127.0.0.1:30003\"" "$W/out" && grep -qF -- "--force" "$W/out"' "the conflict is not spelled out: $(cat "$W/out")"
PREP='rf_defaults "SLOTH_RF_ARGS=--gps gpsd://127.0.0.1:2948"'
refusal conflict-gps "SLOTH_ARGS=--gps $GPSD" "already carries different RF flags" --apply
# ... or a decoder flag the sensor's file does not have.
PREP='rf_defaults "SLOTH_RF_ARGS=--rtl433 $R433"'
refusal conflict-other "SLOTH_ARGS=--adsb $ADSB" "already carries different RF flags" --apply
refusal conflict-dry "SLOTH_ARGS=--adsb $ADSB" "already carries different RF flags"
PREP=
# What cannot be split the way systemd would split it.
refusal no-value "SLOTH_ARGS=--site-label x --adsb" "--adsb in $SCRATCH/refuse-no-value/root/etc/default/sloth has no value" --apply
refusal no-value-eq "SLOTH_ARGS=--aprs= --site-label x" "--aprs= in" --apply
refusal twice "SLOTH_ARGS=--adsb $ADSB --adsb=sbs://127.0.0.1:30003" "--adsb is given twice" --apply
refusal quoting "SLOTH_ARGS=--site-label \"two words\" --adsb $ADSB" "has quoting or a backslash" --apply
PREP='echo "SLOTH_ARGS=--aprs $APRS" >> "$S"'
refusal two-lines "SLOTH_ARGS=--adsb $ADSB" "more than one SLOTH_ARGS= line" --apply
PREP='rm "$S"'
refusal no-file "SLOTH_ARGS=" "there is no Wi-Fi sensor configuration to migrate from" --apply
PREP=
refusal bad-arg "SLOTH_ARGS=--adsb $ADSB" "unknown argument '--appply'" --appply
# sloth-rf is not installed: the flags would go to a daemon that is not
# there. --apply refuses; the dry run says it would.
PREP='rm "$ROOT/usr/local/bin/sloth-rf"'
refusal no-binary "SLOTH_ARGS=--adsb $ADSB" "no executable $SCRATCH/refuse-no-binary/root/usr/local/bin/sloth-rf" --apply
PREP='rm "$ROOT/etc/systemd/system/sloth-rf.service"'
refusal no-unit "SLOTH_ARGS=--adsb $ADSB" "no $SCRATCH/refuse-no-unit/root/etc/systemd/system/sloth-rf.service" --apply
PREP=
setup dry-no-binary "SLOTH_ARGS=--adsb $ADSB"
rm "$ROOT/usr/local/bin/sloth-rf"
h=$(tree_hash "$ROOT")
run
check '[ "$RC" -eq 0 ] && grep -qF "note: --apply would REFUSE: no executable" "$W/out"' "the dry run does not say --apply would refuse: $(cat "$W/out")"
check '[ "$(tree_hash "$ROOT")" = "$h" ]' "the dry run changed the scratch root"

# ── --force merges, the sensor's file winning ────────────────────────────
setup force "SLOTH_ARGS=--adsb $ADSB --gps $GPSD"
rf_defaults "SLOTH_RF_ARGS=--site-label rf-test --adsb sbs://127.0.0.1:30003 --rtl433 $R433 --gps gpsd://127.0.0.1:2948"
cp -p "$R" "$W/rf.orig"
run --apply --force
check '[ "$RC" -eq 0 ]' "exit $RC: $(cat "$W/out")"
check '[ "$(args_of "$R" SLOTH_RF_ARGS)" = "--site-label rf-test --adsb $ADSB --rtl433 $R433 --gps $GPSD" ]' "SLOTH_RF_ARGS: $(args_of "$R" SLOTH_RF_ARGS)"
check '[ "$(args_of "$S" SLOTH_ARGS)" = "--gps $GPSD" ]' "SLOTH_ARGS: $(args_of "$S" SLOTH_ARGS)"
check 'cmp -s "$R.bak.20261115-120000" "$W/rf.orig"' "--force made no backup of what it merged over"

# ── Nothing to migrate ───────────────────────────────────────────────────
setup nothing "SLOTH_ARGS=--site-label test-sensor --my-ssid TestNet"
h=$(tree_hash "$ROOT")
run --apply
check '[ "$RC" -eq 0 ] && grep -qF "nothing to migrate" "$W/out"' "exit $RC: $(cat "$W/out")"
check '[ "$(tree_hash "$ROOT")" = "$h" ]' "nothing to migrate, and the scratch root changed"
check '[ ! -e "$R" ]' "nothing to migrate, and $R was created"
# The commented example lines are not the value.
check '! grep -qF "commented.json" "$W/out" && ! grep -qF "example.json" "$W/out"' "a commented line was read as SLOTH_ARGS: $(cat "$W/out")"

# ── Failure: both files as they were, no litter ──────────────────────────
# A stub mv or cp that fails on its Nth call and is the real one otherwise.
failing() {   # failing mv|cp N -> path of the stub
    f=$W/stub/failing-$1
    cat > "$f" <<EOF
#!/bin/sh
n=\$(cat "$W/calls-$1" 2>/dev/null || echo 0)
n=\$((n + 1))
echo \$n > "$W/calls-$1"
[ \$n -ne $2 ] || { echo "stub $1: call \$n fails" >&2; exit 1; }
exec $1 "\$@"
EOF
    chmod 755 "$f"
    echo "$f"
}
failure() {   # failure NAME: run --apply, expect exit 1 and an untouched root
    h=$(tree_hash "$ROOT")
    rm -f "$W"/calls-*
    run --apply
    check '[ "$RC" -eq 1 ]' "exit $RC, want 1: $(cat "$W/out")"
    check 'grep -qF "both files are as they were" "$W/out"' "the failure does not say the files are as they were: $(cat "$W/out")"
    check '[ "$(tree_hash "$ROOT")" = "$h" ]' "a failed run changed the scratch root (litter: $(litter); backups: $(backups))"
    check '[ ! -s "$LOG" ]' "a failed run ran: $(cat "$LOG")"
}
# The second rename (the sensor's file) fails after sloth-rf's file was
# renamed into place: an existing sloth-rf file is put back ...
setup fail-mv2 "$ALL"
rf_defaults "SLOTH_RF_ARGS=--site-label rf-test"
MVSTUB=$(failing mv 2)
failure
check '[ "$(args_of "$R" SLOTH_RF_ARGS)" = "--site-label rf-test" ]' "$R was not put back: $(args_of "$R" SLOTH_RF_ARGS)"
# ... and one that did not exist is removed again.
setup fail-mv2-new "$ALL"
MVSTUB=$(failing mv 2)
failure
check '[ ! -e "$R" ]' "the new $R was left behind"
# The first rename fails.
setup fail-mv1 "$ALL"
MVSTUB=$(failing mv 1)
failure
# The backup cannot be made (cp calls: the sensor's temporary, then its
# backup): nothing is renamed without one.
setup fail-backup "$ALL"
CPSTUB=$(failing cp 2)
failure
check '[ ! -e "$R" ]' "$R was written without a backup of $S"
# The directory cannot be written at all. Root ignores the mode.
if [ "$(id -u)" -ne 0 ]; then
    setup fail-readonly "$ALL"
    chmod 555 "$ROOT/etc/default"
    failure
    chmod 755 "$ROOT/etc/default"
fi
# After a failure the same command succeeds once the cause is gone.
setup fail-then-ok "$ALL"
MVSTUB=$(failing mv 2)
failure
MVSTUB=
STAMP=20261115-120100
run --apply
check '[ "$RC" -eq 0 ] && [ -e "$R" ] && [ "$(backups)" = "$S.bak.20261115-120100 " ]' "the run after a failure: exit $RC, backups $(backups): $(cat "$W/out")"

# ── No checkout beside the tool (run from /usr/local/sbin) ───────────────
setup no-template "SLOTH_ARGS=--rtl433 $R433"
# shellcheck disable=SC2086  # TOOL_SH may be two words
env PATH="$W/stub:$PATH" ROOT="$ROOT" STAMP="$STAMP" RF_DEFAULTS_TEMPLATE="$W/absent" \
    $TOOL_SH "$TOOL" --apply > "$W/out" 2>&1
RC=$?
check '[ "$RC" -eq 0 ] && [ "$(args_of "$R" SLOTH_RF_ARGS)" = "--rtl433 $R433" ]' "without the template: exit $RC: $(cat "$W/out")"

# ── --help prints the header and changes nothing ─────────────────────────
setup help "$ALL"
h=$(tree_hash "$ROOT")
run --help
check '[ "$RC" -eq 0 ] && grep -qF "sloth-migrate-rf --apply" "$W/out" && ! grep -q "^set -u" "$W/out"' "--help: $(cat "$W/out")"
check '[ "$(tree_hash "$ROOT")" = "$h" ]' "--help changed the scratch root"

echo "deploy-test (sloth-migrate-rf): $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
