#!/bin/sh
# sloth --sweep through the linked binary (#249 review): the refusals
# main.c makes before anything opens, which tests/test_sweep.c (the run's
# functions, called by hand) cannot see.
#
#   sh tests/replay/sweep_cli.sh ./sloth-wifi SCRATCH_DIR
#
# Every line here must exit 2 with its own message, and none may leave a
# file behind: not in the sweep directory, and no --db created. The
# preflight case names a monitor radio that does not exist, so the
# preflight fails (--monitor-only with no monitor radio) and the run
# stops before a session starts; nothing is captured or retuned.
set -u
B=$1
D=$2
rm -rf "$D"
mkdir -p "$D/dir"
fail() { echo "sweep_cli: $*" >&2; exit 1; }
n=0

# want MESSAGE ARGS...: exit 2, MESSAGE on stderr.
want() {
    msg=$1; shift
    "$B" --headless --no-privdrop "$@" >"$D/out" 2>"$D/err"
    rc=$?
    [ "$rc" -eq 2 ] || fail "'$*' exited $rc, want 2: $(head -c 300 "$D/err")"
    grep -q -- "$msg" "$D/err" || fail "'$*': stderr lacks \"$msg\": $(head -c 300 "$D/err")"
    n=$((n + 1))
}

S="--sweep room --sweep-minutes 1"
want "qualify --sweep"        --sweep-minutes 5
want "qualify --sweep"        --sweep-dir "$D/dir"
want "qualify --sweep"        --sweep-group "$(id -gn)"
want "LABEL: 1 to 48"         --sweep a/b --sweep-minutes 1 --hop --sweep-dir "$D/dir"
want "needs --sweep-minutes"  --sweep room --hop --sweep-dir "$D/dir"
want "needs --sweep-minutes"  --sweep room --sweep-minutes 0 --hop --sweep-dir "$D/dir"
# shellcheck disable=SC2086  # $S is a list of words, split on purpose
want "it needs --hop"         $S --sweep-dir "$D/dir"
# shellcheck disable=SC2086
want "refuses --cue"          $S --hop --cue --sweep-dir "$D/dir"
# shellcheck disable=SC2086
want "no radio"               $S --hop --replay /nonexistent.pcap --sweep-dir "$D/dir"
# shellcheck disable=SC2086
want "separate commands"      $S --hop --preflight --sweep-dir "$D/dir"
# shellcheck disable=SC2086
want "needs --sweep-dir DIR"  $S --hop
# shellcheck disable=SC2086
want "not a directory"        $S --hop --sweep-dir "$D/nodir"

# --sweep-group (owner ruling 2026-11-25): a group that is not one, and
# a directory that is not the group's 2770/0770 one.
# shellcheck disable=SC2086
want "no such group"          $S --hop --sweep-dir "$D/dir" --sweep-group no-such-sloth-group-x
chmod 0700 "$D/dir"
# shellcheck disable=SC2086
want "not 2770 or 0770"       $S --hop --sweep-dir "$D/dir" --sweep-group "$(id -gn)"
ln -s dir "$D/link"
# shellcheck disable=SC2086
want "a symlink"              $S --hop --sweep-dir "$D/link" --sweep-group "$(id -gn)"
rm "$D/link"

# A baseline that is there and cannot be read: refused before the
# preflight, so its page is not printed.
mkdir "$D/dir/sweep-room.baseline.tsv"
# shellcheck disable=SC2086
want "the baseline cannot be read" $S --hop --sweep-dir "$D/dir"
if grep -q "preflight" "$D/err"; then
    fail "an unreadable baseline reached the preflight: $(head -c 300 "$D/err")"
fi
rmdir "$D/dir/sweep-room.baseline.tsv"

# The preflight fails: the sweep is not started and nothing opens.
# shellcheck disable=SC2086
want "not started: the preflight failed" $S --hop --sweep-dir "$D/dir" \
    --db "$D/dir/s.db" --monitor-only --monitor-iface slothsw0

left=$(ls -A "$D/dir")
[ -z "$left" ] || fail "a refused sweep left files in its directory: $left"
echo "sweep_cli: $n command lines refused as expected"
