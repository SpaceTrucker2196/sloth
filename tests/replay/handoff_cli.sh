#!/bin/sh
# sloth --handoff and --interference-report through the linked binary
# (#250), on the database the replay run just wrote:
#
#   sh tests/replay/handoff_cli.sh ./sloth-wifi RUN_DIR
#
#   --from without --interference-report    exits 2
#   --handoff with --preflight              exits 2
#   --interference-report without --db      exits 2
#   --handoff DIR --db replay.db            exits 0; every file 0600, DIR
#                                           0700; no file holds the replay's
#                                           clear-text credential user name
#   a second run with --baseline-in DIR/snapshot.tsv
#                                           reads the packet's snapshot and
#                                           reports 0 changes
#   --interference-report - --db replay.db  exits 0 and names the window
#
# RUN_DIR holds wired.pcap, monitor.pcap, bt.pcap and replay.db from
# `make replay-run`. Nothing here opens a radio or the network.
set -u
B=$1
R=$2
D=$R/handoff
rm -rf "$D"
fail() { echo "handoff_cli: $*" >&2; exit 1; }

"$B" --from 2026-01-01 >/dev/null 2>&1
rc=$?
[ "$rc" -eq 2 ] || fail "--from without --interference-report exited $rc, want 2"
"$B" --preflight --handoff "$D" >/dev/null 2>&1
rc=$?
[ "$rc" -eq 2 ] || fail "--preflight --handoff exited $rc, want 2"
[ ! -e "$D" ] || fail "a refused --handoff created $D"
"$B" --interference-report - >/dev/null 2>&1
rc=$?
[ "$rc" -eq 2 ] || fail "--interference-report without --db exited $rc, want 2"

"$B" --handoff "$D" --db "$R/replay.db" --no-privdrop --site-label replay \
    >/dev/null 2>"$R/handoff.err"
rc=$?
[ "$rc" -eq 0 ] || fail "--handoff exited $rc: $(cat "$R/handoff.err")"
[ "$(stat -c %a "$D")" = 700 ] || fail "$D is not 0700"
n=0
for f in "$D"/*; do
    n=$((n + 1))
    [ "$(stat -c %a "$f")" = 600 ] || fail "$f is not 0600"
done
[ "$n" -eq 10 ] || fail "the packet holds $n files, want 10"
# The replay's CLEARTEXT_CRED is HTTP Basic for user "replay": its key
# and detail name it. Neither reaches the packet.
if grep -rq 'HTTP-Basic user\|cred:192\.0\.2\.10' "$D"; then
    fail "a packet file holds the credential's key or detail"
fi
grep -q '^CLEARTEXT_CRED' "$D/findings_open.tsv" ||
    fail "findings_open.tsv does not list the replay's CLEARTEXT_CRED"

"$B" --headless --replay "$R/wired.pcap,$R/monitor.pcap,$R/bt.pcap" \
    --ticks 3 --refresh-ms 100 --baseline-in "$D/snapshot.tsv" \
    >/dev/null 2>"$R/import.err"
grep -q '^sloth: 0 change(s) vs baseline' "$R/import.err" ||
    fail "the packet's snapshot did not import cleanly: $(cat "$R/import.err")"

"$B" --interference-report - --db "$R/replay.db" --from 2026-01-01 \
    >"$R/ifr.md" 2>/dev/null
rc=$?
[ "$rc" -eq 0 ] || fail "--interference-report exited $rc"
grep -q '^- Window: 2026-01-01T00:00:00Z to the file' "$R/ifr.md" ||
    fail "the report does not name its window"
echo "handoff_cli: packet written, withheld, imported; report written"
