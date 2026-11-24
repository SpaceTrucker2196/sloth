#!/bin/sh
# sloth --preflight through the linked binary (#247): what main.c hands
# the checks, which tests/test_preflight.c (pure, pf_config_t built by
# hand) cannot see.
#
#   sh tests/replay/preflight_cli.sh ./sloth-wifi SCRATCH_DIR
#
#   --json alone          exits 2 (it qualifies --preflight)
#   32 --iface names      the last, absent, still reaches the page as a
#                         fail (main.c takes MAX_IFACES, 32; the hook
#                         once copied 16)
#   --monitor-only        with an absent --monitor-iface: a fail line,
#                         as the run refuses (exit 1)
#   --allow-active        nothing on stderr says an opt-in was enabled:
#                         the preflight starts nothing
#
# Each runs read-only: the interfaces named do not exist, and the only
# probes are the preflight's own reads (src/preflight_gather.c).
set -u
B=$1
D=$2
mkdir -p "$D"
fail() { echo "preflight_cli: $*" >&2; exit 1; }

"$B" --json >/dev/null 2>&1
rc=$?
[ "$rc" -eq 2 ] || fail "--json without --preflight exited $rc, want 2"

args=""
i=0
while [ "$i" -lt 31 ]; do args="$args --iface lo"; i=$((i + 1)); done
# shellcheck disable=SC2086  # $args is a list of words, split on purpose
"$B" --preflight --json --no-privdrop $args --iface slothpf0 \
    --monitor-only --monitor-iface slothpf1 --allow-active \
    >"$D/pf.json" 2>"$D/pf.err"
rc=$?
[ "$rc" -eq 2 ] || fail "--preflight with absent interfaces exited $rc, want 2"
grep -q '"item":"slothpf0","level":"fail"' "$D/pf.json" ||
    fail "the 32nd --iface (absent) did not reach the page as a fail"
grep -q '"item":"monitor-only","level":"fail"' "$D/pf.json" ||
    fail "--monitor-only with no monitor radio is not a fail"
if grep -q 'enabled' "$D/pf.err"; then
    fail "--preflight announced an opt-in as enabled: $(cat "$D/pf.err")"
fi
echo "preflight_cli: 4 command lines as expected"
