#!/bin/sh
# The whole build surface, in one run, in one tree (agents/AGENTS.md
# "Discipline"): the six -Werror configs; make test and test-capture-path
# plain, under ASan+UBSan and under TSan; make web-test plain, against
# SQLite 3.45 when a build of it is given, without SQLite, with an empty
# vendor table, under ASan and under TSan twice; the quickstart check;
# deploy-test with every shellcheck given; replay-check; a one-second
# fuzz; cppcheck; and docs-counts and research-index leaving the tree
# clean. Each line is one measured result; CI runs the same matrix on
# every push (.github/workflows/ci.yml), so a local run is for finding
# it first, not instead.
#
#   usage: tools/gate.sh [tree]            (default: the current tree)
#   env:   GATE_SQLITE345=<dir with libsqlite3.so of 3.45.x>
#          GATE_SHELLCHECKS="<dir>:<dir>"  (bin dirs of other shellcheck
#                                           versions; the PATH one always runs)
#          GATE_LOG=<file>                 (default: build/gate.log)
#
# Lessons this script carries, each from a run that went wrong:
#   - It takes a lock on the tree (build/gate.lock). Two runs at once
#     each `make clean` the other's objects, and neither result means
#     anything; a second run is refused, not queued (2026-11-02).
#   - It refuses to start with less than 1.5 GB free in $TMPDIR: the
#     suite builds a 900,000-row database there, and a full tmpfs
#     produced a red that was not the code's (2026-10-27).
#   - It prints the toolchain first. An `apt upgrade` in the middle of a
#     run swapped gcc, glibc and libpcap and broke four configs; with the
#     versions in the log the next reader can tell a tool change from a
#     code change (2026-10-26).
#   - It runs `make clean` before every sanitized step. The build-time
#     generators (web/tools/*.c) are built with the step's CFLAGS only
#     when they are rebuilt; a generator left over from a plain build
#     never ran under the sanitizers locally, and CI, building from a
#     clean tree, found a leak and a qsort(NULL) in one (2026-11-02).
#   - It keeps every step's full log and prints the FAIL and sanitizer
#     lines under a red step, because a one-line summary of a red run
#     cost a second run just to learn which test it was (2026-11-01).
set -u

tree=${1:-.}
cd "$tree" || exit 2
if [ ! -f Makefile ] || [ ! -d src ]; then echo "gate: $tree is not the sloth tree" >&2; exit 2; fi
mkdir -p build
LOG=${GATE_LOG:-build/gate.log}
: > "$LOG"

# One run per tree.
exec 9>build/gate.lock
if ! flock -n 9; then
    echo "gate: another gate run holds build/gate.lock in this tree; not starting a second" >&2
    exit 3
fi

tmp=${TMPDIR:-/tmp}
free_kb=$(df -Pk "$tmp" | awk 'NR == 2 { print $4 }')
if [ "${free_kb:-0}" -lt 1572864 ]; then
    echo "gate: $tmp has $((free_kb / 1024)) MB free, under the 1.5 GB the suite needs" >&2
    exit 3
fi

say() { printf '%s\n' "$*" | tee -a "$LOG"; }
# step NAME CMD...: run, keep the full output, print one summary line, and
# the FAIL / sanitizer lines when the step is red.
step() {
    name=$1; shift
    out=build/gate-$(printf '%s' "$name" | tr -c 'A-Za-z0-9' '_').log
    # `make clean` removes build/, and the step after one would fail on
    # its own redirect (rc=2, nothing run) rather than on the tree.
    mkdir -p build
    "$@" > "$out" 2>&1
    rc=$?
    line=$(grep -E 'assertions passed|slothweb tests:|deploy-test:|wiki-sync-test:|replay-check:|quickstart_check:' "$out" | tail -1)
    say "$name: rc=$rc ${line:-}"
    if [ "$rc" -ne 0 ] || printf '%s' "$line" | grep -qE '[1-9][0-9]* failed'; then
        grep -E '^ *FAIL|SUMMARY: (Address|Thread|Undefined|Leak)Sanitizer|runtime error|WARNING: ThreadSanitizer|error:' "$out" \
            | head -12 | sed 's/^/    /' | tee -a "$LOG"
        red=1
    fi
    cat "$out" >> "$LOG"
}

red=0
SAN='-Werror -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all'

say "gate: $(date -u +%FT%TZ) tree $(git rev-parse --short HEAD 2>/dev/null || echo ?) $(git status --short 2>/dev/null | grep -vc '^??' | sed 's/^/dirty=/')"
say "toolchain: $(${CC:-cc} --version | head -1); libpcap $(pkg-config --modversion libpcap 2>/dev/null || echo ?); sqlite3 $(pkg-config --modversion sqlite3 2>/dev/null || echo ?); shellcheck $(shellcheck --version 2>/dev/null | awk '/^version:/ { print $2 }'); $tmp $((free_kb / 1024)) MB free"

for cfg in "" WITH_NCURSES=0 WITH_PCAP=0 WITH_WIFI=0 WITH_SQLITE=0 embedded; do
    make -s clean > /dev/null 2>&1
    if [ "$cfg" = embedded ]; then
        step "build embedded" make -s embedded EXTRA_CFLAGS=-Werror
    else
        # shellcheck disable=SC2086
        step "build ${cfg:-default}" make -s $cfg EXTRA_CFLAGS=-Werror
    fi
done

make -s clean > /dev/null 2>&1
step "test" make test
step "test-capture-path" make test-capture-path
make -s clean > /dev/null 2>&1
step "test asan" make test EXTRA_CFLAGS="$SAN"
step "test-capture-path asan" make test-capture-path EXTRA_CFLAGS="$SAN"
make -s clean > /dev/null 2>&1
TSAN_OPTIONS=halt_on_error=1 step "test tsan" make test EXTRA_CFLAGS='-fsanitize=thread'

make -s clean > /dev/null 2>&1
step "web-test" make web-test EXTRA_CFLAGS=-Werror
if [ -n "${GATE_SQLITE345:-}" ]; then
    LD_LIBRARY_PATH=$GATE_SQLITE345 step "web-test sqlite-3.45" make web-test
fi
step "web-test WITH_SQLITE=0" make web-test WITH_SQLITE=0 EXTRA_CFLAGS=-Werror
emptyoui=$(mktemp -d "$tmp/gate-oui.XXXXXX")
step "web-test empty-oui" make web-test WEB_OUI_DIR="$emptyoui"
rmdir "$emptyoui"
step "web-quickstart-check" make web-quickstart-check
make -s clean > /dev/null 2>&1
step "web-test asan" make web-test EXTRA_CFLAGS="$SAN"
make -s clean > /dev/null 2>&1
TSAN_OPTIONS=halt_on_error=1 step "web-test tsan 1" make web-test EXTRA_CFLAGS='-fsanitize=thread'
TSAN_OPTIONS=halt_on_error=1 step "web-test tsan 2" make web-test EXTRA_CFLAGS='-fsanitize=thread'

step "deploy-test" make deploy-test
if [ -n "${GATE_SHELLCHECKS:-}" ]; then
    IFS=:; for d in $GATE_SHELLCHECKS; do
        [ -x "$d/shellcheck" ] || continue
        PATH="$d:$PATH" step "deploy-test shellcheck $("$d/shellcheck" --version | awk '/^version:/ { print $2 }')" make deploy-test
    done; unset IFS
fi

make -s clean > /dev/null 2>&1
make -s > /dev/null 2>&1
step "replay-check" make replay-check
step "fuzz" make fuzz FUZZ_SECONDS=1
step "cppcheck" make cppcheck
make docs-counts > /dev/null 2>&1
make research-index > /dev/null 2>&1
dirty=$(git status --short 2>/dev/null | grep -vc '^??')
say "tree dirty after docs-counts and research-index: $dirty"
[ "$dirty" -eq 0 ] || red=1

if [ "$red" -eq 0 ]; then say "gate: green"; else say "gate: RED (see $LOG)"; fi
exit "$red"
