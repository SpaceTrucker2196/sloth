#!/bin/sh
# The five-minute check (#164, M6): follow web/README.md's quick start
# literally, in a temporary copy of the tracked tree, and see the page
# answer. `make web-quickstart-check` runs it from the top of the tree.
#
# The commands are not restated here: they are read out of the README,
# from the sh fences between <!-- quickstart:begin --> and
# <!-- quickstart:end -->, and run as written with two changes, both
# because a check runs unattended: the last command (slothweb itself,
# which a reader leaves in the foreground) is started in the background
# with --web-bind 127.0.0.1:PORT appended, so the check neither blocks
# nor collides with a slothweb already on 8770; and TMPDIR points into
# the check's own directory, so the README's mktemp lands there. Then
# /api/health must say the stream is connected and sloth.db open, and
# / must be the page. Everything is removed afterwards.
#
# Loopback and a unix socket only; nothing leaves the host.
set -eu

top=$(pwd)
[ -f "$top/web/README.md" ] || { echo "quickstart_check: run from the top of the tree" >&2; exit 2; }
command -v curl >/dev/null || { echo "quickstart_check: needs curl" >&2; exit 2; }

# Absolute, so the run below (which cds into it) works under a relative
# TMPDIR too.
base=$(cd "$(mktemp -d "${TMPDIR:-/tmp}/slothweb-qs.XXXXXX")" && pwd)
pids=""
cleanup() {
    for p in $pids; do kill "$p" 2>/dev/null || true; done
    sleep 0.3
    rm -rf "$base"
}
# An interrupt exits, which runs cleanup once through EXIT, rather than
# carrying on against a removed tree.
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# The tree as git sees it, on disk now: tracked files with their
# uncommitted edits, and new files git does not ignore. Nothing built.
mkdir "$base/sloth" "$base/tmp"
(cd "$top" && git ls-files -z --cached --others --exclude-standard | xargs -0 tar -cf -) |
    tar -xf - -C "$base/sloth"

# The README's quick start.
awk '/<!-- quickstart:begin -->/ { on = 1; next }
     /<!-- quickstart:end -->/   { on = 0 }
     on && /^```sh/ { sh = 1; next }
     on && /^```/   { sh = 0; next }
     on && sh' "$top/web/README.md" > "$base/steps.sh"
[ -s "$base/steps.sh" ] || { echo "quickstart_check: no quick start in web/README.md" >&2; exit 1; }
last=$(grep -v '^[[:space:]]*\(#.*\)\{0,1\}$' "$base/steps.sh" | tail -n 1)
case "$last" in
*slothweb*--socket*) ;;
*) echo "quickstart_check: the quick start does not end by starting slothweb: $last" >&2; exit 1 ;;
esac

port=${SLOTHWEB_CHECK_PORT:-$((20000 + $$ % 20000))}
# Every line but the last as written; the last in the background on the
# check's port, its pid kept for the cleanup.
{
    echo 'set -e'
    sed '$d' "$base/steps.sh"
    echo "$last --web-bind 127.0.0.1:$port > \"$base/slothweb.log\" 2>&1 &"
    echo "echo \$! > \"$base/slothweb.pid\""
    echo "jobs -p > \"$base/jobs.pid\""
} > "$base/run.sh"
echo "quickstart_check: following web/README.md in $base/sloth"
sed 's/^/    /' "$base/steps.sh"
start=$(date +%s)
(cd "$base/sloth" && TMPDIR="$base/tmp" sh "$base/run.sh") > "$base/steps.log" 2>&1 || {
    echo "quickstart_check: a step failed:" >&2
    tail -n 30 "$base/steps.log" >&2
    exit 1
}
pids=$(cat "$base/slothweb.pid" "$base/jobs.pid" 2>/dev/null | tr '\n' ' ')

ok=0
i=0
while [ $i -lt 40 ]; do
    h=$(curl -s -m 2 "http://127.0.0.1:$port/api/health" || true)
    case "$h" in
    *'"socket":"connected"'*'"db":"open"'*) ok=1; break ;;
    esac
    sleep 0.5
    i=$((i + 1))
done
if [ $ok -ne 1 ]; then
    echo "quickstart_check: /api/health never said connected with sloth.db open:" >&2
    echo "$h" | head -c 600 >&2; echo >&2
    tail -n 20 "$base/slothweb.log" >&2
    exit 1
fi
page=$(curl -s -m 2 "http://127.0.0.1:$port/")
case "$page" in
*'<title>slothweb</title>'*) ;;
*) echo "quickstart_check: / is not the page" >&2; exit 1 ;;
esac
flows=$(curl -s -m 2 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/api/flows/graph")
[ "$flows" = 200 ] || { echo "quickstart_check: /api/flows/graph answered $flows" >&2; exit 1; }
echo "quickstart_check: ok in $(( $(date +%s) - start )) s: /api/health connected, sloth.db open; / is the page"
