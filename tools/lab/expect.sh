#!/bin/sh
# expect.sh — after a #199 bench test, read beta-site's lab incident and
# judge it against the test's row of the matrix.
#
#   usage: tools/lab/expect.sh [--from-loopback] BASE_URL INCIDENT TEST
#          tools/lab/expect.sh --alerts-json FILE [--incident-json FILE] - INCIDENT TEST
#
#     BASE_URL     slothweb as a literal address: http://192.0.2.10:8080
#                  (no host names; the bench is two known hosts)
#     INCIDENT     the lab incident's id (#199 rule 4, opened before the run)
#     TEST         L1..L8
#
#   --from-loopback      curl --interface 127.0.0.1: for running ON the
#                        sensor against its own address
#   --alerts-json FILE   read /api/alerts' answer from FILE (one page)
#   --incident-json FILE read /api/frrs/incidents' answer from FILE
#
# Reads /api/alerts?incident=N (every page, state=all, the longest
# window) and /api/frrs/incidents?id=N, takes the union of the alert
# type names in the two, and prints one PASS/FAIL line per expected type
# and every type that was not expected. Read-only: two GETs.
#
# Exit 0 PASS; 1 FAIL; 2 usage or fetch error; 3 the row is not judged
# by beta-site's alerts (L7 is judged by w9fjc's listener, L8's rotation
# hints are not alert types).
set -u

me=expect
usage() { sed -n '5,17p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
err()   { echo "$me: $*" >&2; exit 2; }

loop=0
alerts_file=
inc_file=
while [ $# -gt 0 ]; do
    case $1 in
        --from-loopback) loop=1; shift ;;
        --alerts-json)   [ $# -ge 2 ] || usage; alerts_file=$2; shift 2 ;;
        --incident-json) [ $# -ge 2 ] || usage; inc_file=$2; shift 2 ;;
        -h|--help)       usage ;;
        --)              shift; break ;;
        -?*)             echo "$me: unknown option $1" >&2; usage ;;
        *)               break ;;
    esac
done
[ $# -eq 3 ] || usage
base=$1 inc=$2 test_id=$3

case $inc in ''|0*|*[!0-9]*) err "incident must be a positive number, not '$inc'" ;; esac
[ "${#inc}" -le 15 ] || err "incident id too long"
case $test_id in L[1-8]) ;; *) err "test must be L1..L8, not '$test_id'" ;; esac
command -v python3 >/dev/null 2>&1 || err "needs python3"

# The expectations, from #199's matrix. Space-separated groups; a|b is
# any one of them; ?X is reported but not required. "-" is a row that
# must raise nothing; "n/a" one these alerts do not judge.
expect_of() {
    case $1 in
        L1) echo "-" ;;
        L2) echo "EVIL_TWIN ?EVIL_TWIN_PROXIMITY" ;;
        L3) echo "KARMA_AP KARMA_PROBE_FORGE" ;;
        L4) echo "BEACON_FLOOD" ;;
        L5) echo "PMKID_HARVEST|HANDSHAKE_HARVEST" ;;
        L6) echo "ATTACK_PATH ATTACK_TOOL_UA" ;;
        L7) echo "n/a" ;;
        L8) echo "n/a" ;;
    esac
}
want=$(expect_of "$test_id")

tmp=$(mktemp -d "${TMPDIR:-/tmp}/sloth-expect.XXXXXX") || err "mktemp failed"
trap 'rm -rf "$tmp"' EXIT INT TERM HUP

if [ -n "$alerts_file" ]; then
    [ -r "$alerts_file" ] || err "cannot read $alerts_file"
    cp "$alerts_file" "$tmp/alerts.1"
    if [ -n "$inc_file" ]; then
        [ -r "$inc_file" ] || err "cannot read $inc_file"
        cp "$inc_file" "$tmp/incident"
    fi
else
    [ -z "$inc_file" ] || err "--incident-json goes with --alerts-json"
    case $base in
        http://*|https://*) ;;
        *) err "BASE_URL is http://ADDRESS:PORT, not '$base'" ;;
    esac
    hostport=${base#*://}
    hostport=${hostport%/}
    if ! echo "$hostport" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}$' &&
       ! echo "$hostport" | grep -Eq '^\[[0-9A-Fa-f:]+\]:[0-9]{1,5}$'; then
        err "BASE_URL must be a literal address and port, not '$base'"
    fi
    command -v curl >/dev/null 2>&1 || err "needs curl"
    base=${base%/}
    get() {   # $1 = path and query, $2 = output file
        if [ "$loop" -eq 1 ]; then
            curl -fsS --max-time 15 --interface 127.0.0.1 "$base$1" -o "$2"
        else
            curl -fsS --max-time 15 "$base$1" -o "$2"
        fi
    }
    off=0
    page=1
    while :; do
        get "/api/alerts?incident=$inc&state=all&window=34560000&limit=100&offset=$off" \
            "$tmp/alerts.$page" || err "GET /api/alerts failed"
        off=$(python3 -I -c '
import json, sys
d = json.load(open(sys.argv[1]))
n = d.get("next_offset")
print(n if d.get("more") and isinstance(n, int) else "")' "$tmp/alerts.$page") ||
            err "/api/alerts answered something that is not its JSON"
        [ -n "$off" ] || break
        page=$((page + 1))
        [ "$page" -le 50 ] || err "more than 50 pages of alerts in incident $inc"
    done
    get "/api/frrs/incidents?id=$inc" "$tmp/incident" || err "GET /api/frrs/incidents?id=$inc failed"
fi

python3 -I -c '
import glob, json, os, sys
tmp, inc, test, want = sys.argv[1:]
seen = {}
for p in sorted(glob.glob(os.path.join(tmp, "alerts.*"))):
    try:
        d = json.load(open(p))
    except ValueError:
        print("expect: %s is not JSON" % os.path.basename(p), file=sys.stderr); sys.exit(2)
    for r in d.get("rows") or []:
        t = r.get("type_name")
        if isinstance(t, str) and t:
            seen.setdefault(t, set()).add("alerts")
ip = os.path.join(tmp, "incident")
if os.path.exists(ip):
    try:
        d = json.load(open(ip))
    except ValueError:
        print("expect: the incident answer is not JSON", file=sys.stderr); sys.exit(2)
    i = d.get("incident") or {}
    print("incident %s: %s, state %s, %s" % (i.get("id", inc), json.dumps(i.get("title")),
          i.get("state"), "open" if i.get("open") else "closed"))
    for m in d.get("members") or []:
        t = m.get("type")
        if m.get("kind") == "alert" and isinstance(t, str) and t:
            seen.setdefault(t, set()).add("members")
print("test %s, expecting: %s" % (test, want))
if want == "n/a":
    print("NOT JUDGED  %s is not judged by beta-site alerts (#199: L7 by w9fjc'"'"'s listener, L8 rotation hints are estimates, not alerts)" % test)
    for t in sorted(seen):
        print("  seen      %s" % t)
    sys.exit(3)
ok = True
expected = set()
if want == "-":
    if seen:
        ok = False
        print("FAIL        baseline must raise nothing")
    else:
        print("PASS        nothing raised (baseline)")
else:
    for g in want.split():
        opt = g.startswith("?")
        alts = g.lstrip("?").split("|")
        expected.update(alts)
        hit = [a for a in alts if a in seen]
        if hit:
            print("PASS        %s" % " | ".join("%s (%s)" % (a, ",".join(sorted(seen[a]))) for a in hit))
        elif opt:
            print("absent      %s (optional)" % g[1:])
        else:
            ok = False
            print("FAIL        %s not raised" % g)
for t in sorted(set(seen) - expected):
    print("unexpected  %s (%s)" % (t, ",".join(sorted(seen[t]))))
print("RESULT      %s" % ("PASS" if ok else "FAIL"))
sys.exit(0 if ok else 1)
' "$tmp" "$inc" "$test_id" "$want"
