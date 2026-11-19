#!/bin/sh
# make contract-check (#185 item 4): verify the contract artifact the
# way a consumer in another repository would see it.
#
#   tests/contract/check.sh TAR SLOTH_WIFI SLOTH_RF CONTRACT_DB CONTRACT_PARITY
#
# 1. both daemons print the same --print-schema, and it is the shipped
#    schema.sql;
# 2. the tar's own checksum file verifies; the tar unpacks to one
#    directory named for it; SHA256SUMS verifies and lists every file;
#    MANIFEST.json is valid JSON whose path, size and SHA-256 agree with
#    every file and lists every file, and its versions are the tree's;
#    the copied payloads are the tree's files, byte for byte; the alert
#    bundle's text holds no MAC address outside
#    tests/contract/allowed-macs.txt and no home-directory path;
#    palette.json is valid JSON with the tree's IP palette size;
#    alert-daemons.tsv lists every kind in order and its per-daemon
#    counts are the tree's count markers; every parity/ file is what
#    tools/contract_parity.c writes from the tree now, and has rows;
# 3. tests/contract/consumer.c compiles and links against the unpacked
#    headers, libsloth-wire.a and sloth-wire.pc alone, and decodes a
#    hand-built radiotap + beacon; the functions the shipped headers
#    declare and the archive does not define are exactly
#    tests/contract/declared-not-defined.txt;
# 4. schema.sql loads into an in-memory database whose schema_version is
#    the MANIFEST's, and the golden sloth.db has exactly that schema, is
#    auto_vacuum=INCREMENTAL, and holds no row but meta's one;
# 5. a second `make contract` (another umask, time zone and locale, a
#    later second) gives the same bytes.
#
# Everything is unpacked under one mktemp -d, removed on exit. No
# network. Each check prints one line; the first failure exits 1.
set -eu

[ "$#" -eq 5 ] || { echo "usage: $0 TAR SLOTH_WIFI SLOTH_RF CONTRACT_DB CONTRACT_PARITY" >&2; exit 2; }
tar=$1 wifi=$2 rf=$3 cdb=$4 parity=$5
: "${MAKE:=make}" "${CC:=cc}" "${CFLAGS:=-O2}"

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
case $tar in /*) ;; *) tar=$root/$tar ;; esac
case $cdb in /*) ;; *) cdb=$root/$cdb ;; esac
case $parity in /*) ;; *) parity=$root/$parity ;; esac

tmp=$(mktemp -d "${TMPDIR:-/tmp}/sloth-contract.XXXXXX")
# A signal exits (and the EXIT trap cleans up); a trap that only
# removed the directory would let dash carry on after a TERM.
trap 'rm -rf "$tmp"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

fail() { echo "contract-check: FAIL $*" >&2; exit 1; }
ok() { echo "contract-check: ok   $*"; }

# ── 1. the flag, in both daemons ──
"$wifi" --print-schema > "$tmp/wifi.sql" || fail "sloth-wifi --print-schema exited $?"
"$rf" --print-schema > "$tmp/rf.sql" || fail "sloth-rf --print-schema exited $?"
[ -s "$tmp/wifi.sql" ] || fail "sloth-wifi --print-schema printed nothing"
cmp -s "$tmp/wifi.sql" "$tmp/rf.sql" || fail "sloth-wifi and sloth-rf print different schemas"
ok "sloth-wifi and sloth-rf --print-schema identical"

# ── 2. unpack, SHA256SUMS, MANIFEST.json ──
name=$(basename "$tar" .tar)
# The release asset beside the tar: what a downloader checks first.
(cd "$(dirname "$tar")" && sha256sum -c --quiet "$name.SHA256SUMS") ||
    fail "$name.SHA256SUMS does not verify the tar"
ok "$name.SHA256SUMS verifies the tar"
mkdir "$tmp/x"
tar -C "$tmp/x" -xf "$tar"
set -- "$tmp/x"/* "$tmp/x"/.[!.]*
if [ "$1" != "$tmp/x/$name" ] || [ -e "${2:-}" ] || [ -e "${3:-}" ]; then
    fail "the tar holds something beside one $name/"
fi
d=$tmp/x/$name
(cd "$d" && sha256sum -c --quiet SHA256SUMS) || fail "SHA256SUMS does not verify"
(cd "$d" && find . -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort) > "$tmp/files"
sed 's/^[0-9a-f]*  //' "$d/SHA256SUMS" | LC_ALL=C sort > "$tmp/summed"
cmp -s "$tmp/files" "$tmp/summed" || fail "SHA256SUMS does not list exactly the files in the archive"
ok "SHA256SUMS verifies and covers $(wc -l < "$tmp/files" | tr -d ' ') files"

m=$d/MANIFEST.json
# Valid JSON first (SQLite's strict RFC 8259 json_valid()): the sed
# reads below are line-shaped and would accept a trailing comma.
[ "$("$cdb" jsql "$m" 'SELECT json_valid(?1)')" = 1 ] || fail "MANIFEST.json is not valid JSON"
sed -n 's/^ *{"path": "\([^"]*\)", "size": \([0-9]*\), "sha256": "\([0-9a-f]*\)"},*$/\1 \2 \3/p' "$m" > "$tmp/listed"
while read -r p size sum; do
    [ -f "$d/$p" ] || fail "MANIFEST.json lists $p, which is not in the archive"
    [ "$(wc -c < "$d/$p" | tr -d ' ')" = "$size" ] || fail "MANIFEST.json size of $p"
    [ "$(sha256sum "$d/$p" | cut -d' ' -f1)" = "$sum" ] || fail "MANIFEST.json sha256 of $p"
done < "$tmp/listed"
cut -d' ' -f1 "$tmp/listed" | LC_ALL=C sort > "$tmp/manifested"
grep -v '^MANIFEST\.json$' "$tmp/files" > "$tmp/payload"
cmp -s "$tmp/payload" "$tmp/manifested" || fail "MANIFEST.json does not list exactly the files in the archive"
field() { sed -n "s/^  \"$1\": \"*\([^\",]*\)\"*,*\$/\1/p" "$m"; }
[ "$(field contract_format)" = 1 ] || fail "contract_format is not 1"
want=$(sed -n 's/^#define SLOTH_VERSION "\(.*\)"$/\1/p' "$root/include/sloth.h")
[ "$(field sloth_version)" = "$want" ] || fail "sloth_version is not $want"
[ "$name" = "sloth-contract-$want" ] || fail "the tar is not named for SLOTH_VERSION $want"
want=$(sed -n 's/^#define SLOTH_JSONL_VERSION "\(.*\)"$/\1/p' "$root/include/sloth.h")
[ "$(field jsonl_version)" = "$want" ] || fail "jsonl_version is not $want"
want=$(sed -n 's/^#define DB_SCHEMA_VERSION \([0-9]*\).*/\1/p' "$root/src/db.h")
[ "$(field db_schema_version)" = "$want" ] || fail "db_schema_version is not $want"
[ "$("$cdb" jsql "$m" "SELECT json_array_length(?1, '\$.files')")" = "$(wc -l < "$tmp/listed" | tr -d ' ')" ] ||
    fail "MANIFEST.json's files array and its lines disagree"
ok "MANIFEST.json matches all $(wc -l < "$tmp/listed" | tr -d ' ') files and the tree's versions"

# The copies are the tree's files. The sums above only prove the archive
# agrees with itself; a wrong file checksummed consistently passes them.
same() { cmp -s "$root/$1" "$d/$2" || fail "$2 is not the tree's $1"; }
same docs/wiki/jsonl-schema.md jsonl/jsonl-schema.md
same docs/wiki/sqlite-schema.md schema/sqlite-schema.md
same tests/replay/golden.jsonl fixtures/golden.jsonl
same include/jsonl_ptr_fixture.h fixtures/jsonl_ptr_fixture.h
for h in "$d"/include/sloth-wire/*.h; do
    h=${h##*/}
    same "src/$h" "include/sloth-wire/$h"
done
for f in include/sloth_alerts.def docs/views/alerts.md docs/wiki/alerts.md \
         docs/wiki/alert-remediation.md research.db; do
    same "$f" "alerts/$f"
done
(cd "$root" && git ls-files 'docs/wiki/alert-assessments/*.md' 'research/*.md') |
    LC_ALL=C sort > "$tmp/kb.tree" || fail "git ls-files"
(cd "$d/alerts" && find docs/wiki/alert-assessments research -type f) | LC_ALL=C sort > "$tmp/kb.tar"
if ! [ -s "$tmp/kb.tree" ] || ! cmp -s "$tmp/kb.tree" "$tmp/kb.tar"; then
    fail "alerts/ does not hold exactly the tracked assessments and research documents"
fi
while read -r f; do same "$f" "alerts/$f"; done < "$tmp/kb.tree"
ok "payloads are the tree's ($(wc -l < "$tmp/kb.tree" | tr -d ' ') assessment and research documents)"

# No host data rides out on a release asset: no MAC-shaped string but
# tests/contract/allowed-macs.txt's, and no home-directory path. The
# text files are read; research.db is not, because its rows are the
# research documents' text (it is the tree's file, above, and the gate
# fails when research-index would change it) and its record headers
# hold byte pairs such as "~/" by coincidence.
find "$d/alerts" -type f ! -name research.db > "$tmp/kbtext"
xargs grep -hoiE '([0-9a-f]{2}:){5}[0-9a-f]{2}' < "$tmp/kbtext" | tr 'A-F' 'a-f' |
    LC_ALL=C sort -u > "$tmp/macs"
grep -v '^#' "$here/allowed-macs.txt" | LC_ALL=C sort -u > "$tmp/macs.ok"
LC_ALL=C comm -23 "$tmp/macs" "$tmp/macs.ok" > "$tmp/macs.bad"
if [ -s "$tmp/macs.bad" ]; then
    cat "$tmp/macs.bad" >&2
    fail "alerts/ carries MAC addresses not in tests/contract/allowed-macs.txt"
fi
if xargs grep -lE '[~]/|/home/' < "$tmp/kbtext" > "$tmp/homes"; then
    cat "$tmp/homes" >&2
    fail "alerts/ carries a home-directory path"
fi
ok "alerts/ carries no host MAC address or home-directory path"

p=$d/palette/palette.json
[ "$("$cdb" jsql "$p" 'SELECT json_valid(?1)')" = 1 ] || fail "palette.json is not valid JSON"
want=$(sed -n 's/^#define IP_NUM_COLORS \([0-9]*\).*/\1/p' "$root/src/ip_color.h")
[ "$("$cdb" jsql "$p" "SELECT json_extract(?1, '\$.ip_colors')")" = "$want" ] ||
    fail "palette.json's ip_colors is not IP_NUM_COLORS $want"
bad=$("$cdb" jsql "$p" "SELECT count(*) FROM json_each(?1, '\$.tokens')
    WHERE json_extract(value, '\$.hex') NOT GLOB '#[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]'
       OR json_type(value, '\$.xterm') != 'integer'
       OR json_extract(value, '\$.xterm') NOT BETWEEN 0 AND 255
       OR json_type(value, '\$.name') != 'text'")
ntok=$("$cdb" jsql "$p" "SELECT json_array_length(?1, '\$.tokens')")
if [ "$bad" != 0 ] || [ "${ntok:-0}" -lt "$want" ]; then
    fail "palette.json's tokens ($ntok, $bad malformed)"
fi
ok "palette.json is valid; $ntok tokens, ip_colors $want"

# alert-daemons.tsv: every kind of sloth_alerts.def, in order, ty 0..n-1,
# and the per-daemon totals are the count markers docs_counts.sh keeps
# in docs/wiki/alerts.md (wifi = sloth-wifi + both, rf = sloth-rf + both).
t=$d/alerts/alert-daemons.tsv
sed -n 's/^X(\([A-Z0-9_]*\),.*/\1/p' "$root/include/sloth_alerts.def" > "$tmp/kinds"
grep -v '^#' "$t" | sed 1d > "$tmp/tsv"
awk -F '\t' '$1 != NR - 1 || ($3 != "sloth-wifi" && $3 != "sloth-rf" && $3 != "both") { exit 1 }' \
    "$tmp/tsv" || fail "alert-daemons.tsv: ty not 0..n-1, or an unknown raised_by"
cut -f2 "$tmp/tsv" | cmp -s - "$tmp/kinds" || fail "alert-daemons.tsv does not list sloth_alerts.def's kinds in order"
marker() { sed -n "s/.*<!-- count:$1 -->\([0-9]*\)<!-- \/count -->.*/\1/p" "$root/docs/wiki/alerts.md" | sed -n 1p; }
nw=$(awk -F '\t' '$3 != "sloth-rf"' "$tmp/tsv" | wc -l | tr -d ' ')
nr=$(awk -F '\t' '$3 != "sloth-wifi"' "$tmp/tsv" | wc -l | tr -d ' ')
if [ "$nw" != "$(marker rules-wifi)" ] || [ "$nr" != "$(marker rules-rf)" ]; then
    fail "alert-daemons.tsv: sloth-wifi $nw, sloth-rf $nr; the tree's markers say $(marker rules-wifi), $(marker rules-rf)"
fi
ok "alert-daemons.tsv: $(wc -l < "$tmp/tsv" | tr -d ' ') kinds; sloth-wifi raises $nw, sloth-rf $nr"

# parity/ (sloth#233): each file is what the tool writes from this tree
# now (a pin that stopped holding fails the tool itself), and none is
# empty past its header.
for pf in constants akm-names ip-color literals pins fire-sites; do
    case $pf in
        constants) set -- constants ;;
        akm-names) set -- akm ;;
        ip-color)  set -- ipcolor ;;
        literals)  set -- literals tests/contract/literals.txt ;;
        pins)      set -- pins tests/contract/pins.tsv ;;
        fire-sites)
            set -- fires src/alerts/rules_ble.c src/alerts/rules_camera.c \
                src/alerts/rules_enterprise.c src/alerts/rules_gnss.c src/alerts/rules_mle.c \
                src/alerts/rules_regulatory.c src/alerts/rules_twin.c \
                src/alerts/rules_wifi_mgmt.c src/alerts/rules_wired.c ;;
    esac
    (cd "$root" && "$parity" "$@") > "$tmp/parity.$pf" || fail "contract_parity $1 on the tree"
    cmp -s "$tmp/parity.$pf" "$d/parity/$pf.tsv" || fail "parity/$pf.tsv is not what the tree gives now"
    [ "$(grep -cv '^#' "$d/parity/$pf.tsv")" -ge 2 ] || fail "parity/$pf.tsv has no rows"
done
[ "$(grep -cv '^#' "$d/parity/akm-names.tsv")" = 257 ] || fail "parity/akm-names.tsv is not 256 suite types"
ok "parity/: six files, each the tree's ($(grep -cv '^#' "$d/parity/pins.tsv") pin lines hold)"

cmp -s "$tmp/wifi.sql" "$d/schema/schema.sql" || fail "schema.sql is not what sloth-wifi --print-schema prints"
ok "schema.sql is the daemon's"

# ── 3. a consumer of the unpacked archive alone ──
cp "$here/consumer.c" "$tmp/consumer.c"
pc=$d/lib/pkgconfig
cflags=$(PKG_CONFIG_PATH=$pc pkg-config --cflags sloth-wire) || fail "pkg-config cannot read sloth-wire.pc"
libs=$(PKG_CONFIG_PATH=$pc pkg-config --libs sloth-wire)
[ "$(PKG_CONFIG_PATH=$pc pkg-config --modversion sloth-wire)" = "$(field sloth_version)" ] ||
    fail "sloth-wire.pc's Version is not the MANIFEST's sloth_version"
# Only the unpacked tree: no -I of this repository, and cd'd away from
# it, so a quote include cannot find a header beside the source either.
# shellcheck disable=SC2086
(cd "$tmp" && $CC $CFLAGS -Werror $cflags -o consumer consumer.c $libs) ||
    fail "the consumer does not build against the unpacked archive"
"$tmp/consumer" || fail "the consumer's decode"
ok "consumer built from sloth-wire.pc alone and decoded the beacon"

# What a header promises and the archive cannot link. A consumer that
# calls such a function compiles and then fails to link, so the set is
# pinned: it may change only with tests/contract/declared-not-defined.txt
# and the gap it records in docs/wiki/contract.md. GCC's -aux-info lists
# every prototype with the file it came from; another compiler cannot
# run this step, and it fails rather than skipping.
: "${NM:=nm}"
for h in "$d"/include/sloth-wire/*.h; do
    h=${h##*/}
    (cd "$d/include/sloth-wire" && $CC -std=c99 -fsyntax-only -aux-info "$tmp/aux1" -x c "$h") ||
        fail "$CC -aux-info on $h (this step needs GCC)"
    cat "$tmp/aux1" >> "$tmp/aux"
done
sed -n 's/^\/\* \([^/:]*\.h\):[0-9]*:[A-Z]* \*\/ extern [^(]*[ *]\([A-Za-z_][A-Za-z0-9_]*\) (.*/\1 \2/p' \
    "$tmp/aux" | LC_ALL=C sort -u > "$tmp/declared"
[ -s "$tmp/declared" ] || fail "no prototype read from the shipped headers"
$NM -g --defined-only "$d/lib/libsloth-wire.a" | awk 'NF == 3 { print $3 }' | LC_ALL=C sort -u > "$tmp/defined"
awk 'NR == FNR { d[$1] = 1; next } !($2 in d)' "$tmp/defined" "$tmp/declared" > "$tmp/undef"
grep -v '^#' "$here/declared-not-defined.txt" | cmp -s - "$tmp/undef" || {
    grep -v '^#' "$here/declared-not-defined.txt" | diff - "$tmp/undef" >&2 || true
    fail "declared-but-undefined functions are not tests/contract/declared-not-defined.txt"
}
ok "$(wc -l < "$tmp/declared" | tr -d ' ') declared functions; the $(wc -l < "$tmp/undef" | tr -d ' ') the archive does not define are the pinned list"

# ── 4. the schema and the golden database ──
v=$("$cdb" version "$d/schema/schema.sql") || fail "schema.sql does not load into an empty database"
[ "$v" = "$(field db_schema_version)" ] || fail "schema.sql records schema_version $v, the MANIFEST says $(field db_schema_version)"
ok "schema.sql loads; schema_version $v"
"$cdb" dump "$d/schema/schema.sql" > "$tmp/schema.dump" || fail "dump of schema.sql"
"$cdb" dump "$d/fixtures/sloth.db" > "$tmp/golden.dump" || fail "fixtures/sloth.db does not open"
[ -s "$tmp/schema.dump" ] || fail "schema.sql defines nothing"
cmp -s "$tmp/schema.dump" "$tmp/golden.dump" || fail "fixtures/sloth.db's schema is not schema.sql's"
[ "$("$cdb" version "$d/fixtures/sloth.db")" = "$v" ] || fail "fixtures/sloth.db's schema_version"
# Empty, and made as db_open() makes a file: auto_vacuum=INCREMENTAL (2)
# set before the first table; no row but schema.sql's own meta row.
"$cdb" facts "$d/schema/schema.sql" | grep '^rows ' > "$tmp/sql.rows" || true
[ "$(cat "$tmp/sql.rows")" = "rows meta 1" ] || fail "schema.sql inserts more than the meta row"
"$cdb" facts "$d/fixtures/sloth.db" > "$tmp/golden.facts" || fail "facts of fixtures/sloth.db"
[ "$(cat "$tmp/golden.facts")" = "$(printf 'auto_vacuum 2\nrows meta 1')" ] ||
    fail "fixtures/sloth.db is not empty or not auto_vacuum=INCREMENTAL: $(tr '\n' ' ' < "$tmp/golden.facts")"
ok "fixtures/sloth.db has schema.sql's $(wc -l < "$tmp/schema.dump" | tr -d ' ') objects"

# ── 5. reproducible ──
cp "$tar" "$tmp/first.tar"
# A different umask, time zone and locale, and at least a second later:
# none may reach the bytes. `sleep` is POSIX; the second is what makes a
# leaked wall-clock mtime show. Not varied here: the checkout's path (a
# hand check of two clones at different paths gave the same bytes; see
# docs/wiki/contract.md).
sleep 1
# MAKE is make's own variable, which may carry a path or flags.
# shellcheck disable=SC2086
(cd "$root" && umask 077 && TZ=Pacific/Chatham LC_ALL=C.UTF-8 \
    $MAKE -s contract > "$tmp/second.log" 2>&1) ||
    { cat "$tmp/second.log" >&2; fail "the second make contract"; }
cmp "$tmp/first.tar" "$tar" || fail "two builds of one tree are not the same bytes"
ok "rebuilt: byte-identical ($(sha256sum "$tar" | cut -d' ' -f1))"

echo "contract-check: green"
