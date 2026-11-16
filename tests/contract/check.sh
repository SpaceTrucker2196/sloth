#!/bin/sh
# make contract-check (#185 item 4): verify the contract artifact the
# way a consumer in another repository would see it.
#
#   tests/contract/check.sh TAR SLOTH_WIFI SLOTH_RF CONTRACT_DB
#
# 1. both daemons print the same --print-schema, and it is the shipped
#    schema.sql;
# 2. the tar unpacks to one directory named for it; SHA256SUMS verifies
#    and lists every file; MANIFEST.json's path, size and SHA-256 agree
#    with every file and lists every file, and its versions are the
#    tree's;
# 3. tests/contract/consumer.c compiles and links against the unpacked
#    headers, libsloth-wire.a and sloth-wire.pc alone, and decodes a
#    hand-built radiotap + beacon;
# 4. schema.sql loads into an in-memory database whose schema_version is
#    the MANIFEST's, and the golden sloth.db has exactly that schema;
# 5. a second `make contract` (another umask, a later second) gives the
#    same bytes.
#
# Everything is unpacked under one mktemp -d, removed on exit. No
# network. Each check prints one line; the first failure exits 1.
set -eu

[ "$#" -eq 4 ] || { echo "usage: $0 TAR SLOTH_WIFI SLOTH_RF CONTRACT_DB" >&2; exit 2; }
tar=$1 wifi=$2 rf=$3 cdb=$4
: "${MAKE:=make}" "${CC:=cc}" "${CFLAGS:=-O2}"

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
case $tar in /*) ;; *) tar=$root/$tar ;; esac
case $cdb in /*) ;; *) cdb=$root/$cdb ;; esac

tmp=$(mktemp -d "${TMPDIR:-/tmp}/sloth-contract.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM

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
ok "MANIFEST.json matches all $(wc -l < "$tmp/listed" | tr -d ' ') files and the tree's versions"

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

# ── 4. the schema and the golden database ──
v=$("$cdb" version "$d/schema/schema.sql") || fail "schema.sql does not load into an empty database"
[ "$v" = "$(field db_schema_version)" ] || fail "schema.sql records schema_version $v, the MANIFEST says $(field db_schema_version)"
ok "schema.sql loads; schema_version $v"
"$cdb" dump "$d/schema/schema.sql" > "$tmp/schema.dump" || fail "dump of schema.sql"
"$cdb" dump "$d/fixtures/sloth.db" > "$tmp/golden.dump" || fail "fixtures/sloth.db does not open"
[ -s "$tmp/schema.dump" ] || fail "schema.sql defines nothing"
cmp -s "$tmp/schema.dump" "$tmp/golden.dump" || fail "fixtures/sloth.db's schema is not schema.sql's"
[ "$("$cdb" version "$d/fixtures/sloth.db")" = "$v" ] || fail "fixtures/sloth.db's schema_version"
ok "fixtures/sloth.db has schema.sql's $(wc -l < "$tmp/schema.dump" | tr -d ' ') objects"

# ── 5. reproducible ──
cp "$tar" "$tmp/first.tar"
# A different umask and at least a second later: neither may reach the
# bytes. `sleep` is POSIX; the second is what makes a leaked wall-clock
# mtime show.
sleep 1
# MAKE is make's own variable, which may carry a path or flags.
# shellcheck disable=SC2086
(cd "$root" && umask 077 && $MAKE -s contract > "$tmp/second.log" 2>&1) ||
    { cat "$tmp/second.log" >&2; fail "the second make contract"; }
cmp "$tmp/first.tar" "$tar" || fail "two builds of one tree are not the same bytes"
ok "rebuilt: byte-identical ($(sha256sum "$tar" | cut -d' ' -f1))"

echo "contract-check: green"
