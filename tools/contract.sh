#!/bin/sh
# Build the sensor's contract artifact (#185 item 4, #184 §2 C1-C5, C9).
# Run as `make contract`, which builds the inputs this script names and
# passes them in; see docs/wiki/contract.md for what the archive holds
# and why each decision was made.
#
#   tools/contract.sh VERSION SLOTH_WIFI PALETTE_GEN CONTRACT_DB \
#                     "WIRE_SRCS" "WIRE_HDRS" CONTRACT_PARITY
#
# Environment: CC, AR, CONTRACT_CFLAGS (from the Makefile);
# SOURCE_DATE_EPOCH (default: the HEAD commit's time).
#
# Output: dist/sloth-contract-VERSION.tar and
# dist/sloth-contract-VERSION.SHA256SUMS (the tar's line alone, in
# sha256sum's format: the release asset beside it, named for the tar so
# it never collides with the release's own SHA256SUMS of the binaries). Reproducible: the same commit
# built with the same toolchain gives the same bytes. Everything is
# rebuilt from scratch on every run, so no stale object or stale fixture
# can stand in for a fresh one: entries sorted by name, every mtime
# SOURCE_DATE_EPOCH, owner and group 0 by number, modes normalised
# (u=rwX,go=rX) whatever the umask, the archive written with ar's
# deterministic mode, objects compiled with no debug information and
# with the tree's path mapped away.
set -eu

[ "$#" -eq 7 ] || { echo "usage: $0 VERSION SLOTH_WIFI PALETTE_GEN CONTRACT_DB WIRE_SRCS WIRE_HDRS CONTRACT_PARITY" >&2; exit 2; }
version=$1 wifi=$2 palgen=$3 cdb=$4 wire_srcs=$5 wire_hdrs=$6 parity=$7
: "${CC:=cc}" "${AR:=ar}" "${CONTRACT_CFLAGS:=-O2 -std=c99}"

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    SOURCE_DATE_EPOCH=$(git log -1 --format=%ct 2> /dev/null || true)
    [ -n "$SOURCE_DATE_EPOCH" ] || {
        echo "contract: no git history to date the archive by; set SOURCE_DATE_EPOCH" >&2
        exit 1
    }
fi
case $SOURCE_DATE_EPOCH in
    ''|*[!0-9]*) echo "contract: SOURCE_DATE_EPOCH must be whole seconds" >&2; exit 1 ;;
esac
commit=$(git rev-parse HEAD 2> /dev/null || echo unknown)
dirty=false
if [ "$commit" != unknown ] && [ -n "$(git status --porcelain --untracked-files=no 2> /dev/null)" ]; then
    dirty=true
fi

jsonl_version=$(sed -n 's/^#define SLOTH_JSONL_VERSION "\(.*\)"$/\1/p' include/sloth.h)
name=sloth-contract-$version
work=build/contract
stage=$work/stage/$name
rm -rf "$work"
mkdir -p "$stage/include/sloth-wire" "$stage/lib/pkgconfig" "$stage/schema" \
         "$stage/jsonl" "$stage/palette" "$stage/alerts" "$stage/fixtures" \
         "$stage/parity" "$work/obj" dist

# ── libsloth-wire.a: exactly the sources slothweb links (CONTRACT_WIRE_SRCS) ──
objs=
for src in $wire_srcs; do
    obj=$work/obj/$(basename "$src" .c).o
    # Word splitting of CONTRACT_CFLAGS is intended: it is a flag list.
    # shellcheck disable=SC2086
    $CC $CONTRACT_CFLAGS -c -o "$obj" "$src"
    objs="$objs $obj"
done
# shellcheck disable=SC2086
$AR rcD "$stage/lib/libsloth-wire.a" $objs
for h in $wire_hdrs; do
    cp "$h" "$stage/include/sloth-wire/"
done
cat > "$stage/lib/pkgconfig/sloth-wire.pc" <<EOF
prefix=\${pcfiledir}/../..
libdir=\${prefix}/lib
includedir=\${prefix}/include/sloth-wire

Name: sloth-wire
Description: sloth's leaf wire parsers (radiotap, 802.11 frame and elements, DNS wire format, band plan, RF model)
Version: $version
Cflags: -I\${includedir}
Libs: -L\${libdir} -lsloth-wire -lm
EOF

# ── schema.sql: printed by the daemon, not copied from the source ──
"$wifi" --print-schema > "$stage/schema/schema.sql"
db_version=$(sed -n 's/^-- sloth database schema, DB_SCHEMA_VERSION \([0-9]*\) .*/\1/p' \
                 "$stage/schema/schema.sql")
[ -n "$db_version" ] || { echo "contract: --print-schema named no DB_SCHEMA_VERSION" >&2; exit 1; }
# The schema page whose recipes the SQL box offers (sloth-mesh's
# tools/recipes.c reads its "## Recipes" fences), as in the tree.
cp docs/wiki/sqlite-schema.md "$stage/schema/sqlite-schema.md"

# ── the record contract and the palette ──
cp docs/wiki/jsonl-schema.md "$stage/jsonl/jsonl-schema.md"
"$palgen" json src/tui.c "$stage/palette/palette.json"

# ── the alert knowledge bundle, at its tree paths under alerts/ ──
# Paths are kept so each generator's arguments are the same paths with
# a prefix (sloth-mesh's tools/alertkb.c, sloth-mesh's tools/alertasm.c).
copy_tree() {   # copy_tree FILE... into alerts/, keeping the path
    for f in "$@"; do
        mkdir -p "$stage/alerts/$(dirname "$f")"
        cp "$f" "$stage/alerts/$f"
    done
}
copy_tree include/sloth_alerts.def docs/views/alerts.md docs/wiki/alerts.md \
          docs/wiki/alert-remediation.md research.db
# Tracked files only: an operator's scratch note under research/ is not
# part of a release. LC_ALL=C so the order never depends on a locale.
# Listed first and checked, because a command substitution used as
# arguments escapes set -e: outside a git checkout this would otherwise
# write a tar with no assessments and no research corpus, and say
# nothing. Each half must be non-empty.
kb=$(git ls-files 'docs/wiki/alert-assessments/*.md' 'research/*.md') || {
    echo "contract: git ls-files failed; the alert bundle needs a git checkout" >&2
    exit 1
}
kb=$(printf '%s\n' "$kb" | LC_ALL=C sort)
n_asm=$(printf '%s\n' "$kb" | grep -c '^docs/wiki/alert-assessments/' || true)
n_res=$(printf '%s\n' "$kb" | grep -c '^research/' || true)
if [ "$n_asm" -eq 0 ] || [ "$n_res" -eq 0 ]; then
    echo "contract: git lists $n_asm assessments and $n_res research documents" >&2
    exit 1
fi
# shellcheck disable=SC2086
copy_tree $kb

# Which daemon raises each kind, from the two rule tables. The model
# tools/docs_counts.sh and tests/test_docs_consistency.c hold the
# count markers to: sloth-rf's table (src/alerts/rules_table_rf.c) has
# one row per kind, rule_<kind>; a kind there that sloth-wifi's table
# (src/alerts/rules_table.c) also lists is both daemons'; every other
# kind in the shared list is sloth-wifi's.
tab=$(printf '\t')
rf_rows=$(sed -n 's/^[[:space:]]*R(\(rule_[a-z0-9_]*\)),.*/\1/p' src/alerts/rules_table_rf.c)
{
    printf '# Which daemon raises each alert kind. ty is the persisted number\n'
    printf '# (the row of include/sloth_alerts.def, JSONL "ty"); kind is\n'
    printf '# ALERT_TYPE_<kind>. Generated by tools/contract.sh from\n'
    printf '# src/alerts/rules_table.c and src/alerts/rules_table_rf.c.\n'
    printf 'ty\tkind\traised_by\n'
    ty=0
    sed -n 's/^X(\([A-Z0-9_]*\),.*/\1/p' include/sloth_alerts.def | while read -r kind; do
        by=sloth-wifi
        lower=$(printf '%s' "$kind" | tr '[:upper:]' '[:lower:]')
        for r in $rf_rows; do
            if [ "$r" = "rule_$lower" ]; then
                if grep -q "^[[:space:]]*R($r)," src/alerts/rules_table.c; then by=both; else by=sloth-rf; fi
            fi
        done
        printf '%d\t%s\t%s\n' "$ty" "$kind" "$by"
        ty=$((ty + 1))
    done
} > "$stage/alerts/alert-daemons.tsv"
# Fail closed: a sloth-rf row whose name is not a kind would otherwise
# vanish from the file and leave its kind attributed to sloth-wifi.
for r in $rf_rows; do
    kind=$(printf '%s' "${r#rule_}" | tr '[:lower:]' '[:upper:]')
    awk -F "$tab" -v k="$kind" '$2 == k && $3 != "sloth-wifi" { f = 1 } END { exit !f }' \
        "$stage/alerts/alert-daemons.tsv" || {
        echo "contract: sloth-rf's $r names no kind in include/sloth_alerts.def" >&2
        exit 1
    }
done

# ── parity: the facts a consumer's tests hold its copies to (sloth#233) ──
# Values compiled from the headers, rsn_akm_name() whole, the colour
# hash on fixed keys, the string literals and pinned lines of the files
# tests/contract/ names (a pin that no longer holds stops the build), and
# the fire() sites of the rule files whose severities the dashboard's
# rule table is held to. docs/wiki/contract.md, "parity/".
"$parity" constants > "$stage/parity/constants.tsv"
"$parity" akm > "$stage/parity/akm-names.tsv"
"$parity" ipcolor > "$stage/parity/ip-color.tsv"
"$parity" literals tests/contract/literals.txt > "$stage/parity/literals.tsv"
"$parity" pins tests/contract/pins.tsv > "$stage/parity/pins.tsv"
"$parity" fires src/alerts/rules_ble.c src/alerts/rules_camera.c src/alerts/rules_enterprise.c \
    src/alerts/rules_gnss.c src/alerts/rules_mle.c src/alerts/rules_regulatory.c \
    src/alerts/rules_twin.c src/alerts/rules_wifi_mgmt.c src/alerts/rules_wired.c \
    > "$stage/parity/fire-sites.tsv"

# ── golden fixtures ──
cp tests/replay/golden.jsonl "$stage/fixtures/golden.jsonl"
# The one dns record that links sloth's writer to a reader's passive PTR
# cache (tests/test_jsonl.c emits it; a consumer feeds it).
cp include/jsonl_ptr_fixture.h "$stage/fixtures/jsonl_ptr_fixture.h"
"$cdb" build "$stage/fixtures/sloth.db" "$stage/schema/schema.sql"

# ── MANIFEST.json and SHA256SUMS ──
files=$(cd "$stage" && find . -type f | sed 's|^\./||' | LC_ALL=C sort)
cc_version=$($CC --version 2> /dev/null | sed -n 1p | sed 's/["\\]//g')
sqlite_version=$("$cdb" libversion)
# The flags as recorded: the prefix map names the directory the tree was
# built in, which is neither part of the contract nor anyone's business,
# and would make two checkouts of one commit disagree.
cflags_rec=$(printf '%s\n' "$CONTRACT_CFLAGS" | sed -e 's/-ffile-prefix-map=[^ ]*//g' \
                 -e 's/["\\]//g' -e 's/  */ /g' -e 's/^ //' -e 's/ $//')
{
    printf '{\n'
    printf '  "contract_format": 1,\n'
    printf '  "sloth_version": "%s",\n' "$version"
    printf '  "jsonl_version": "%s",\n' "$jsonl_version"
    printf '  "db_schema_version": %s,\n' "$db_version"
    printf '  "git_commit": "%s",\n' "$commit"
    printf '  "git_dirty": %s,\n' "$dirty"
    printf '  "source_date_epoch": %s,\n' "$SOURCE_DATE_EPOCH"
    printf '  "toolchain": {"cc": "%s", "cflags": "%s", "sqlite": "%s"},\n' \
        "$cc_version" "$cflags_rec" "$sqlite_version"
    printf '  "files": [\n'
    n=$(printf '%s\n' "$files" | wc -l)
    i=0
    for f in $files; do
        i=$((i + 1))
        size=$(wc -c < "$stage/$f" | tr -d ' ')
        sum=$(sha256sum "$stage/$f" | cut -d' ' -f1)
        sep=,; [ "$i" -eq "$n" ] && sep=
        printf '    {"path": "%s", "size": %s, "sha256": "%s"}%s\n' "$f" "$size" "$sum" "$sep"
    done
    printf '  ]\n}\n'
} > "$stage/MANIFEST.json"
# shellcheck disable=SC2086
(cd "$stage" && sha256sum MANIFEST.json $files > SHA256SUMS)

tar=dist/$name.tar
rm -f "$tar" "dist/$name.SHA256SUMS"
tar -C "$work/stage" --sort=name --format=gnu --mtime="@$SOURCE_DATE_EPOCH" \
    --owner=0 --group=0 --numeric-owner --mode='u=rwX,go=rX' \
    -cf "$tar" "$name"
(cd dist && sha256sum "$name.tar" > "$name.SHA256SUMS")
echo "contract: $tar ($(wc -c < "$tar" | tr -d ' ') bytes, $(printf '%s\n' "$files" | wc -l | tr -d ' ') files + MANIFEST.json + SHA256SUMS)"
