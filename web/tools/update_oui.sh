#!/bin/sh
# make update-oui (#162; owner ruling 2026-10-26): refresh the IEEE
# registry CSVs committed in web/data/ and the hashes and date in
# web/data/SOURCE.md. A developer runs it by hand and commits the
# result; nothing in the build, the tests or CI calls it, so a build
# never touches the network.
#
#   web/tools/update_oui.sh [DEST [SRC]]
#
# DEST defaults to web/data. Each file is copied from SRC (default
# /usr/share/ieee-data, Debian's ieee-data package). There is no
# network fetch: the IEEE server refuses scripted downloads (it answers
# 418), and this script does not work around that. Without the
# package, install it (apt install ieee-data) or download the four
# files from https://standards-oui.ieee.org/ in a browser into a
# directory and pass it as SRC. Every file must be a CSV with the
# registry header and at least one row of its registry before any of
# them replaces what DEST holds: a failed refresh leaves DEST unchanged.
# A refresh that brings back the same four files changes nothing.
set -eu

dest=${1:-web/data}
src=${2:-/usr/share/ieee-data}
bom=$(printf '\357\273\277')
header='Registry,Assignment,Organization Name,Organization Address'

[ -f "$dest/SOURCE.md" ] || { echo "update_oui: $dest/SOURCE.md missing" >&2; exit 2; }

tmp=$(mktemp -d "${TMPDIR:-/tmp}/sloth-oui.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM

# name, URL path, the registry its rows carry.
set -- oui oui/oui.csv MA-L \
       mam oui28/mam.csv MA-M \
       oui36 oui36/oui36.csv MA-S \
       iab iab/iab.csv IAB
origin=""
while [ $# -ge 3 ]; do
    name=$1 path=$2 reg=$3
    shift 3
    out="$tmp/$name.csv"
    if [ ! -r "$src/$name.csv" ]; then
        echo "update_oui: no $src/$name.csv. Install Debian's ieee-data" >&2
        echo "  package, or download https://standards-oui.ieee.org/$path in a" >&2
        echo "  browser into a directory and run: $0 $dest DIR" >&2
        exit 1
    fi
    cp "$src/$name.csv" "$out"
    how="copied from $src"
    first=$(head -n 1 "$out" | tr -d '\r')
    first=${first#"$bom"}
    [ "$first" = "$header" ] ||
        { echo "update_oui: $name.csv is not the IEEE registry CSV (first line: $first)" >&2; exit 1; }
    grep -q "^$reg," "$out" ||
        { echo "update_oui: $name.csv has no $reg row" >&2; exit 1; }
    case "$origin" in
    *"$how"*) ;;
    *) origin="${origin:+$origin; }$how" ;;
    esac
done

# Nothing changed: every new file is byte for byte the one in DEST and
# the one SOURCE.md's block records. Then SOURCE.md is left alone, so
# its "Refreshed" date stays the day the data last changed, not the
# day the script last ran.
same=1
for name in oui mam oui36 iab; do
    new=$(sha256sum "$tmp/$name.csv" | cut -d' ' -f1)
    have=$( { [ -f "$dest/$name.csv" ] && sha256sum "$dest/$name.csv"; } | cut -d' ' -f1)
    recorded=$(sed -n '/^<!-- update-oui:begin -->$/,/^<!-- update-oui:end -->$/p' "$dest/SOURCE.md" |
               grep "^| .$name\.csv. |" | sed -n 's/.*\([0-9a-f]\{64\}\).*/\1/p')
    if [ "$new" != "$have" ] || [ "$new" != "$recorded" ]; then same=0; break; fi
done
if [ "$same" = 1 ]; then
    echo "update_oui: $dest unchanged ($origin); SOURCE.md left as it is"
    exit 0
fi

version=""
if [ "$src" = /usr/share/ieee-data ] && command -v dpkg-query >/dev/null; then
    # shellcheck disable=SC2016 # ${Version} is dpkg-query's, not the shell's
    version=$(dpkg-query -W -f='${Version}' ieee-data 2>/dev/null || true)
fi

# The block between the markers in SOURCE.md is this script's; the rest
# of the page is prose and is kept.
block="$tmp/block"
{
    echo '<!-- update-oui:begin -->'
    echo "Refreshed $(date -u +%Y-%m-%d) by \`make update-oui\`: $origin${version:+ (ieee-data $version)}."
    echo
    echo '| File | Registry | Rows | Bytes | SHA-256 |'
    echo '|---|---|---|---|---|'
    for f in oui:MA-L mam:MA-M oui36:MA-S iab:IAB; do
        name=${f%%:*} reg=${f#*:}
        out="$tmp/$name.csv"
        rows=$(grep -c "^$reg," "$out")
        bytes=$(wc -c < "$out" | tr -d ' ')
        sum=$(sha256sum "$out" | cut -d' ' -f1)
        echo "| \`$name.csv\` | $reg | $rows | $bytes | \`$sum\` |"
    done
    echo '<!-- update-oui:end -->'
} > "$block"
if ! grep -q '^<!-- update-oui:begin -->$' "$dest/SOURCE.md" ||
   ! grep -q '^<!-- update-oui:end -->$' "$dest/SOURCE.md"; then
    echo "update_oui: $dest/SOURCE.md has no update-oui markers" >&2
    exit 1
fi
awk -v blk="$block" '
    /^<!-- update-oui:begin -->$/ { while ((getline l < blk) > 0) print l; skip = 1; next }
    /^<!-- update-oui:end -->$/   { skip = 0; next }
    !skip' "$dest/SOURCE.md" > "$tmp/SOURCE.md"

for name in oui mam oui36 iab; do mv "$tmp/$name.csv" "$dest/$name.csv"; done
mv "$tmp/SOURCE.md" "$dest/SOURCE.md"
echo "update_oui: $dest refreshed ($origin); review and commit web/data/"
