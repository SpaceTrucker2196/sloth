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
# /usr/share/ieee-data, Debian's ieee-data package) when it is there,
# and otherwise fetched from standards-oui.ieee.org with curl. The IEEE
# server answers a plain curl with 418, so the fetch sends a browser
# User-Agent and Accept headers. Every file must be a CSV with the
# registry header and at least one row of its registry before any of
# them replaces what DEST holds: a failed refresh leaves DEST unchanged.
set -eu

dest=${1:-web/data}
src=${2:-/usr/share/ieee-data}
ua='Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0'
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
    if [ -r "$src/$name.csv" ]; then
        cp "$src/$name.csv" "$out"
        how="copied from $src"
    else
        command -v curl >/dev/null || { echo "update_oui: no $src/$name.csv and no curl" >&2; exit 1; }
        curl -fsSL --retry 2 -A "$ua" \
             -H 'Accept: text/csv,text/plain;q=0.9,*/*;q=0.8' \
             -H 'Accept-Language: en-US,en;q=0.5' \
             -o "$out" "https://standards-oui.ieee.org/$path" ||
            { echo "update_oui: fetching $path failed" >&2; exit 1; }
        how="fetched from https://standards-oui.ieee.org/"
    fi
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
grep -q '^<!-- update-oui:begin -->$' "$dest/SOURCE.md" &&
    grep -q '^<!-- update-oui:end -->$' "$dest/SOURCE.md" ||
    { echo "update_oui: $dest/SOURCE.md has no update-oui markers" >&2; exit 1; }
awk -v blk="$block" '
    /^<!-- update-oui:begin -->$/ { while ((getline l < blk) > 0) print l; skip = 1; next }
    /^<!-- update-oui:end -->$/   { skip = 0; next }
    !skip' "$dest/SOURCE.md" > "$tmp/SOURCE.md"

for name in oui mam oui36 iab; do mv "$tmp/$name.csv" "$dest/$name.csv"; done
mv "$tmp/SOURCE.md" "$dest/SOURCE.md"
echo "update_oui: $dest refreshed ($origin); review and commit web/data/"
