#!/bin/sh
# make update-btsig (the ab5fcb2 ruling, as web/tools/update_oui.sh):
# refresh the Bluetooth SIG assigned-numbers CSVs committed in
# web/data/btsig/ and the hashes and date in its SOURCE.md, from a
# GIVEN directory. A developer runs it by hand and commits the result;
# nothing in the build, the tests or CI calls it, so a build never
# touches the network.
#
#   web/tools/update_btsig.sh [DEST [SRC]]
#
# DEST defaults to web/data/btsig. SRC (no default: there is no package
# to copy from) is a directory holding the three YAML files of the SIG's
# public assigned-numbers repository, either flat (company_identifiers.yaml,
# service_uuids.yaml, appearance_values.yaml) or in its own layout
# (company_identifiers/, uuids/, core/). There is no network fetch:
# download them from
# https://bitbucket.org/bluetooth-SIG/public/src/main/assigned_numbers/
# in a browser (or clone the repository) and pass the directory. Each
# YAML is turned into a two-column CSV (value,name; RFC 4180 quoting)
# by the awk below, and must yield its expected header and at least one
# row before any of them replaces what DEST holds: a failed refresh
# leaves DEST unchanged. A refresh that brings back the same three
# files changes nothing.
set -eu

dest=${1:-web/data/btsig}
src=${2:-}
[ -n "$src" ] || { echo "update_btsig: give the directory holding the SIG YAML files" >&2; exit 2; }
[ -f "$dest/SOURCE.md" ] || { echo "update_btsig: $dest/SOURCE.md missing" >&2; exit 2; }

tmp=$(mktemp -d "${TMPDIR:-/tmp}/sloth-btsig.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM

# The YAML's scalar on a "key: value" line, unquoted: a single-quoted
# scalar undoes its '' escapes, a double-quoted one its \" and \\; a
# bare one is trimmed. Then RFC 4180: quoted when it holds a comma, a
# quote or an edge space, with " doubled.
AWK_LIB='
function unq(s) {
    sub(/^[ \t]+/, "", s); sub(/[ \t\r]+$/, "", s)
    if (s ~ /^'\''.*'\''$/) { s = substr(s, 2, length(s) - 2); gsub(/'\'''\''/, "'\''", s) }
    else if (s ~ /^".*"$/) { s = substr(s, 2, length(s) - 2); gsub(/\\"/, "\"", s); gsub(/\\\\/, "\\", s) }
    return s
}
function csv(s) {
    if (s ~ /[",]/ || s ~ /^ / || s ~ / $/) { gsub(/"/, "\"\"", s); return "\"" s "\"" }
    return s
}
function hex(s) { sub(/^[ \t]+/, "", s); sub(/[ \t\r]+$/, "", s); return s }
function hexval(s,    i, c, v, d) {
    s = hex(s); sub(/^0[xX]/, "", s); v = 0
    for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1); d = index("0123456789abcdef", tolower(c)) - 1
        if (d < 0) return -1
        v = v * 16 + d
    }
    return v
}
'

find_yaml() {
    for p in "$src/$1.yaml" "$src/$2/$1.yaml" "$src/assigned_numbers/$2/$1.yaml"; do
        [ -r "$p" ] && { echo "$p"; return 0; }
    done
    echo "update_btsig: no $1.yaml under $src (nor $src/$2/)" >&2
    echo "  download it from https://bitbucket.org/bluetooth-SIG/public/src/main/assigned_numbers/$2/" >&2
    exit 1
}

# company_identifiers.yaml: "  - value: 0x004C" then "    name: 'Apple, Inc.'".
y=$(find_yaml company_identifiers company_identifiers)
{
    echo 'value,name'
    awk "$AWK_LIB"'
    /^[ \t]*-[ \t]*value:/ { v = hex(substr($0, index($0, "value:") + 6)); next }
    /^[ \t]*name:/ && v != "" { print v "," csv(unq(substr($0, index($0, "name:") + 5))); v = "" }
    ' "$y"
} > "$tmp/company_identifiers.csv"

# service_uuids.yaml: " - uuid: 0x1800" / "   name: GAP" / "   id: ...".
y=$(find_yaml service_uuids uuids)
{
    echo 'value,name'
    awk "$AWK_LIB"'
    /^[ \t]*-[ \t]*uuid:/ { v = hex(substr($0, index($0, "uuid:") + 5)); next }
    /^[ \t]*name:/ && v != "" { print v "," csv(unq(substr($0, index($0, "name:") + 5))); v = "" }
    ' "$y"
} > "$tmp/service_uuids.csv"

# appearance_values.yaml: " - category: 0x002" / "   name: Computer" /
# "   subcategory:" / "    - value: 0x01" / "      name: Laptop". The
# 16-bit appearance is category << 6 | subcategory (Assigned Numbers
# 2.6.2); subcategory 0 is the generic form, named by its category.
y=$(find_yaml appearance_values core)
{
    echo 'value,name'
    awk "$AWK_LIB"'
    function out(v, n) { printf "0x%04X,%s\n", v, csv(n) }
    /^[ \t]*-[ \t]*category:/ { cat = hexval(substr($0, index($0, "category:") + 9)); want = "cat"; next }
    /^[ \t]*-[ \t]*value:/ { subv = hexval(substr($0, index($0, "value:") + 6)); want = "sub"; next }
    /^[ \t]*name:/ {
        n = unq(substr($0, index($0, "name:") + 5))
        if (want == "cat" && cat >= 0) { catname = n; out(cat * 64, n) }
        else if (want == "sub" && subv >= 0) out(cat * 64 + subv, catname " / " n)
        want = ""
    }
    ' "$y"
} > "$tmp/appearance_values.csv"

for name in company_identifiers service_uuids appearance_values; do
    out="$tmp/$name.csv"
    [ "$(head -n 1 "$out")" = "value,name" ] ||
        { echo "update_btsig: $name.csv did not come out as value,name" >&2; exit 1; }
    [ "$(wc -l < "$out")" -gt 1 ] ||
        { echo "update_btsig: $name.yaml yielded no row" >&2; exit 1; }
done
origin="converted from $src"

same=1
for name in company_identifiers service_uuids appearance_values; do
    new=$(sha256sum "$tmp/$name.csv" | cut -d' ' -f1)
    have=$( { [ -f "$dest/$name.csv" ] && sha256sum "$dest/$name.csv"; } | cut -d' ' -f1)
    recorded=$(sed -n '/^<!-- update-btsig:begin -->$/,/^<!-- update-btsig:end -->$/p' "$dest/SOURCE.md" |
               grep "^| .$name\.csv. |" | sed -n 's/.*\([0-9a-f]\{64\}\).*/\1/p')
    if [ "$new" != "$have" ] || [ "$new" != "$recorded" ]; then same=0; break; fi
done
if [ "$same" = 1 ]; then
    echo "update_btsig: $dest unchanged ($origin); SOURCE.md left as it is"
    exit 0
fi

block="$tmp/block"
{
    echo '<!-- update-btsig:begin -->'
    echo "Refreshed $(date -u +%Y-%m-%d) by \`make update-btsig\`: $origin."
    echo
    echo '| File | Table | Rows | Bytes | SHA-256 |'
    echo '|---|---|---|---|---|'
    for f in company_identifiers:'Company Identifiers' service_uuids:'16-bit Service UUIDs' appearance_values:'Appearance Values'; do
        name=${f%%:*} tab=${f#*:}
        out="$tmp/$name.csv"
        rows=$(($(wc -l < "$out") - 1))
        bytes=$(wc -c < "$out" | tr -d ' ')
        sum=$(sha256sum "$out" | cut -d' ' -f1)
        echo "| \`$name.csv\` | $tab | $rows | $bytes | \`$sum\` |"
    done
    echo '<!-- update-btsig:end -->'
} > "$block"
if ! grep -q '^<!-- update-btsig:begin -->$' "$dest/SOURCE.md" ||
   ! grep -q '^<!-- update-btsig:end -->$' "$dest/SOURCE.md"; then
    echo "update_btsig: $dest/SOURCE.md has no update-btsig markers" >&2
    exit 1
fi
awk -v blk="$block" '
    /^<!-- update-btsig:begin -->$/ { while ((getline l < blk) > 0) print l; skip = 1; next }
    /^<!-- update-btsig:end -->$/   { skip = 0; next }
    !skip' "$dest/SOURCE.md" > "$tmp/SOURCE.md"

for name in company_identifiers service_uuids appearance_values; do mv "$tmp/$name.csv" "$dest/$name.csv"; done
mv "$tmp/SOURCE.md" "$dest/SOURCE.md"
echo "update_btsig: $dest refreshed ($origin); review and commit web/data/btsig/"
