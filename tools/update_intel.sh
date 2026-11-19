#!/bin/sh
# make update-intel PACK=<dir> [COMMIT=<sha>] (#231): refresh sloth's
# pinned intel-pack snapshot in intel/ from a GIVEN pack root and
# rewrite intel/LOCK. A developer runs it by hand and commits the
# result; nothing in the build, the tests or CI calls it, and it never
# reaches the network.
#
#   tools/update_intel.sh PACK INTEL_DIR INTEL_GEN [COMMIT]
#
# PACK holds the packs as directories: sloth-comint's packs/, or an
# unpacked sloth-intel-pack-<ver>/. Only sloth's six are taken (the
# list is tools/intel_read.c's ir_pack_names), and of each only
# manifest.json and the files it lists. The version is PACK/VERSION
# (packs/) or MANIFEST.json's pack_version (a bundle). The commit is
# COMMIT, or PACK's git HEAD when PACK is in a work tree with nothing
# uncommitted under it: a LOCK naming a commit whose bytes differ from
# what was copied would name nothing.
#
# The copy is staged and verified (intel_gen lock: every hash, length,
# row count and value) before it replaces anything; a refusal leaves
# intel/ as it was. A refresh that brings back the same bytes changes
# only LOCK's date.
set -eu

pack=${1:-}
dest=${2:-intel}
gen=${3:-build/intel/intel_gen}
commit=${4:-}
packs="attacker-ouis ble-watchlist camera-vendor oui-builtin surveillance-endpoints tool-fingerprints"

[ -n "$pack" ] && [ -d "$pack" ] || { echo "update_intel: PACK must be a directory" >&2; exit 2; }
[ -x "$gen" ] || { echo "update_intel: $gen not built" >&2; exit 2; }

if [ -f "$pack/VERSION" ]; then
    version=$(sed -n '1{s/[[:space:]]*$//;p;}' "$pack/VERSION")
elif [ -f "$pack/MANIFEST.json" ]; then
    version=$(sed -n 's/^[[:space:]]*"pack_version":[[:space:]]*"\([^"]*\)".*/\1/p' "$pack/MANIFEST.json" | head -n 1)
else
    echo "update_intel: $pack has neither VERSION nor MANIFEST.json" >&2
    exit 2
fi

if [ -z "$commit" ]; then
    if git -C "$pack" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        if [ -n "$(git -C "$pack" status --porcelain -- .)" ]; then
            echo "update_intel: $pack has uncommitted changes; commit them or pass COMMIT=" >&2
            exit 2
        fi
        commit=$(git -C "$pack" rev-parse HEAD)
    else
        echo "update_intel: $pack is not in a git work tree; pass COMMIT=<sha>" >&2
        exit 2
    fi
fi

mkdir -p "$dest"
tmp=$(mktemp -d "$dest.update.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM

for p in $packs; do
    [ -f "$pack/$p/manifest.json" ] || { echo "update_intel: $pack/$p/manifest.json missing" >&2; exit 1; }
    mkdir "$tmp/$p"
    cp "$pack/$p/manifest.json" "$tmp/$p/"
    # The listed paths: flat names (intel_read.c refuses any other), so
    # a "path" member's value is the whole file name.
    for f in $(sed -n 's/^[[:space:]]*"path":[[:space:]]*"\([A-Za-z0-9._+-]*\)".*/\1/p' "$pack/$p/manifest.json"); do
        [ -f "$pack/$p/$f" ] || { echo "update_intel: $pack/$p/$f missing" >&2; exit 1; }
        cp "$pack/$p/$f" "$tmp/$p/"
    done
done

"$gen" lock "$tmp" "$version" "$commit" "$(date -u +%Y-%m-%d)"

for p in $packs; do
    rm -rf "${dest:?}/$p"
    mv "$tmp/$p" "$dest/$p"
done
mv "$tmp/LOCK" "$dest/LOCK"
echo "update_intel: $dest is pack $version from $commit"
