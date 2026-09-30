#!/bin/sh
# Mirror docs/wiki/ into the GitHub wiki repository (sloth.wiki.git).
#
# docs/wiki/ is the single source of truth; the GitHub wiki is a render
# of it, never edited by hand. This script is what the wiki-sync
# workflow runs on every push to main, and what an agent runs locally
# to publish before the workflow does (see agents/AGENTS.md "Wiki").
#
#   usage: wiki_sync.sh <docs/wiki dir> <wiki checkout dir> [--no-push]
#
# Transformations, all mechanical:
#   - index.md            -> Home.md   (GitHub's landing page name)
#   - YAML front matter   stripped     (the wiki renders it as a table)
#   - ](../views/x.md)    -> absolute blob URL on main
#   - ](../personas/x.md) -> absolute blob URL on main
#   - ](../../X.md)       -> absolute blob URL on main
#   - ](page.md)          -> ](page)   (sibling wiki page)
#   - [[page]]            untouched    (GitHub wiki resolves these itself)
#   - _Sidebar.md         generated from index.md's headings + [[links]]
#   - _Footer.md          fixed provenance line
#
# Exit non-zero on any failure so CI goes red rather than half-syncing.
set -eu

SRC=${1:?docs/wiki dir}
DST=${2:?wiki checkout dir}
PUSH=1
[ "${3:-}" = "--no-push" ] && PUSH=0

REPO_URL=${SLOTH_REPO_URL:-https://github.com/SpaceTrucker2196/sloth}
BLOB="$REPO_URL/blob/main"

[ -f "$SRC/index.md" ] || { echo "wiki_sync: $SRC/index.md missing" >&2; exit 1; }
[ -d "$DST/.git" ]     || { echo "wiki_sync: $DST is not a git checkout" >&2; exit 1; }

# Remove every page we own so a page deleted from docs/wiki/ also
# leaves the wiki. Anything else in the checkout is left alone.
find "$DST" -maxdepth 1 -name '*.md' -type f -exec rm -f {} +

render() {
    # $1 = source file, $2 = destination file
    awk '
        NR == 1 && $0 == "---" { fm = 1; next }
        fm && $0 == "---"      { fm = 0; next }
        fm                     { next }
        { print }
    ' "$1" \
    | sed \
        -e "s#](\.\./views/\([^)]*\))#]($BLOB/docs/views/\1)#g" \
        -e "s#](\.\./personas/\([^)]*\))#]($BLOB/docs/personas/\1)#g" \
        -e "s#](\.\./\.\./\([^)]*\))#]($BLOB/\1)#g" \
        -e "s#](\([a-z0-9-]*\)\.md)#](\1)#g" \
        -e "s#](\([a-z0-9-]*\)\.md\(\#[^)]*\))#](\1\2)#g" \
    > "$2"
}

for f in "$SRC"/*.md; do
    base=$(basename "$f" .md)
    case "$base" in
        index) out=Home ;;
        *)     out=$base ;;
    esac
    render "$f" "$DST/$out.md"
done

# Sidebar: every "## Heading" and every "- [[page]] — hook" line from
# index.md, hooks truncated so the sidebar stays a sidebar.
awk '
    /^## /            { sub(/^## /, ""); printf "\n**%s**\n\n", $0; next }
    /^- \[\[[^]]*\]\]/ {
        match($0, /\[\[[^]]*\]\]/)
        page = substr($0, RSTART + 2, RLENGTH - 4)
        printf "- [[%s]]\n", page
    }
' "$SRC/index.md" > "$DST/_Sidebar.md"

cat > "$DST/_Footer.md" <<EOF
Mirrored from [\`docs/wiki/\`]($REPO_URL/tree/main/docs/wiki) on \`main\` by \`.github/scripts/wiki_sync.sh\`. Edit there, not here — hand edits to this wiki are overwritten on the next push.
EOF

cd "$DST"
git add -A .
if git diff --cached --quiet; then
    echo "wiki_sync: no changes"
    exit 0
fi
src_sha=$(git -C "$SRC" rev-parse --short HEAD 2>/dev/null || echo unknown)
git -c user.name="${GIT_AUTHOR_NAME:-sloth wiki-sync}" \
    -c user.email="${GIT_AUTHOR_EMAIL:-noreply@github.com}" \
    commit -q -m "Sync docs/wiki from sloth@$src_sha"
echo "wiki_sync: committed $(git diff --stat HEAD~1 | tail -1)"
if [ "$PUSH" -eq 1 ]; then
    git push -q origin HEAD:master
    echo "wiki_sync: pushed"
fi
