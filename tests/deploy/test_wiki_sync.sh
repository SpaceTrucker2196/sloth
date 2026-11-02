#!/bin/sh
# .github/scripts/wiki_sync.sh against a hand-built docs/wiki tree and a
# scratch wiki checkout (--no-push: nothing leaves the machine). The
# GitHub wiki is flat, so a page in docs/wiki/<dir>/ publishes as
# <dir>-<page> and <dir>/README.md as <dir>; every link shape the
# script rewrites is checked here, and a flattened name that would
# overwrite a top-level page must fail the sync.
set -u

top=$(pwd)
sync=$top/.github/scripts/wiki_sync.sh
[ -f "$sync" ] || { echo "test_wiki_sync: run from the top of the tree" >&2; exit 2; }
command -v git >/dev/null || { echo "test_wiki_sync: needs git" >&2; exit 2; }

base=$(cd "$(mktemp -d "${TMPDIR:-/tmp}/sloth-wikisync.XXXXXX")" && pwd)
trap 'rm -rf "$base"' EXIT INT TERM HUP

pass=0
fail=0
check() {   # $1 = file, $2 = fixed string expected in it, $3 = what
    if grep -qF -- "$2" "$1" 2>/dev/null; then pass=$((pass + 1));
    else fail=$((fail + 1)); echo "  FAIL $3: '$2' not in $(basename "$1")"; fi
}
norel() {   # $1 = file, $2 = what: no relative .md link survives (blob URLs may end in .md)
    if grep -qE '\]\([^h)][^)]*\.md(#[^)]*)?\)' "$1" 2>/dev/null; then
        fail=$((fail + 1)); echo "  FAIL $2: a relative .md link in $(basename "$1")";
    else pass=$((pass + 1)); fi
}
lacks() {   # $1 = file, $2 = fixed string that must be absent, $3 = what
    if grep -qF -- "$2" "$1" 2>/dev/null; then
        fail=$((fail + 1)); echo "  FAIL $3: '$2' in $(basename "$1")";
    else pass=$((pass + 1)); fi
}

mkwiki() {  # $1 = root
    mkdir -p "$1/src/alert-assessments" "$1/dst"
    git -C "$1/dst" init -q
    cat > "$1/src/index.md" <<'EOF'
# Wiki
## Pages
- [[alerts]] — the rules
EOF
    cat > "$1/src/alerts.md" <<'EOF'
See [the index](alert-assessments/README.md), [one](alert-assessments/PORT_SCAN.md)
and [a part](alert-assessments/PORT_SCAN.md#bibliography), [cli](cli-reference.md).
EOF
    cat > "$1/src/alert-assessments/README.md" <<'EOF'
| [PORT_SCAN](PORT_SCAN.md) | [back](../alerts.md) | [[alerts]] |
EOF
    cat > "$1/src/alert-assessments/PORT_SCAN.md" <<'EOF'
---
type: PORT_SCAN
---
## What the rule checks
[rule](../../../src/alerts/rules_wired.c), [view](../../views/alerts.md),
[index](README.md#top), [sibling](DEAUTH_FLOOD.md), [up](../alerts.md#rules).
EOF
}

r=$base/ok
mkwiki "$r"
if sh "$sync" "$r/src" "$r/dst" --no-push >"$r/out" 2>&1; then pass=$((pass + 1));
else fail=$((fail + 1)); echo "  FAIL sync exited non-zero:"; cat "$r/out"; fi
o=$r/dst
B=https://github.com/SpaceTrucker2196/sloth/blob/main
check "$o/Home.md"   "[[alerts]]" "index -> Home"
check "$o/alerts.md" "](alert-assessments)" "top-level link to a subdirectory README"
check "$o/alerts.md" "](alert-assessments-PORT_SCAN)" "top-level link to a subdirectory page"
check "$o/alerts.md" "](alert-assessments-PORT_SCAN#bibliography)" "anchor kept"
check "$o/alerts.md" "](cli-reference)" "sibling link unchanged"
check "$o/alert-assessments.md" "](alert-assessments-PORT_SCAN)" "README -> page <dir>, sibling flattened"
check "$o/alert-assessments.md" "](alerts)" "../page.md from a subdirectory"
check "$o/alert-assessments.md" "[[alerts]]" "wikilink untouched"
check "$o/alert-assessments-PORT_SCAN.md" "]($B/src/alerts/rules_wired.c)" "../../../ to a repo file"
check "$o/alert-assessments-PORT_SCAN.md" "]($B/docs/views/alerts.md)" "../../views from a subdirectory"
check "$o/alert-assessments-PORT_SCAN.md" "](alert-assessments#top)" "README.md#anchor inside the subdirectory"
check "$o/alert-assessments-PORT_SCAN.md" "](alert-assessments-DEAUTH_FLOOD)" "sibling inside the subdirectory"
check "$o/alert-assessments-PORT_SCAN.md" "](alerts#rules)" "up-link with an anchor"
lacks "$o/alert-assessments-PORT_SCAN.md" "type: PORT_SCAN" "front matter stripped"
norel "$o/alert-assessments-PORT_SCAN.md" "subdirectory page"
norel "$o/alert-assessments.md" "subdirectory index"
norel "$o/alerts.md" "top-level page"
if [ -e "$o/README.md" ]; then fail=$((fail + 1)); echo "  FAIL a README page published unflattened";
else pass=$((pass + 1)); fi

# A top-level page with the name a subdirectory page flattens to.
r=$base/clash
mkwiki "$r"
echo "clash" > "$r/src/alert-assessments-PORT_SCAN.md"
if sh "$sync" "$r/src" "$r/dst" --no-push >"$r/out" 2>&1; then
    fail=$((fail + 1)); echo "  FAIL a colliding page was accepted"
else
    pass=$((pass + 1))
    check "$r/out" "would overwrite page alert-assessments-PORT_SCAN" "collision named"
fi

echo "wiki-sync-test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
