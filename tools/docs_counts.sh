#!/bin/sh
# Rewrite the generated prose counts (#117). Run as `make docs-counts`.
#
# The docs state how many views and alert rules sloth has, and every
# slice that adds one used to hand-edit half a dozen sentences — the
# collision point when slices land in parallel, and the place the counts
# drifted (#96). Each such number now sits inside a marker:
#
#   <!-- count:views -->35<!-- /count -->
#   <!-- count:rules -->75<!-- /count -->
#
# HTML comments, so the rendered page shows only the number. This script
# recounts from the two .def lists — one `X(` row at column 0 per view or
# alert type, the same rows the C enums are generated from — and rewrites
# every marker in place. tests/test_docs_consistency.c then asserts each
# marker against VIEW_COUNT / ALERT_TYPE_COUNT and that the row count
# here agrees with the compiled one, so drift is a red test whose fix is
# this one command.
#
# With no arguments it rewrites every Markdown file that carries a
# marker under the repo's prose surfaces; with arguments, only those
# files. A file is replaced only when its text changes, so an up-to-date
# tree is left untouched (mtimes included). docs/wiki/log.md is never
# given markers: it is history, and a past entry's count stays true.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)

views=$(grep -c '^X(' "$root/include/sloth_views.def")
rules=$(grep -c '^X(' "$root/include/sloth_alerts.def")

if [ "$#" -eq 0 ]; then
    # Word splitting is intended: repo paths contain no whitespace.
    # shellcheck disable=SC2046
    set -- $(grep -rl --include='*.md' '<!-- count:' \
                 "$root/README.md" "$root/MISSION.md" "$root/SECURITY.md" \
                 "$root/docs" "$root/agents" 2>/dev/null || true)
fi

changed=0
for f in "$@"; do
    tmp="$f.docs_counts.$$"
    sed -e "s|<!-- count:views -->[0-9]*<!-- /count -->|<!-- count:views -->$views<!-- /count -->|g" \
        -e "s|<!-- count:rules -->[0-9]*<!-- /count -->|<!-- count:rules -->$rules<!-- /count -->|g" \
        "$f" > "$tmp"
    if cmp -s "$f" "$tmp"; then
        rm -f "$tmp"
    else
        cat "$tmp" > "$f"
        rm -f "$tmp"
        echo "docs-counts: updated $f"
        changed=$((changed + 1))
    fi
done
echo "docs-counts: views=$views rules=$rules, $changed file(s) rewritten"
