#!/bin/sh
# Rewrite the generated prose counts (#117). Run as `make docs-counts`.
#
# The docs state how many views and alert rules sloth has, and every
# slice that adds one used to hand-edit half a dozen sentences — the
# collision point when slices land in parallel, and the place the counts
# drifted (#96). Each such number now sits inside a marker:
#
#   <!-- count:views -->35<!-- /count -->       sloth-wifi's views
#   <!-- count:rules -->75<!-- /count -->       alert kinds, both daemons
#   <!-- count:rules-wifi -->70<!-- /count -->  the kinds sloth-wifi raises
#   <!-- count:rules-rf -->6<!-- /count -->     the kinds sloth-rf raises
#   <!-- count:vendors -->277<!-- /count -->   (slothweb's vendor research)
#
# The sensor is two daemons since #216 (ADR 0010), so "how many" has a
# "which binary". Views: sloth-wifi has every row of the views list and
# sloth-rf is headless, so `views` is sloth-wifi's. Alert kinds: the
# enum is one list both daemons share (the numbers are persisted), and
# `rules` is still its length. `rules-rf` is the rows of sloth-rf's rule
# table (src/alerts/rules_table_rf.c: one row per kind there), and
# `rules-wifi` is the whole list less the rows that table has and
# sloth-wifi's (src/alerts/rules_table.c) does not. A kind both raise,
# SENSOR_SOURCE_DOWN, is in both counts, which is why the two do not
# add up to `rules`.
#
# HTML comments, so the rendered page shows only the number. This script
# recounts from the two .def lists — one `X(` row at column 0 per view or
# alert type, the same rows the C enums are generated from — and rewrites
# every marker in place. tests/test_docs_consistency.c then asserts each
# marker against VIEW_COUNT / ALERT_TYPE_COUNT and that the row count
# here agrees with the compiled one, so drift is a red test whose fix is
# this one command.
#
# The two per-daemon counts are held the same way, against the compiled
# rule tables.
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
# One `R(rule_name),` row per line in each table.
rf_rows=$(sed -n 's/^[[:space:]]*R(\(rule_[a-z0-9_]*\)),.*/\1/p' "$root/src/alerts/rules_table_rf.c")
rules_rf=0
rf_only=0
for r in $rf_rows; do
    rules_rf=$((rules_rf + 1))
    grep -q "^[[:space:]]*R($r)," "$root/src/alerts/rules_table.c" || rf_only=$((rf_only + 1))
done
rules_wifi=$((rules - rf_only))
# slothweb's vendor research entries: one .md per vendor under
# web/data/vendors/, COVERAGE.md beside them not being one (the same
# rule web/tools/vendorkb.c applies; web/tests/test_vendorkb.c holds the
# table to the files, tests/test_docs_consistency.c the markers to them).
vendors=$(ls "$root/web/data/vendors" | grep '\.md$' | grep -vc '^COVERAGE\.md$' || true)

if [ "$#" -eq 0 ]; then
    # Word splitting is intended: repo paths contain no whitespace.
    # shellcheck disable=SC2046
    set -- $(grep -rl --include='*.md' '<!-- count:' \
                 "$root/README.md" "$root/MISSION.md" "$root/SECURITY.md" \
                 "$root/docs" "$root/agents" "$root/web/README.md" \
                 "$root/web/data/vendors/COVERAGE.md" 2>/dev/null || true)
fi

changed=0
for f in "$@"; do
    tmp="$f.docs_counts.$$"
    sed -e "s|<!-- count:views -->[0-9]*<!-- /count -->|<!-- count:views -->$views<!-- /count -->|g" \
        -e "s|<!-- count:rules -->[0-9]*<!-- /count -->|<!-- count:rules -->$rules<!-- /count -->|g" \
        -e "s|<!-- count:rules-wifi -->[0-9]*<!-- /count -->|<!-- count:rules-wifi -->$rules_wifi<!-- /count -->|g" \
        -e "s|<!-- count:rules-rf -->[0-9]*<!-- /count -->|<!-- count:rules-rf -->$rules_rf<!-- /count -->|g" \
        -e "s|<!-- count:vendors -->[0-9]*<!-- /count -->|<!-- count:vendors -->$vendors<!-- /count -->|g" \
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
echo "docs-counts: views=$views (sloth-wifi) rules=$rules (sloth-wifi $rules_wifi, sloth-rf $rules_rf) vendors=$vendors, $changed file(s) rewritten"
