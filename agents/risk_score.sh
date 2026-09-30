#!/bin/sh
# risk_score.sh — risk-proportionate autonomy gate (issue #45).
#
# Scores the pending diff (default: working tree vs origin/main, so it
# works pre-commit) for blast radius before the converge loop ships.
# The green suite stays the correctness oracle; this scores *what kind*
# of change is riding on it.
#
# Usage:
#   sh agents/risk_score.sh [range]     score a diff (default origin/main)
#   sh agents/risk_score.sh --selftest  run canned-fixture assertions
#
# Modes:
#   advisory  (default)                 always exit 0; score is informational
#   enforcing (agents/risk_enforce exists)
#                                       exit 1 when TOTAL >= RISK_THRESHOLD
#
# Env: RISK_THRESHOLD (default 50).
#
# Weights (owner-reviewable; keep this table in sync with FACTORY.md §10.3):
#   +40  agent-instruction / CI surface   agents/ .github/ .githooks/
#   +30  external-contract narrowing      >=10 deleted lines in src/jsonl.c
#                                         or src/main.c, or any deletion
#                                         in src/jsonl.h
#   +10  external-contract widening       docs/wiki/jsonl-schema.md touched
#                                         with no such source deletions:
#                                         a documented additive change
#   +20  forensic-output integrity        src/jsonl.c src/alert_pcap.c
#                                         src/pcap_write.c src/eapol_log.c
#   +5   per new file (cap +20)
#   +10  per deleted file (cap +30)
#   +15  churn > 300 lines (+30 if > 800)
#    0   docs/ + tests/ + *.md only       overrides everything
#
# Input to the scoring core (stdin): `git diff --name-status` lines,
# a literal "--" separator, then `git diff --numstat` lines. The core is
# pure text→score so the selftest can feed hand-built fixtures — same
# rule as the protocol parsers: no circular tests.

THRESHOLD="${RISK_THRESHOLD:-50}"
ENFORCE_MARKER="$(dirname "$0")/risk_enforce"

score_core() {
    awk -F'\t' '
        BEGIN { section = 0; adds = 0; dels = 0; churn = 0; n = 0 }
        $0 == "--" { section = 1; next }
        NF == 0 { next }
        section == 0 {
            status = substr($1, 1, 1)
            path = (status == "R" || status == "C") ? $3 : $2
            paths[n] = path; stat[n] = status; n++
            if (status == "A") adds++
            if (status == "D") dels++
        }
        section == 1 {
            if ($1 != "-") churn += $1 + $2
            if ($2 != "-") del_lines[$3] = $2
        }
        END {
            cold = 1
            for (i = 0; i < n; i++) {
                # agent/CI surface is hot even when the file is markdown
                if (paths[i] ~ /^agents\// || paths[i] ~ /^\.github\// || paths[i] ~ /^\.githooks\//)
                    cold = 0
                else if (paths[i] !~ /^docs\// && paths[i] !~ /^tests\// && paths[i] !~ /\.md$/)
                    cold = 0
            }
            if (n == 0 || cold) {
                print "  +0  docs/tests-only diff (or empty) — negative-weight override"
                print "TOTAL 0"
                exit
            }
            total = 0
            for (i = 0; i < n; i++)
                if (paths[i] ~ /^agents\// || paths[i] ~ /^\.github\// || paths[i] ~ /^\.githooks\//) {
                    printf "  +40 agent-instruction / CI surface: %s\n", paths[i]
                    total += 40; break
                }
            # Contract risk is asymmetric, and until 2026-09-30 this
            # scored it as if it were not. dark-factory.md 4.3 names the
            # stop-and-ask as changing the JSONL schema "in a
            # non-additive way"; a consumer breaks when a field changes
            # meaning or disappears, not when a new one appears beside
            # it — the schema doc says outright that an unknown field is
            # ignored. Scoring any touch of that doc at +30 meant
            # "documented a new field" and "deleted a field" both landed
            # on exactly the threshold, so the gate carried no
            # information at the one point where it acts.
            #
            # The source-deletion proxies also need a floor. main.c is a
            # thousand lines of poll loop, not a flag table: two deleted
            # lines there are not evidence a CLI flag went away, and the
            # #91 slice that removed exactly two scored 50 for it.
            # jsonl.h is exempt from the floor — it is small, and a
            # single deleted line there really can be a removed field.
            DEL_FLOOR = 10
            contract = ""; widen = ""
            if (del_lines["src/jsonl.c"] + 0 >= DEL_FLOOR) contract = "src/jsonl.c (deletions)"
            else if (del_lines["src/jsonl.h"] + 0 > 0) contract = "src/jsonl.h (deletions)"
            else if (del_lines["src/main.c"] + 0 >= DEL_FLOOR)  contract = "src/main.c (deletions)"
            else for (i = 0; i < n; i++)
                if (paths[i] == "docs/wiki/jsonl-schema.md") { widen = paths[i]; break }
            if (contract != "") {
                printf "  +30 external-contract narrowing: %s\n", contract
                total += 30
            } else if (widen != "") {
                printf "  +10 contract widening (documented, additive): %s\n", widen
                total += 10
            }
            for (i = 0; i < n; i++)
                if (paths[i] == "src/jsonl.c" || paths[i] == "src/alert_pcap.c" ||
                    paths[i] == "src/pcap_write.c" || paths[i] == "src/eapol_log.c") {
                    printf "  +20 forensic-output path: %s\n", paths[i]
                    total += 20; break
                }
            if (adds > 0) {
                w = adds * 5; if (w > 20) w = 20
                printf "  +%d new files: %d\n", w, adds
                total += w
            }
            if (dels > 0) {
                w = dels * 10; if (w > 30) w = 30
                printf "  +%d deleted files: %d\n", w, dels
                total += w
            }
            if (churn > 800)      { printf "  +30 churn: %d lines\n", churn; total += 30 }
            else if (churn > 300) { printf "  +15 churn: %d lines\n", churn; total += 15 }
            printf "TOTAL %d\n", total
        }
    '
}

# Untracked files are pending blast radius: a new file counts before it
# is ever staged, which is why the default (working-tree) mode folds
# them in. Two kinds of entry must not be treated as ordinary files,
# though, and until 2026-09-30 both were:
#
#   - A trailing slash is git declining to descend into a nested repo
#     (`.claude/worktrees/<id>/`). It is not a file: `wc -l` on it
#     printed "Is a directory" and it still scored as an add. Its
#     contents stay unscored, which is the honest limit — they belong
#     to another repository.
#   - A binary (a stray `sloth.bak-*`) has no meaningful line count.
#     Line-counting two of them produced 3,760 lines of phantom churn
#     and scored a CLEAN tree at 45/50, one point under the threshold.
#
# git already classifies both correctly, so ask it instead of guessing:
# a numstat of "-" means binary, exactly as in a committed diff, where
# a new binary scores as an added file and contributes no churn.
untracked_files() {
    git ls-files --others --exclude-standard 2>/dev/null | while IFS= read -r f; do
        case "$f" in */) continue ;; esac     # nested repo, not a file
        [ -f "$f" ] || continue
        printf '%s\n' "$f"
    done
}

untracked_numstat() {
    untracked_files | while IFS= read -r f; do
        n=$(git diff --no-index --numstat /dev/null "$f" 2>/dev/null | cut -f1)
        [ "$n" = "-" ] && continue            # binary: an add, no churn
        printf '%s\t0\t%s\n' "${n:-0}" "$f"
    done
}

selftest() {
    pass=0; fail=0
    check() {
        want="$1"; name="$2"; input="$3"
        got=$(printf '%s\n' "$input" | score_core | awk '/^TOTAL/ { print $2 }')
        if [ "$got" = "$want" ]; then
            pass=$((pass + 1)); echo "  [pass] $name"
        else
            fail=$((fail + 1)); echo "  [FAIL] $name: want $want, got $got"
        fi
    }
    # docs-only diff scores zero regardless of churn
    check 0 "docs_only_zero" \
"M	docs/wiki/foo.md
M	README.md
--
400	10	docs/wiki/foo.md
20	2	README.md"
    # routine parser fix + its test scores zero
    check 0 "routine_fix_zero" \
"M	src/dns.c
M	tests/test_dns.c
--
30	10	src/dns.c
40	0	tests/test_dns.c"
    # agent-surface touch alone
    check 40 "agent_surface_40" \
"M	agents/converge.md
--
10	2	agents/converge.md"
    # jsonl.c with deletions past the floor: narrowing + forensic path
    check 50 "jsonl_deletion_50" \
"M	src/jsonl.c
--
12	14	src/jsonl.c"
    # ...and under the floor it is just the forensic-path weight
    check 20 "jsonl_small_deletion_under_floor" \
"M	src/jsonl.c
--
12	6	src/jsonl.c"
    # additive-only jsonl.c: forensic path but no contract proxy
    check 20 "jsonl_additive_20" \
"M	src/jsonl.c
--
40	0	src/jsonl.c"
    # schema doc touch alone, no source deletions: widening only
    check 10 "schema_doc_widening_10" \
"M	docs/wiki/jsonl-schema.md
M	src/tui.c
--
5	1	docs/wiki/jsonl-schema.md
3	1	src/tui.c"
    # the case the widening rule must NOT soften: a field removed from
    # the emitter and struck from the schema is a real break, and still
    # scores the same 50 it did before the split.
    check 50 "schema_doc_narrowing_still_50" \
"M	src/jsonl.c
M	docs/wiki/jsonl-schema.md
--
4	22	src/jsonl.c
2	9	docs/wiki/jsonl-schema.md"
    # below the floor: two deleted lines in main.c are not a flag
    # removal (the #91 hop-activity slice deleted exactly two).
    check 0 "main_c_small_deletion_under_floor" \
"M	src/main.c
--
12	2	src/main.c"
    # at the floor it fires again
    check 30 "main_c_deletion_at_floor" \
"M	src/main.c
--
4	10	src/main.c"
    # jsonl.h is exempt from the floor: it is small enough that one
    # deleted line can be a removed field.
    check 30 "jsonl_h_single_deletion_still_hot" \
"M	src/jsonl.h
--
1	1	src/jsonl.h"
    # new-file cap: 5 adds capped at +20, churn 900 = +30
    check 50 "new_file_cap_churn" \
"A	src/views/foo.c
A	src/views/foo.h
A	src/foo_log.c
A	src/foo_log.h
A	src/foo_snoop.c
--
300	0	src/views/foo.c
40	0	src/views/foo.h
300	0	src/foo_log.c
40	0	src/foo_log.h
220	0	src/foo_snoop.c"
    # deleted-file cap: 4 dels capped at +30
    check 45 "deleted_file_cap" \
"D	src/old_a.c
D	src/old_b.c
D	src/old_c.c
D	src/old_d.c
--
0	120	src/old_a.c
0	80	src/old_b.c
0	60	src/old_c.c
0	90	src/old_d.c"
    # rename scores the destination path (into agents/ = agent surface)
    check 40 "rename_dest_path" \
"R100	scripts/gate.sh	agents/gate.sh
--
0	0	agents/gate.sh"
    # binary numstat lines ("-") don't poison churn
    check 0 "binary_numstat_ignored" \
"M	src/tui.c
--
-	-	docs/assets/logo.png
10	2	src/tui.c"
    # ── untracked enumeration ──────────────────────────────────────
    # score_core is pure text, but the bug that scored a clean tree at
    # 45/50 lived in the enumeration feeding it, which no fixture could
    # reach. This drives the real thing against a real scratch repo: a
    # text file, a binary, and a nested repo are exactly the three cases
    # that were conflated.
    tmp="${TMPDIR:-/tmp}/risk_score_selftest.$$"
    rm -rf "$tmp"; mkdir -p "$tmp/nested"
    ( cd "$tmp" && git init -q . 2>/dev/null &&
      printf 'a\nb\nc\n' > plain.txt &&
      printf '\000\001\002binary\000' > blob.bin &&
      cd nested && git init -q . 2>/dev/null && : > inner.c ) 2>/dev/null
    if [ -d "$tmp/.git" ]; then
        got=$( cd "$tmp" && untracked_files | tr '\n' ' ' )
        check_str() {
            want="$1"; name="$2"; got="$3"
            if [ "$got" = "$want" ]; then
                pass=$((pass + 1)); echo "  [pass] $name"
            else
                fail=$((fail + 1)); echo "  [FAIL] $name: want '$want', got '$got'"
            fi
        }
        # The nested repo is skipped; both real files are listed.
        check_str "blob.bin plain.txt " "untracked_skips_nested_repo" "$got"
        # Only the text file carries line counts — a binary must not
        # become churn, which is what inflated the clean-tree score.
        got=$( cd "$tmp" && untracked_numstat | tr '\t' ' ' | tr '\n' ';' )
        check_str "3 0 plain.txt;" "untracked_binary_has_no_churn" "$got"
    else
        echo "  [skip] untracked enumeration (git init unavailable)"
    fi
    rm -rf "$tmp"

    echo "$pass passed, $fail failed"
    [ "$fail" -eq 0 ]
}

case "$1" in
--selftest)
    selftest
    exit $?
    ;;
esac

RANGE="${1:-origin/main}"

# An explicit range scores history, where every file is already tracked.
# Without one we are scoring the working tree, and a file that is
# neither committed nor staged is invisible to `git diff` — which is how
# a slice adding three new source files scored 50 before the commit and
# 80 after it. Same diff, different answer; the pre-commit number was
# the wrong one, and it is the number the converge loop acts on.
if [ -z "$1" ]; then
    NAMES=$(untracked_files | sed 's/^/A\t/')
    NUMSTAT=$(untracked_numstat)
else
    NAMES=""
    NUMSTAT=""
fi
out=$( {
    git diff --name-status "$RANGE"
    [ -n "$NAMES" ] && printf '%s\n' "$NAMES"
    echo "--"
    git diff --numstat "$RANGE"
    [ -n "$NUMSTAT" ] && printf '%s\n' "$NUMSTAT"
} | score_core ) || exit 2
echo "$out"
total=$(printf '%s\n' "$out" | awk '/^TOTAL/ { print $2 }')

if [ -f "$ENFORCE_MARKER" ]; then mode="enforcing"; else mode="advisory"; fi
echo "RISK $total/$THRESHOLD ($mode, range $RANGE)"

if [ "$mode" = "enforcing" ] && [ "$total" -ge "$THRESHOLD" ]; then
    echo "HALT: score >= threshold — do not push; surface the breakdown on the issue."
    exit 1
fi
exit 0
