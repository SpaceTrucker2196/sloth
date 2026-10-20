# sloth — agent instructions

Repo-local rules for any coding agent (Claude Code, Copilot, Codex).
Build/infra runbook lives in `agents/FACTORY.md`; charter in the root
`MISSION.md`. This folder is plaintext and public — it was git-crypt
encrypted until 2026-07-28; see the root `CLAUDE.md` for why that was
dropped.

## What sloth is

A terminal-based **passive** network monitor for Linux, written in C99.
It never injects a frame onto a network it monitors — the one absolute
in `MISSION.md` §2; every other network-using behaviour is opt-in and
announced. It reads `/proc`, `/sys`, netlink (rtnetlink / nl80211 / INET_DIAG) and a
pcap stream, then surfaces what it sees through <!-- count:views -->35<!-- /count --> ncurses views
(`VIEW_COUNT`), <!-- count:rules -->80<!-- /count --> alert rules (one per `ALERT_TYPE_*`), an embedded
threat-intel matcher whose shipped IOC list is **synthetic demo data**,
optional per-alert pcap dumps, and an optional JSONL forensic log.

Single binary `sloth`. Test binary `sloth_test`.

## Architecture

- `include/sloth.h` — central header: shared structs, the `view_t` enum.
- `src/main.c` — CLI, signal handlers, main poll loop.
- `src/tui.c` + `tui.h` — ncurses rendering, colour pair init, key
  polling. ANSI fallback when built without ncurses.
- `src/platform/linux*.c` — Linux backends (rtnetlink, nl80211, /proc
  readers, INET_DIAG).
- `src/capture/capture.c` — libpcap thread; dispatches per-protocol
  parsers (decode_ipv4/v6 → TCP/UDP → DNS/TLS/HTTP/QUIC/NTP/ICMP).
- `src/{dns,tls,quic,http,ntp,icmp}_log.c` — ring buffers + per-record
  snapshot.
- `src/{alerts,beacon_detect,devices,threat_intel,filter,jsonl,alert_pcap,
  top_hosts,ip_color,ip_owner}.c` — synthesis + export.
- `src/views/*.c` — one file per VIEW_*. The dashboard composites
  several panels into one grid.
- `src/md5.c` — embedded MD5 for JA3 (verified against RFC 1321 vectors).
- `tests/` — unit tests, fake platform, scenarios. For the assertion
  count, run `make test` and read the last line; this file deliberately
  does not carry the number, because the three copies of it that used to
  live in `agents/` all sat three thousand assertions stale while this
  same file was telling readers never to quote a recalled count.
- `docs/views/*.md` — per-view deep dives. Linked from README tables.

## Discipline

- **Tests must pass.** `make test` returns 0. Never commit a red test.
  **Any assertion count you report is measured, never recalled** — build
  the parent and the shipped tree and quote both. A wrong count is worse
  than no count, because it makes the rest of the report unverifiable
  (see agents/converge.md step 8 for the case that established this).
- **Builds must be warning-clean — the whole matrix, not just `make`.**
  `make`, `make WITH_NCURSES=0`, `make WITH_PCAP=0`, `make WITH_WIFI=0`,
  `make WITH_SQLITE=0` and `make embedded` each produce no warnings.
  Treat any new warning as a failed build. Checking only the default
  build is how #99 happened: two helpers in `src/views/wifi.c` sat
  outside the `WITH_WIFI` guard and warned for an unknown number of
  releases, because no gate ever compiled that variant.
  **CI enforces this** (`.github/workflows/ci.yml`): it builds all six
  with `EXTRA_CFLAGS=-Werror`, so a warning fails the run rather than
  depending on someone remembering to look. Run them locally anyway —
  finding it after the push is slower, not safer.
  **Objects are per config** since #115 (`build/<cfg>/`, with flag
  stamps), so the old "`make clean` between configs" rule is no longer
  load-bearing. It is still cheap insurance before quoting a matrix
  result, and the six-config loops in this repo's history do it.

  **The whole build surface, every slice:** the six configs above;
  `make test` and `make test-capture-path`; **both again under
  `EXTRA_CFLAGS="-Werror -fsanitize=address,undefined
  -fno-omit-frame-pointer -fno-sanitize-recover=all"`**; `make fuzz
  FUZZ_SECONDS=1`; `make cppcheck`. The sanitized capture-path run is
  the one that caught a 900-byte stack over-read in a test helper on
  2026-10-15 after every other local gate was green. Source lists are
  derived since #115 - a new `src/*.c` goes in `CORE_COMMON_SRCS` once,
  and tests and fuzz harnesses are picked up by wildcard.
- **Views and alert kinds are X-macro lists** since #117:
  `include/sloth_views.def` and `include/sloth_alerts.def` generate the
  enums, labels, dispatch, key switch and name/technique tables. Edit
  the `.def`, then run `make docs-counts` so the prose counts follow.
- **Hand-crafted protocol tests.** Parsers are tested with raw byte
  arrays built from first principles per RFC. Don't write circular
  tests (parser feeding its own output back).
- **No pcap fixtures.** The same rule, stated for the 802.11 detector
  work because it keeps getting re-argued: detector tests are annotated
  `uint8_t` arrays built per the relevant IEEE clause, not captures from
  a lab rig. Precedent is `tests/test_beacon_snoop.c` (#33) and
  `tests/test_action_snoop.c` (#59); `tests/` holds zero `.pcap` files
  and should stay that way. Hand-built frames reach the truncated,
  malformed and adversarial cases a capture can't, and need no radio.
  The gap that leaves is real and worth stating: they prove the parser
  against the spec, not against what `mdk4` or `bettercap` actually put
  on the air. A capture is a later *integration* layer on top, never a
  substitute. The `needs-pcap-fixture` label means exactly that —
  wanted as follow-up validation, not blocking.
- **No mocks of real-data interfaces.** The fake platform in
  `tests/fake_platform.c` lives there for a reason.
- **Per-view docs follow the template** in `docs/views/README.md`:
  protocol → what sloth captures → text mockup → normal → suspicious →
  see-also.
- **Detectors cite their sources.** Every alert rule names what it is
  detecting *from*: the CVE, the CERT advisory, the MITRE technique, the
  IEEE clause, or the paper. Not decoration — a behavioural threshold
  with no cited basis is indistinguishable from a guess, and the
  operator deciding whether to act on a CRIT needs to know which it is.
  In practice that means the rule table row in `docs/views/alerts.md`
  and the `alert_technique()` entry, plus a wiki page for anything with
  a non-obvious mechanism.

  The habit has been followed since the first detector batch without
  ever being written down here, which is why `#73` proposed enforcing
  it. Enforcement should follow documentation, so it was documented
  first: a new detector with no cited basis is incomplete, the same way
  an untested one is.

  **Enforced since #73's content pass.**
  `tests/test_research_corpus.c :: test_every_citable_alert_kind_is_cited`
  fails when an `ALERT_TYPE_*` with a MITRE technique has no document in
  `research/**.md` naming it. Adding a detector therefore means adding
  its source, in the same change, or the suite goes red and names the
  kind in its output.

  The exception is deliberate and narrow, and it has two forms. The
  first is a rule reporting sloth's **own operational state** rather
  than an adversary: `ALERT_TYPE_NO_MONITOR_MODE` is still the only one,
  and there is no CVE, advisory or clause to cite for it, so it is
  excluded from the coverage count rather than treated as a gap.

  The second arrived with #80 and is **not** the same thing: a finding
  that has a real, citable basis but no honest *ATT&CK technique*,
  because what it reports is a posture or an exposure and not an
  adversary's behaviour. `ALERT_TYPE_OPEN_SETUP_AP` (#80),
  `ALERT_TYPE_CAM_WS_DISCOVERY` (#106),
  `ALERT_TYPE_SURV_CLOUD_SNI` (#105),
  `ALERT_TYPE_TPC_ABSENT_HIGH_BAND` (#101) and
  `ALERT_TYPE_CAM_SETUP_SSID` (#106) are the five today — and this
  sentence has already said "the three" twice while the set grew, so
  **do not trust the count here**: the list in the test below is the
  authority, and it is the thing that fails. (Two other kinds,
  `ALERT_TYPE_ATTACK_PATH` and `ALERT_TYPE_WEAK_TLS`, also return `""`
  and are on neither list; they predate this rule and are a third,
  undocumented shape. Someone should decide which form they are.) These
  are *not* excused the citation — the rule here is about the source,
  not the technique, so each is named explicitly in
  `tests/test_research_corpus.c ::
  test_uncitable_kinds_with_a_real_basis_are_still_cited`, which asserts
  both that the technique is empty and that a corpus document cites the
  kind. A new rule in that position belongs on that list.

  So: if you want the exemption because there is no ATT&CK ID, say which
  form and add the list entry. If you want it because there is no
  source, the detector needs a source, not an exemption.

  Adding a document: `docs/wiki/research-corpus.md`. One source may back
  several kinds — group by source, not by alert.

- **A test that asserts absence is worthless until it has been seen to
  fail.** "X does not happen" passes identically when the test
  exercises nothing, so mutate the guard or revert the fix, watch the
  new assertion go red, then restore — and only then write the comment
  claiming coverage. Three tests in one session on 2026-10-13 were
  green for the wrong reason; agents/converge.md step 5 has them. Where
  a case provably cannot be isolated, the comment says that instead of
  claiming the case.

- **Test helpers are code, and the sanitiser treats them as code.**
  Size a frame buffer to the frame actually built, not to a round
  number: `memset(f, 0, 64 + payload_len)` over a `uint8_t f[64]` is a
  stack overflow that ASan will fail the suite for, and it is the test
  that is wrong, not the gate.

- **Change-only emission must bucket its continuous values.** The JSONL
  writer suppresses a record whose signature is unchanged, so putting a
  raw monotonically-moving value — a seconds-since counter, a byte
  total — into that signature defeats the suppression and turns a
  change feed into a once-per-second firehose. Quantise first:
  `stale_secs` enters the `sensor_health` signature as the three-state
  `stale_state()` bucket, not as itself. Heartbeat is what guarantees
  liveness; the signature's job is to encode *meaningful* change.

## Conventions

- **Commit messages.** Imperative subject line, blank line, optional
  body explaining the *why*. End with the `Co-Authored-By` trailer.
- **Branches.** Work on `main`. No long-running feature branches.
- **Pushes.** Push after each green commit. The user reviews on GitHub.
- **`git add` specific files.** **Never** `git add -A` or `git add .`.
  A local `wifi-sigint/` directory must never be staged or pushed.

## Wiki — keep it complete and synced

`docs/wiki/` is the **complete information source for sloth** and the
single source of truth. The [GitHub wiki](https://github.com/SpaceTrucker2196/sloth/wiki)
is a render of it, published by `.github/workflows/wiki-sync.yml` on every
push to `main` that touches `docs/wiki/**` (script:
`.github/scripts/wiki_sync.sh`). Never hand-edit the GitHub wiki — it is
overwritten. Full mechanism: `docs/wiki/wiki-maintenance.md`.

- **A behaviour change updates the wiki in the same change**, the same way
  a code change ships with its test. Concretely:
  - new or changed CLI flag / keybinding → `docs/wiki/cli-reference.md`;
  - new view → `docs/wiki/views-catalog.md` (plus the per-view doc the
    "add a view" checklist already demands);
  - new alert → `docs/wiki/alerts.md` (plus the `research/` citation
    enforced by `tests/test_research_corpus.c`);
  - new Wi-Fi vulnerability class or 802.11 generation →
    `docs/wiki/wifi-state-of-the-art.md` (the repo's living Wi-Fi radar);
  - any new concept page → link it from `docs/wiki/index.md` and append a
    line to `docs/wiki/log.md`.
- **Page format** (`docs/CLAUDE.md`): `**Summary**`, `**Sources**`,
  `**Last updated**`, content, then `## Related pages`.
- Editing anything under `agents/` scores +40 on the risk gate
  (`agents/FACTORY.md` §10.3). Editing `docs/wiki/` does not — wiki
  updates are meant to ride along with the change they document, not to
  be gated.

## UI conventions

- Terminal **backgrounds are disabled** — rows render on the terminal
  default. Don't reintroduce row tints without asking. One sanctioned
  exception (owner-requested, 2026-08-10): rows sourced from the
  passive monitor radio render on dark grey (`CP_MON_ROW*`, xterm 236)
  wherever the 802.11 stream interleaves with the IP capture, so the
  operator can tell per row which interface heard what.
- **IP palette = Fallout phosphor**: 8 hash-derived colours orbiting
  the project's teal phosphor base. Same IP → same colour everywhere.
  IPs appearing in ≥2 dashboard sources render **bold**.
- **SSIDs** use the same 8-colour palette via a separate hash.
- **Brand colourisation** in hostnames: `google` → G-o-o-g-l-e in
  blue/red/yellow/blue/green/red (logo); `firefox` → orange;
  `cloudflare` → red; `example.org` → grey. Case-insensitive substring
  matches (`tui_brand_addstr`).
- **Box-drawing**: panel titles use `── name ──` (U+2500). `->` is `→`
  (U+2192). Reserved macros `G_VERT`, `G_TL/TR/BL/BR` are available for
  future framing.
- **Sparklines** are heat-graded by level (cool phosphor → peak red)
  with `_` for zero / missing samples. They stretch to fill any width.
- **Dashboard layout** is a 7-band tile filling the terminal:
  iface (height = iface_count), conn + top-hosts (= 2H), packets (= 2H),
  three 3-panel rows at H each, dns/icmp at H. Min terminal 100×33.

## Hard "don't"s

- Don't run destructive git ops (`reset --hard`, `push --force`, branch
  delete) without explicit user authorisation.
- Don't add new files at repo root; everything has a home (`src/`,
  `tests/`, `docs/`, `include/`).
- Don't stage `wifi-sigint/`, `sloth`, or `sloth_test`.
- Don't reintroduce coloured row backgrounds (deliberately removed).
- Don't bypass git hooks (`--no-verify` etc.) unless explicitly asked.
- Don't push directly to a branch other than `main` without asking.

## How to add a new view

1. Add one `X(ID, label, key, slug)` line to `include/sloth_views.def`
   (its position is the tab order); the enum, `VIEW_COUNT`, the label,
   the `tui.c` dispatch and the `main.c` key case are generated from it.
2. Add state fields (ring buffer + count + sel) on `sloth_state_t` only
   if the view needs a snapshot; prefer an accessor on the module.
3. Add the data type / log entry struct.
4. Create `src/views/<name>.c` + `.h` with `view_<name>_draw` and
   `view_<name>_key`. Add the `.c` to `CORE_COMMON_SRCS` once.
5. If the view has any *view-local* action bound to a letter that the
   global switch already uses, add a claim in `src/view_route.c ::
   view_claims_key()` and cover it in `tests/test_state.c` (#13).
6. Run `make docs-counts`.
7. Write a `tests/test_<name>.c` with at least: empty-state,
   populated-state render, nav, and any protocol-specific parse tests.
8. Write a `docs/views/<name>.md` and link it from `README.md` and
    `docs/views/README.md`.
9. The full build surface (Discipline, above) before committing.

## How to add an alert rule

1. Add one `X(NAME, "NAME", "T1xxx")` line to `include/sloth_alerts.def`
   (empty technique only under the documented exceptions), then
   `make docs-counts`.
2. Write a `rule_<name>(state, now)` function in the domain file under
   `src/alerts/` (`rules_wired.c`, `rules_wifi_mgmt.c`, `rules_twin.c`,
   `rules_enterprise.c`, `rules_mle.c`) that calls `fire(...)`; build its
   key with the `akey_*` builder (#112), never `snprintf` of a remote
   string.
3. Add its row to `src/alerts/rules_table.c` — the table order is the
   run order, and `test_rule_order_dependencies` pins the pairs that
   matter.
4. If the alert has a known target IP, pass `match_ip` + `match_port`
   to `fire()` so per-alert pcap export works.
5. Add a row to the rule table in `docs/views/alerts.md`.
6. Test: seed state that should trigger the rule, run `alerts_update`,
   assert `find_alert(type) >= 0`.

## Style

- Terse, technical, no marketing language in code or docs.
- Comments explain *why*, never *what* (the code shows what).
- C99 only. No GNU extensions unless gated and explained.
- Variable column widths in views should flex with panel width — fixed
  widths are a smell.
- Errors at boundaries only (user input, syscalls, parsing). Trust
  internal code.

## When you don't know

- Read `docs/views/<view>.md` for protocol context.
- Read the existing `tests/test_<x>.c` for the canonical usage of `<x>`.
- The platform vtable (`platform_ops_t` in `sloth.h`) is the seam to
  the kernel; views must never call platform ops directly — they read
  from `sloth_state_t`.

## Token / Cost Ledger

The owner bills from `LEDGER.md` (exact, never estimated). After every
substantive commit: run `~/.claude/billing/ledger.py --append --summary
"<desc>"`, then commit `LEDGER.md` as its own `chore(ledger): <sha>`
commit. Never hand-author, estimate, or rewrite rows (append-only); if
the script can't produce a row, stop and surface it. See
`ledger.py --help` for flags (`--dry-run`, `--commit <sha>`).

Energy (optional, read-only): `~/.claude/billing/ledger.py --energy-total` estimates the rough datacenter kWh behind the whole ledger; `--energy` adds a per-row estimate. Order-of-magnitude only.
