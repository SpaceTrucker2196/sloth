# sloth v1.8.4 — WPS attack detection and tunable thresholds

Weekly patch release, and the first since v1.8.1 to add alert types:
the alert-type enum goes **61 → 64** with the three WPS rules (#82).
`VIEW_COUNT` stays **35** — no new views.

Two things carry this release. The first is that #82's WPS work reached
its verdicts: v1.8.3 shipped the EAP-WSC decoder as parse-only, waves 6
and 7 added the session table and the lockout ring as measurement, and
`d652502` lands the three rules on top with their research-corpus
sources. The second is that every behavioural threshold in the tree —
23 of them, not just the WPS counts — moved from a `#define` to a
`--tune` registry (#82, `4206fe7`), because the owner's acceptance of
the WPS thresholds was conditional on each being configurable and
nothing in the tree could satisfy that.

Alongside those: exporting crackable material is now opt-in with a
7-day retention sweep (#87), sensor health gained measured dwell, hop
activity and four more eviction counters (#91), the capture path is
finally reachable by the sanitizers through the real `pcap_dispatch`
callback (#95), the shipped binary builds hardened (#95), the capture
scope allow-list counts its refusals and refuses an interactive `[m]`
retarget (#85), and the regulatory IE parsers landed inert (#101).

**No issues closed on this release.** Twelve advanced and were
deliberately left open (#45, #82, #85, #86, #87, #90, #91, #92, #95,
#96, #101, #103). Suite went **11229 → 12254 assertions**.

---

## ⚠️ Upgrade notes — read before upgrading

**No schema bump. `DB_SCHEMA_VERSION` stays 4.** An existing v4 `--db`
file opens unchanged. **JSONL is additive only** — new fields, no record
type or field removed, renamed or re-typed. **No CLI flag was renamed
or removed**; eight were added.

Even so, two #87 changes can turn a working v1.8.3 invocation into a
refused one — or delete files it wrote:

**1. `--eapol-dir` alone now exits 2 (#87).** Writing PMKIDs and 4-way
handshakes is gated behind a new `--collect-handshakes` opt-in, off by
default. `--eapol-dir DIR` without it does not warn and continue; it
refuses at argv time and returns 2, because an operator who named a
destination for crackable material and got a running sloth would
reasonably read that as the export happening. **Any init unit, script
or cron entry passing `--eapol-dir` today will fail to start on
v1.8.4 until `--collect-handshakes` is added.** Detection, alerting,
the `[e]` view and the JSONL/`--db` `eapol_events` records are
unaffected by the flag — only the `.22000` lines and the per-handshake
pcaps are gated. The inverse (`--collect-handshakes` with no
`--eapol-dir`) warns and runs.

**2. Exported handshake material is now deleted after 7 days (#87).**
`--handshake-retention DAYS` defaults to **7** and sweeps at startup
and once a day while running. On the first v1.8.4 run with
`--collect-handshakes --eapol-dir DIR`, every artifact in DIR last
written before the window **is unlinked**. If you are keeping older
exports in that directory, copy them out first or pass
`--handshake-retention 0` to keep forever. Granularity is whole-file by
mtime, so `eapol.22000` goes only once nothing has been appended for
the whole window — the 22000 format has no per-line timestamp.
Deletion goes through the dirfd pinned at startup, entries are
`fstatat`'d `AT_SYMLINK_NOFOLLOW`, and only regular files are unlinked,
so a symlink planted at an artifact name cannot redirect a deletion out
of the export directory.

**3. A bad `--tune` exits 2 (#82).** An unknown knob name, a
non-integer, a missing value or an out-of-range number refuses the run
rather than falling back to the default. `ssh.brute` is not accepted as
an abbreviation of `ssh.brute_force`. This is the design point: a knob
the operator believes they set but did not is worse than no knob,
because the run looks tuned and behaves stock.

New flags this release, all additive: `--tune`, `--tune-list`,
`--collect-handshakes`, `--handshake-retention`,
`--wps-pin-brute-cycles`, `--wps-lockout-cycles`,
`--wps-pbc-concurrent`, and the `--data-socket-allow-remote` /
`--eapol-dir` / `--pcap-dir` spellings carried from v1.8.3.

**Also worth knowing, not breaking:** a raised `--tune` threshold can
silence a detector, which is indistinguishable from a quiet segment.
`sensor_health` therefore exports `tuned_count` and `tuned` (the knobs
themselves, not just a count — a count would not say which rule went
quiet), and the Interfaces health strip renders a fault-only
`tuned N/M` token.

---

## New alert types (#82)

Three rules, each with its citation on file — `ALERT_TYPE_*` without a
research-corpus source turns `test_every_citable_alert_kind_is_cited`
red, which is why waves 6 and 7 stopped at measurement. Thresholds are
the owner's decision of 2026-09-30; only the **counts** are tunable,
because the 60 s, 1 h and 120 s windows are protocol facts rather than
preferences.

| Alert | Severity | Rule | Source |
|-------|----------|------|--------|
| `WPS_PIN_BRUTE` | CRIT (T1110.001) | ≥5 M1→M3→EAP-NACK restart cycles in 60 s | CERT/CC VU#723755 — WPS PIN brute force (Viehböck, 2011; CVE-2011-5053) |
| `WPS_LOCKOUT_CYCLING` | WARN; CRIT on `--my-bssid` (T1110.001) | ≥2 completed locked→unlocked cycles per hour | same advisory, lockout clause |
| `WPS_PBC_RACE` | CRIT (T1557) | >2 live unfinished WSC registrations on one BSSID inside the 120 s walk time | WSC 2.0 PBC walk time and session overlap, as implemented in hostap `src/wps/wps_defs.h` (`WPS_PBC_WALK_TIME`, `WPS_CFG_MULTIPLE_PBC_DETECTED`) |

One `WPS_PIN_BRUTE` cycle is one refused PIN guess, and the EAP-NACK is
the oracle VU#723755 describes — which is exactly why it is countable
off the air without sloth sending anything. The rule fires in two
shapes: per station, and per UUID-E across **≥2** stations, because an
attacker rotating the MAC the AP rate-limits on leaves the enrollee
identity inside M1 alone. The rotating pass requires two or more
stations so a plain Reaver run is never reported twice.

`WPS_LOCKOUT_CYCLING` is the same attack read from the victim's side,
and it matters because the lock bit rides every beacon while the EAP
exchange is a brief unicast burst a hopping radio usually misses. An AP
that locks once and stays locked is a posture, not an attack, and never
fires.

`WPS_PBC_RACE` is gated on that AP's beacon advertising Device Password
ID `0x0004`. WSC's own session-overlap rule makes the condition an abort
(Configuration Error 12, *Multiple PBC sessions detected*), so the CRIT
reports a protocol error rather than an inferred intent.

The substrate landed first and is unchanged by the rules:
`440d514` added `wps_track.c`, a bounded LRU table keyed (BSSID, STA)
running the WSC 2.0 §7.7 state machine IDLE→M1_SEEN→M3_SEEN→NACKED/DONE
over the inner EAP packets `eap_track` already sees — a NACK completes a
restart cycle only when it follows M3, since M1→NACK is an ordinary
M2D-style refusal and counting it would inflate every brute-force figure
with normal traffic. `4a5d036` added a `WPS_LOCK_RING(8)` of transitions
between *known* lock states per BSSID; a beacon that merely omits the
attribute records nothing.

---

## One tunable registry for every threshold (#82, `4206fe7`)

Owner decision 2026-10-04 settled the surface: one repeatable flag over
a named registry, not ~20 flags, since one flag per threshold would mean
a new permanent CLI contract for every future detector.

```
sloth --tune dns.tunnel_label_thresh=40 --tune ssh.brute_force=20
sloth --tune-list
```

`src/tune.{c,h}` holds 23 rows indexed by a `tune_id_t`, so a detector
reads an array slot rather than comparing strings on the hot path; the
name exists for the CLI, `--tune-list` and the export. Each row carries
its shipped default, a range and a unit. Bounds exclude only values that
would make a rule meaningless — a count below 1, a zero-length window —
not values an operator who knows their segment might legitimately want.

The 22 `#define`s and `KARMA_SSID_THRESH` now expand to `tune_val(...)`,
so every use site is untouched. That was deliberate: had any site needed
a compile-time constant it would have failed the build rather than
quietly changing meaning. Before this, every behavioural threshold in
`src/alerts.c` was a `#define` and sloth had exactly one `getenv`
(`NO_COLOR`).

---

## Crackable material is opt-in, with retention (#87, `f8fd5e8`)

See upgrade notes 1 and 2 for the operator-visible half. The reasoning:
#87's earlier slices made the export private on disk (0700/0600, by
descriptor, validated never repaired), which bounds who can read the
file and does nothing about the file existing at all. A PMKID or a
paired M1+M2 supports offline password guessing by whoever gets a copy,
so its lifetime on disk is the remaining exposure.

The gate is about **writing only**, and that boundary was checked
against the code rather than assumed: the EAPOL-Key parser, the M1..M4
attempt state machine, the replay-counter pairing verdict, the
PTK-generation counter `src/fragattack.c` reads, M3 association
evidence, the `[e]` view and the JSONL / `--db` `eapol_events` records
all run unchanged with the gate closed. Only
`append_22000_line_for_bssid()` and `write_handshake_pcap()` are gated,
and both re-check `g_collect` at the last statement before material
becomes a file, so a future caller cannot route round
`eapol_set_output_dir()`'s refusal. Blinding the detector would have
cost detections and protected nothing, since nothing crackable leaves
the process.

Retention follows `src/db.c`'s existing shape — a window, a last-run
clock, a scheduling wrapper the poll loop calls — rather than
introducing a second scheduler. A skipped entry or a failed `unlinkat`
is counted and surfaced through the existing `sfile_fail` path (stderr,
the `[e]` header, `storage_eapol_failures`) instead of being swallowed.

---

## Sensor health: measured, not planned (#91)

Three slices, each replacing a number the code believed with one it
measured.

**Hop activity from the monitor radio's own frames (`8e3e971`).**
`chanhop_observe()` was fed `s->pkt_total`, the general capture counter,
so traffic on a wired management port lengthened the dwell of whichever
channel the radio happened to be parked on — an RF heuristic steered by
packets that never touched the air. It now takes the delta of
`mon_frame_total()`. On top of that, per-channel visit and frame tallies
that **do not decay** (the scheduler's own `activity` decays
deliberately, which makes it useless for answering "did this ever hear
anything"). `chanhop_activity()` reports channels, lifetime visits and
frames, and the count of channels visited at least once that have never
produced a frame. An unvisited channel is not silent, only unmeasured,
and is excluded. That silent count is the tell for a retune that reports
success and does not take — the scan bar looks identical either way,
because the bracket moves regardless. Surfaced as `hop silent 2/4` on
the interface health strip and six additive JSONL fields;
`hop_channels == 0` states plainly that hopping is off rather than
leaving a consumer to read absent fields as silence.

**Measured vs planned dwell (`bdb5608`).** A dwell is only ever serviced
when the poll loop next runs, so a 250 ms plan under a 1 s poll parks
the radio for a full second — every channel's airtime is four times what
the scheduler believes, and nothing said so. `chanhop_tick()` now closes
out each dwell as it ends, recording planned and measured milliseconds;
measured spans start-of-dwell to start-of-next, so the servicing delay
lands inside the figure rather than vanishing between them.
`chanhop_dwell()` reports the last pair, lifetime means, a
worst-overshoot high-water mark, and the completed count that is the
means' denominator. Both means are exported, so a consumer can read the
ratio without knowing sloth's poll interval; the health strip renders it
only when the lifetime means diverge by half again or more, judged on
means rather than the last dwell so one slow tick does not flap the
line.

`chanhop_init()`'s "zero everything" loop named three slot members and
missed the rest, so both slices' new counters started as stack garbage —
three tests caught it in the first, and the second replaced the loop
with a `memset` over the whole struct, ending the pattern rather than
patching its latest instance.

**Four more eviction kinds (`5b0bcda`).** `beacon_ap`, `seqnum_client`,
`assoc_pair` and `assoc_req` — the assoc module has two bounded tables,
and omitting one would read as "no loss" where it means "not measured".
Bumped at each LRU-eviction site and emitted through the existing
`sensor_health` loop. Update-in-place paths do not count: only a new
identity displacing a resident one is a lost observation.
`440d514` adds `evict_wps_session` on the same terms.

---

## Assurance: the capture path under the sanitizers (#95)

v1.8.3 put ASan/UBSan, TSan and cppcheck in CI as blocking jobs. They
could not see the code that matters most.

**The capture path now runs through the real callback (`557b879`).**
`sloth_test` is built without `WITH_PCAP`, so `on_packet()`, the scope
election and the whole `decode_frame()` dispatch — every line that
consumes attacker-controlled bytes off the air — were absent from every
ASan, UBSan and TSan run. Seeding `sloth_state_t` exercises the tables,
never the parser that fills them. `capture_test_dispatch()` builds a
libpcap savefile **in memory**, written from the format spec, and hands
it to `pcap_fopen_offline()` through `fmemopen()`. No device, no file,
so `tests/` stays free of `.pcap` fixtures and the frames stay
hand-built byte arrays per AGENTS.md. A second binary,
`sloth_test_pcap` (`make test-capture-path`), links libpcap and runs
only this suite; CI runs it in the default, ASan/UBSan and TSan jobs.
The roadmap suggested `pcap_open_dead()`, which builds a `pcap_t` with
no packet source — right for `pcap_dump`/`compile`, useless for
dispatch.

Two findings came from the suite's first runs rather than from
reasoning. ASan caught the frame builder overrunning its own callers'
64-byte buffers (`memset(f, 0, 64 + payload_len)`), fixed to zero
exactly the frame it builds. And `decode_frame()` ends both IP arms with
`return 1`, reporting "this was an IP ethertype", not "this decoded" —
so a malformed IPv4 frame takes a ring slot as a blank row and bumps
`pkt_total`, meaning a stream of them evicts real packets from the
256-slot ring and inflates the counter at no cost to the sender. **Left
asserted as-is** in `test_undecodable_ip_still_occupies_a_ring_slot`
rather than quietly changed: it is a behaviour decision for the owner,
and the test names itself if the arms are ever made to propagate the
result.

**Sanitizer builds of `sloth` itself now link (`321c78c`).** `make
EXTRA_CFLAGS=-fsanitize=address,undefined` could not build the shipped
binary: the link rule carried no compiler flags, so all 140-odd objects
compiled instrumented and `ld` failed with 10,383 undefined `__asan_*`
references. The consequence is the gap, not the error message —
`src/main.c`, the libpcap capture path and the ncurses renderer exist
only in `sloth`, never in `sloth_test`, and CI's sanitizer jobs ran
`make test` and nothing else, so those three bodies of code had never
been compiled *or* linked under any sanitizer. The fix is `$(CFLAGS)` on
the `$(TARGET)` link line. `tests/test_build_recipe.c` states the
invariant as an assertion over all link rules rather than over one line
number, so a binary added later is covered too, and the `sanitize` job
now builds `sloth` and `embedded`. Linking is the entire assertion —
MISSION.md §2 forbids running sloth against an interface and CI has
none, so nothing there executes the binary.

**The shipped binary builds hardened (`b12f882`).** `sloth` and
`embedded` always compile with `-fPIE -fstack-protector-strong
-D_FORTIFY_SOURCE=3` and link `-pie -Wl,-z,relro,-z,now` on Linux.
Deviated from #95's literal `_FORTIFY_SOURCE=2`: this repo's CI host
already defaults to level 3, so hardcoding 2 would have silently
downgraded it, and glibc degrades a requested 3 on a toolchain that
cannot support it. Honest finding recorded with it — every one of these
properties was *already* gcc's default on this host, so the new `harden`
job's `readelf`/`nm` binary checks stayed green through a full revert of
the Makefile block and would not have caught a regression; the job's
greps of the emitted compile and link command lines do go red, and are
the real guard. Scoped to `sloth` only, not `sloth_test`, which is a
`-O0 -g` artifact nobody runs in production.

**The last T11 concurrency item (`0f22370`).** The `[y]` toggle
`memmove`d `s->iface_deselected[]` on the main thread while
`on_packet()` walked the same array per packet, so a torn read could
match a half-copied name or index past the count mid-shrink. The
callback now consults only a snapshot inside `capture_policy_t`, written
under the module's existing `g_mu`. A toggle lands on the next poll tick
rather than the next packet — the same latency the scope-health numbers
already have.

Two cppcheck suppressions and one correction, all CI-red fixes:
`834dc63` (`readdirCalled` for #87's sweep, with the verified reason
that `sweep_locked()` `fdopendir`s a dup of the pinned descriptor into a
local `DIR*`), `f8ae668` (`main()` over cppcheck's normal ValueFlow
budget once `--tune` landed on top of the three `--wps-*` flags — the
existing entry for `beacon_parse_ies()` predicted exactly this), and
`a2cf5a3`, which is the lesson worth recording: a **bare `#`** used as a
paragraph separator in `tests/cppcheck.supp` is parsed as a suppression
with no id, and the whole list is rejected before anything is analysed —
which is why the failure message named no file.

---

## Capture scope as an authorization boundary (#85)

**Refusals are counted (`cb19f70`).** `scope`/`scope_enforced`/
`scope_generation` said whether the boundary was intact; nothing said
whether it was being tested. `capture_frame_in_scope()` now bumps a
lifetime counter whenever an active allow-list refuses a frame — an
unattributable ifindex, a non-SLL2 or short frame, or an index with no
valid pin — deliberately excluding the runtime `[y]` deselect, which is
an operator toggle rather than an authorization failure. Exported as
`sensor_health.scope_dropped`.

**An `[m]` retarget outside the allow-list is refused (`1b3cc00`).** The
Interfaces view's `[m]` key retargeted the monitor radio onto any
interface mid-run with no check, and the monitor stream has no per-frame
scope test of its own to catch it — a single keystroke moved collection
outside the scope the operator declared at launch. The check lives in
`probe_set_iface()`, not in `view_iface_key()`, so a second caller
cannot reintroduce the hole silently, and it runs before `probe_stop()`
so a refused retarget does not cost a capture already running.

**And the asymmetry is now documented as policy (`bc316f5`).** Owner
ruling 2026-10-04: the 802.11 monitor stream stays **outside** the
`--iface` allow-list, because narrowing `probe_open()` would silence
802.11 collection for a plain `sloth --iface eth0` run. That makes
`docs/wiki/jsonl-schema.md`'s claim under `scope_not_enforced` —
"Out-of-scope traffic is never collected in any state" — **wrong rather
than merely premature**, so it is corrected rather than left pending.
The allow-list scopes the IP capture stream plus the `[m]` retarget, and
nothing else; a consumer needing "only these interfaces" has to scope
the radio out of band with `--monitor-only` or a host with no
monitor-capable adapter. This was the more dangerous kind of
documentation error: it told an analyst reading an export that a
boundary held.

**Enforcement is tested through the real callback (`385085a`),** which
the #95 seam made possible: every prior scope test called
`capture_frame_in_scope()` directly, proving the predicate and not the
callback meant to consult it. 8 cases, +64 assertions, driving
`pcap_dispatch` → `on_packet()` with hand-built SLL2 frames, including a
pin whose valid bit was cleared and an `EN10MB` frame that decodes
without an allow-list and is refused under one. Verified non-vacuous
rather than assumed: disabling the check turns all six refusal cases red
and leaves both controls green.

`47a9d52` surfaces `probe_err` in the Interfaces view — the one place an
operator's `[m]` keystroke actually lands, and where a refused retarget
previously produced no feedback at all.

---

## Regulatory IE parsers, deliberately inert (#101, `6ff3385`)

Sloth read no regulatory element at all (`grep -cE
'country_ie|power_constraint|tpc' src/` was 0), leaving the cheapest
non-compliance signal in 802.11 invisible: a 5 GHz AP that names no
country, which is the hostapd/OpenWrt stripped-build default and the
shape most rogue kits ship in.

Slice 1 parses Country (tag 7, 802.11-2020 §9.4.2.8), Power Constraint
(tag 32, §9.4.2.13) and TPC Report (tag 35, §9.4.2.16) into a
`reg_ie_t` and **nothing else happens** — no regulatory table, no
channel-legality decision, no alert type, no field on `probe_ap_t`, no
view, no JSONL record. Reading a claim is not judging it, and the
judging half needs a versioned regulatory table this half must not
pre-empt.

Two places a naive parser goes wrong, both pinned by tests: the Country
String's third octet has **five** forms, not three (`' '`, `'I'`, `'O'`,
`'X'`, or the *binary* Annex E operating-class number — hostapd emits
`0x04`), and anything else is `REG_ENV_UNKNOWN`, because inventing "any"
for an undefined octet would put a regulatory assertion in the record
that never went over the air. And the triplets are two structures
sharing one shape, decided per triplet by the first octet: ≥201 is an
Operating Extension Identifier, below it a subband. Read the wrong way,
global class 81 reports "channel 201, 81 channels, 3 dBm" — plausible
enough to pass unnoticed. Max TX power and both TPC fields are signed;
unsigned turns −2 dBm into 254 dBm.

It reaches frames through the existing unified `beacon_parse_ies()`
seam as one optional NULL-safe out-parameter, the same seam the monitor
path and the nl80211 managed path already share, so the two cannot
diverge on regulatory depth the way they once did on RSN depth. Every
caller passes NULL today. Triplets are capped at 16 with a
`triplets_truncated` flag rather than stored unbounded — a hostile
element can claim 84, and a silently clipped list reads as a short list.
Country-code *content* is stored verbatim and not validated; whether
"ZZ" names a country is the regulatory table's question, in slice 2.

---

## Forensics and evidence honesty (#92, #90, #96)

**Real captured length in handshake pcaps (`35838d2`).** A pcap record
header carries both `caplen` (bytes stored) and `origlen` (the frame's
own length); `src/eapol_log.c` wrote the truncated copy's length as
both, so every record in a handshake export claimed the frame really was
as short as the 512-byte buffer sloth kept, and an analyst could not
tell a genuinely short frame from a truncated one.
`m_frame_origlens[]` now carries the frame length alongside
`m_frame_lens[]` and the writer emits the two independently;
`caplen <= origlen` holds for every record. Scope correction from
adversarial review, and it matters for an issue about not over-claiming:
`origlen` is **not** the on-wire length. `on_probe_frame()` derives its
length from `hdr->caplen`, not `hdr->len`, so what is plumbed through is
libpcap's captured length with radiotap removed. The radio opens at a
65535 snaplen so the two coincide for any real 802.11 frame, but it is
not the wire length by construction, and all three places that said
"what was on the air" now say "as captured" and state the caveat.

**A cannot-persist badge on the tab bar (`54fc919`).** Every export sink
already counted its write failures and kept retrying — one stderr line,
then silence. The JSONL `sensor_health` record sums them for a log
consumer, but a console operator saw nothing unless they sat on the one
view rendering its own sink's counter, and a sensor that detects but
cannot persist is quietly not doing its job. `persist_badge()` formats
`!persist jsonl:3 pcap:1 eapol:2`, naming only failing sinks, from the
same accessors `sensor_health` sums — so badge and log can never
disagree — and both tab bars render it in the alert heat grade, so it is
visible from every view. The `statvfs` capacity guard stays a later
slice.

**KARMA_AP's benign readings are named (`ee79274`).** The rule row named
one benign explanation where MY_NET_RECON's row (the #94 precedent)
names four. The substantive point was an overlap implicit in two places
and stated in neither: `docs/views/karma.md` puts legitimate multi-VAP
gear at 1–4 distinct SSIDs and `KARMA_SSID_THRESH` is 3, so lawful 3- or
4-SSID gear crosses the bare count **by design**. Both docs now say so.
Deliberately narrow — an earlier draft was rejected in review for adding
~1.4 kB of mechanism prose making claims the code does not support,
and writing false mechanism into the row that exists to stop
over-claiming is the wrong trade.

---

## The wiki is the complete reference (#103, `bf5a23b`)

Seven new concept pages make `docs/wiki/` the complete information
source: `how-wifi-works`, `what-sloth-does`, `monitor-mode`,
`where-exploits-happen`, `wifi-sigint-techniques`, `cli-reference`,
`wifi-state-of-the-art`, plus `wiki-maintenance` documenting the
source-of-truth model. The wiki was previously a scattered set of
detector pages with no from-scratch reference to Wi-Fi itself, no CLI
page, and no published mirror. Agents keep it current by rule and by
machine: a "Wiki" duty section in `AGENTS.md` and `docs/CLAUDE.md` ties
every behaviour change to its wiki page, and
`.github/scripts/wiki_sync.sh` + `wiki-sync.yml` render `docs/wiki/` to
the GitHub wiki on every push to `main`.

Data-socket documentation was finished in the same period:
`5a2c4cf` moved the remaining 45 copyable `unix:/tmp/sloth.sock`
invocations to `/run/sloth.sock` (four files carried both spellings at
once), completing the sweep v1.8.3's slice 3 started. `/tmp` is
world-writable, so a local user can pre-plant the socket path; since
`f2bf0b5` that is a denial of service rather than a hijack, but the
posture an operator copies out of the docs should not model a path
somebody else controls.

---

## The risk gate measures what it claims (#45, `7d0625c`)

Owner-approved calibration, measured and agreed before being written,
since weights are owner-review territory per FACTORY.md §10.3.
Measurement defects first, because the weights had been tuned against
the numbers these produced: an untracked entry ending in `/` is git
declining to descend into a nested repo, not a file, and `wc -l` on it
printed "Is a directory" while still scoring as an added file;
untracked binaries were line-counted, so two stray `sloth.bak-*`
release backups contributed 3,760 lines of phantom churn and scored a
**clean working tree at 45/50**, one point under the threshold; and
because the default mode was unusable, scoring fell back to an explicit
range where untracked files are invisible to `git diff` entirely — the
WPS slice scored 50 before its commit and 80 after, same diff, with the
pre-commit number being the one the loop acts on.

Then the weights. The contract proxy scored any touch of the schema doc
at +30, so adding a field **the documented way** — `jsonl.c` at +20 plus
its schema entry at +30 — summed to exactly the threshold: following the
repo's discipline guaranteed a halt, and a real break scored 50 too, so
the gate gave one answer to both questions. `dark-factory.md` §4.3
already draws the line correctly, naming the stop-and-ask as changing
the schema "in a non-additive way"; the weights now implement that —
additive-and-documented is +10, narrowing keeps +30. Source-deletion
proxies gain a 10-line floor, since `main.c` is a thousand lines of poll
loop and two deleted lines there are not a CLI flag going away
(`jsonl.h` is exempt, being small enough that one deleted line can be a
removed field). Measured over 14 real code commits: 4 scored at or above
threshold before, 0 do now, and a synthetic break still scores 50.
Enforcing mode is a live option in a way it was not before.

---

## Smaller, with a reason

- **`8d869ad`** — `data_socket_spec_tcp_port()` had no direct test. Its
  only coverage ran through `discovery_routable_tcp_port()`, which gates
  on `data_socket_spec_is_remote() == 1` and so can never reach a
  loopback spec: **the shipped default, `tcp:127.0.0.1:8765`, was the
  one path with no assertion at all.** Named as a known gap in the
  v1.8.3 reports and now covered, plus an agreement test, since
  `src/discovery.c` consults both exported views of one spec.
- **`04dea4c`** — those two functions each ran their own copy of the
  `parse_host_port()` + `inet_pton()` sequence, which was two chances
  for the exposure classifier and the advertised port to disagree about
  what the operator typed. Refactor only, byte-identical behaviour.
- **`4a1b779`** — the header claimed `-1` for "anything the binder would
  reject"; it only checks syntax, so `tcp:192.0.2.1:8765` returns 8765
  from a function documented as agreeing with a binder that refuses it
  without `--data-socket-allow-remote`. Comment only — over-claiming
  here is the kind of thing a caller gates on.

---

## Verification

Every variant built warning-clean and the suite green, on `origin/main`
at `fb4da62`, before the version bump:

```
make                  0 warnings
make WITH_NCURSES=0   0 warnings
make WITH_PCAP=0      0 warnings   (EXTRA_CFLAGS=-Werror)
make WITH_WIFI=0      0 warnings   (EXTRA_CFLAGS=-Werror)
make WITH_SQLITE=0    0 warnings
make embedded         0 warnings
make test             12254 assertions passed, 0 failed
```

CI on that SHA was green across CI, CodeQL and the Code Review job,
including the blocking `sanitize`, `tsan`, `cppcheck` and `harden` jobs.

Still no `.pcap` files in `tests/` — the new capture-path suite builds
its libpcap savefile in memory from the format spec, and every detector
test, including the WPS session cases and the regulatory IE parsers, is
hand-built bytes per the relevant IEEE or WSC clause.
