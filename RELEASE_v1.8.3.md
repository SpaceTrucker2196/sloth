# sloth v1.8.3 — strict by default

Weekly patch release. Like v1.8.2 it adds **no new views and no new alert
types** — `VIEW_COUNT` (35) and the alert-type enum are byte-identical to
v1.8.2. What it changes is what the shipped binary *does on its own*.

Until this release, "sloth never transmits, never scans, never changes
kernel state" was a property of how you invoked it. Reverse DNS ran by
default, the nl80211 scan trigger fired from the ordinary poll loop with
no policy check, and the QUIC decoder resolved on the capture thread
where no operator toggle could reach it. **Strict observation is now the
default** (#84), and there is one module that owns the policy every
subsystem asks.

Alongside that: the data socket gained an exposure guard and
close-on-exec (#86), the evil-twin family traded attacker-writable trust
anchors for an operator-supplied inventory (#89), capture scope is
pinned by ifindex instead of a stale name cache (#85), and the assurance
work (#95) put ASan/UBSan, ThreadSanitizer and cppcheck in CI as
blocking jobs — which then found and fixed four real defects.

Two issues closed on this release's code (#89, #94). Two more (#97, #98)
were closed administratively this week; their code shipped in v1.8.2.
Nine advanced and deliberately left open (#82, #84, #85, #86, #87, #90,
#92, #95, #96). Suite went **9304 → 11229 assertions**.

---

## ⚠️ Upgrade notes — read before upgrading

**No schema bump. `DB_SCHEMA_VERSION` stays 4.** An existing v4 `--db`
file opens unchanged. **JSONL is additive only** — new fields, no record
type or field removed, renamed or re-typed. **No CLI flag was renamed or
removed**; seven were added.

Four behaviour changes can turn a working v1.8.2 invocation into a
different — or refused — v1.8.3 run:

**1. Reverse DNS is off by default (#84).** Sloth now originates no
reverse-DNS traffic unless you pass `--allow-active`. The resolver
worker thread is not created at all in a strict run, so the guarantee is
a property of the process rather than a branch taken per lookup. If you
depended on numeric addresses resolving to names in the `[n]` toggle,
top hosts, or the packet detail pane, pass `--allow-active`. Names that
sloth **observed** passively — from the DNS/mDNS/NBNS/DHCP/SNI snoopers
— still resolve with no flag; only active lookups changed.

`--allow-active` deliberately does **not** restore resolution in the
UDP/443 QUIC decoder. That path runs per packet on the capture thread,
and re-enabling it behind a flag would reproduce the defect #84 names,
just less visibly.

**2. A routable data socket is refused without an explicit opt-in
(#86).** A `tcp:` spec outside 127.0.0.0/8 — including the `0.0.0.0`
wildcard — now requires `--data-socket-allow-remote`. The refusal names
the flag and offers an `ssh -L` one-liner; the permitted path warns,
naming address and port and the fact that the stream is unauthenticated
and unencrypted. **If you bind the data socket to a routable address
today, v1.8.3 will refuse to start until you add the flag.** Loopback is
the whole /8, so an operator already on 127.0.0.2 needs nothing. `unix:`
specs are unaffected.

**3. `unix:` data sockets are created 0600 (#86).** They were created at
the process umask — 0755 on a default 0022 host, i.e. world-connectable.
A consumer running as a **different uid** than sloth will now be refused
by the kernel. That plus the uid-ownership check is the peer
authentication that replaces the crypto the Captain ruled out (#100
records the TLS design; it is not scheduled). Socket examples in the
quickstart, landing page and interfaces doc moved from
`unix:/tmp/sloth.sock` to `unix:/run/sloth.sock` — `/tmp` is
world-writable and should not be modelled as a recommended posture.

**4. A replugged adapter under `--iface`/`--monitor-only` stays failed
closed until restart (#85).** The allow-list is pinned to
(ifindex, name) pairs before the capture thread starts. A rename, a
delete, or an index reused by a different device clears that pin for the
rest of the run. This is deliberate — the alternative is a stale cache
acting as an authorization source — but it means a hot-replug now needs
a restart rather than silently resuming. `capture_scope_state()` reports
`none` / `enforced` / `no_capture` / `degraded` so the blackout is
visible instead of silent.

New flags this release, all additive: `--allow-active`, `--strict`,
`--inventory`, `--site`, `--no-correlate`, `--correlate-retain`,
`--data-socket-allow-remote`.

**Known asymmetry, stated rather than papered over:** `--strict` locks
out the scan trigger but does **not** refuse `--hop`, and does not close
an opted-in routable data socket. `--hop` is parsed independently and
never consulted against the strict lock. `sloth --help`, README and
`docs/wiki/data-socket-exposure.md` were all corrected to say so
(`baa9638`, `6c33228`) after each claimed full coverage. Whether
`--strict` should refuse `--hop` is an open owner decision.

---

## Strict observation is the default (#84, slices 1–3 + docs)

Three slices, then two doc corrections, on the issue an external CISO/GRC
review filed as F02: the headline passivity claim was not backed by the
code.

**Slice 1 (`4315676`) built the seam.** `dns_lookup()` was the only
spelling of name resolution in the tree, so every caller that wanted "a
name if we have one" silently became a caller that generated
reverse-DNS egress on a cache miss. Now `dns_lookup_cached()` answers
only from metadata sloth already observed — and claims no PENDING cache
slot, because a refused miss must leave the cache indistinguishable from
one never taken, or the slot alone hands the next caller work it did not
ask for. `dns_resolve()` is the single choke point; `getnameinfo(3)`
appears exactly once in the tree behind it. `dns_resolver_stats()` is
the observable seam, and `getnameinfo_calls` is incremented inside
`resolve_ip()` rather than at the enqueue site, so the number means
"work that actually left the process" — a test asserts the two diverge.

**Slice 2 (`4374ff1`) decided the policy**, per the Captain's written
decision on the issue. `dns_resolver_set_enabled()` defaults off and the
worker thread is gated. `test_resolver_enabled_by_default` was inverted
to `test_resolver_disabled_by_default` — that assertion existed to make
this flip arrive as a deliberate edit rather than drift.

**Slice 3 (`b9aa686`) extended the policy to the paths it did not
cover.** New `src/observe.{c,h}` owns the run's observation policy,
because the scan trigger lives in the platform layer and discovery in
its own module, neither of which can sensibly depend on the DNS module.
`trigger_scan_async()` fired `NL80211_CMD_TRIGGER_SCAN` from the poll
loop with no policy check; the decision, the limiter and the message
construction are split into `linux_wifi_prepare_scan_trigger()`, which
returns 0 when either refuses, and the sending path opens no socket when
nothing was built. Counting at the builder rather than at `sendto(2)` is
deliberate: a request built and then dropped is still one the code was
willing to make.

The scan limiter is also now genuinely per-interface. It was one
function-static `time_t` shared across every radio, behind a comment
claiming per-interface limiting, so the first interface enumerated
consumed the whole budget and the rest starved. A dedicated monitor
radio alongside an uplink is the deployment this tool targets, so
"global" did not mean fair — it meant one radio preferred.

---

## Data socket hardening (#86)

The Captain's decision on #86 was **no crypto in sloth** — no OpenSSL,
no mbedTLS, no bearer tokens. That leaves the transport and lifecycle
half, and a boundary to write down in place of the crypto.

- **Listener lifecycle (`f2bf0b5`).** `init_unix()` unconditionally
  `unlink()`'d whatever sat at the socket path: a regular file, a
  symlink, or another process's live listener were all removed the way a
  dead socket was. `unix_path_removable()` now `lstat()`s the path,
  never follows a symlink, refuses anything not `S_ISSOCK` or not owned
  by our uid, and probes liveness with a `connect()` — `ECONNREFUSED`
  means stale and safe, a successful connect leaves the path untouched.
  `set_nonblock()`'s return value was discarded at all three call sites,
  leaving a blocking fd behind — a hazard under `g_mu`, where
  `accept()`/`send()` could stall while the mutex is held. Both are now
  checked. `init_tcp()`'s port parse was `strtol(s, NULL, 10)`, which
  took `"8080x"` as 8080; now checked against the full string.
- **Exposure guard (`1d19bc8`)** — see upgrade note 2. The check runs
  before `socket()`, so a bind nobody opted into never reaches the
  kernel.
- **Close-on-exec (`d3170da`).** Without `FD_CLOEXEC` any child sloth
  `exec()`s inherited the listener and every live client, and could
  `accept()` on or read the unauthenticated JSONL stream afterwards. The
  listener is created `SOCK_CLOEXEC|SOCK_NONBLOCK` and clients accepted
  with `accept4()`, so the flag is set atomically — a later `fcntl()`
  would leave a fork+exec window. Non-Linux targets use a checked
  `fcntl(F_SETFD)` and close the fd if it fails.
- **One exposure classifier (`8fc0cb0`).** `discovery_routable_tcp_port()`
  carried its own drifted copy of "is this spec routable": it named only
  `127.0.0.1` as loopback, so `tcp:127.0.0.2:8765` bound without the
  flag and discovery then advertised it over mDNS as a LAN service no
  other host can reach. It also read the port with `atoi()`. It now
  delegates to `data_socket_spec_is_remote()` and
  `data_socket_spec_tcp_port()`, so the advertisement can only describe
  what the guard allowed.

---

## Evil-twin findings get a trust anchor (#89, slices 1–3 — closed)

**Slice 1 (`09f7e2d`) removed three things the code treated as proof of
ownership**, all of them values an attacker writes into a frame:

- An **802.11k neighbour report** dropped a pair outright if either AP
  advertised the other. Nothing authenticates that frame, so an attacker
  advertising the AP it impersonates erased the finding — the
  suppression was an off switch handed to the adversary. It is now a
  confidence deduction that can never demote a severity backed by a hard
  signal.
- A **matching vendor OUI** is three bytes every rogue-AP tool can set.
  A same-OUI pair whose vendor-IE fingerprints contradict each other now
  fires; a same-OUI pair with no other signal stays quiet because it
  carries no positive evidence — a different fact from being trusted,
  and why a legitimate multi-BSSID deployment is still silent.
- **RSSI no longer names the impostor.** It is a fact about distance and
  antennas, and in the commonest case backwards: the operator's own AP
  is the closest radio in the room, which the old rule read as the
  rogue. Attribution now needs an operator designation, a tainted BSSID
  or an attacker-tool OUI; otherwise the pair is `UNATTRIBUTED`, ordered
  canonically and flagged `?`.

Severity is split from confidence: severity is how bad the finding is if
true, confidence (5..95%, never 100) how likely it is to be true.

**Slice 2 (`0e00373`) added the anchor** — `--inventory`, a JSON file
naming which BSSIDs are authorised for which SSID, and the only trust
input in this family that does not arrive over the air. The loader is
hand-rolled recursive descent, no new dependency: the tree has no JSON
*parser* (`jsonl.c` and `formatter.c` only write), a flat key scanner
cannot express `networks[].bssids[]` and would match `"ssid"` inside a
string value, and a library would have been the first third-party
dependency in a tree whose embedded build links only pthread and libm.

The load is **all-or-nothing**. Malformed JSON, wrong types, duplicate
or empty keys, bad MACs, control bytes, an embedded NUL, >256 KiB, >8
deep nesting — each fails with a reason and a byte offset and loads
nothing, leaving a previously valid inventory in force. A partial
inventory is the worst outcome available: the operator believes their
APs are approved while the dropped half alerts as rogue. `--inventory`
therefore exits 2 rather than starting.

**Slice 3 (`722cd00`) separated the three classes** the issue asked
for — and two of the three are decidable, one is not. `ap_class` answers
`impostor` / `neighbor` / `declared` / `?` from RF plus the approved
inventory. `wired_attach` is a **separate field, not a fourth class
value**, because RF cannot establish wired attachment at all: a
Pineapple on an LTE uplink and a rogue bridged onto the access VLAN
beacon identically. It reads `UNKNOWN` for every pair today, the view
renders `?`, the status bar says `wired correlation: none`, and the
alert detail carries a literal `wired=?` — load-bearing rather than
decorative, so a reader cannot mistake "not measured" for "not
attached". The controller/switch/DHCP correlation hook is left open.

---

## Evidence honesty (#94 — closed; #90)

**Sequence correlation and MY_NET_RECON (`618f300`).** Both produced
records that could be quoted in a personnel investigation or used to
point at a person in a room, and both stated conclusions their evidence
did not support. The old rule minimised *absolute* modular distance over
two 8-entry trails, accepted any pair inside a flat 64-seqnum/30-second
window, expired nothing, and labelled the result `LIKELY SAME DEVICE`.
Five requirements now gate a pair, each removing a class of false pair
rather than tuning a threshold: **freshness** (both heard within
`--correlate-retain`, 300s, of *now*), **ordering**, **exclusivity**
(one radio holds one address at a time, so two MACs transmitting through
the same seconds are two radios however close their counters sit),
**direction** (the counter advanced forward by 1..64 — absolute distance
cannot separate +5 from −5 and only one is a rotation; 0 is excluded
because a repeated value is a duplicate), and **continuity**. A
calibrated confidence (cap 90, floor 20) replaces the verdict. The false
pair rate is measured against 64 independent radios over 512 counter
positions, not estimated from a uniform model.

**KARMA severity split from confidence (`00b1bff`).** A bare SSID-count
crossing fired CRIT unconditionally, so a long-lived AP that renamed
itself a few times scored the same as an active PineAP lure; a bare
candidate is now WARN. The deauth-then-lure check credited every KARMA
candidate in range with any recent flood *anywhere*, with no shared
victim or BSSID established — `karma_deauth_lure_victim()` now requires
the victim's PNL to ask for one of the candidate's SSIDs, or the victim
to have since associated with it. PMKID observation stays informational
and never escalates severity alone, matching legitimate 802.11r/PMK
caching.

**Tool-signature provenance (`ef7db0d`).** A KARMA finding attributed to
a tool said `[ESP32 Marauder/med?]` and nothing more; the `?` existed
only in prose, so a JSONL or socket consumer could not tell a validated
identification from a research guess. Both signature rows sloth ships
today are UNVERIFIED, so **every** tool attribution it can currently
make was exported with no machine-readable provenance at all. Alerts now
carry `signature_id`, `signature_version`, `validated` and
`signature_evidence`, stamped inside `fire_inv` so `alert.create`
already has them and refreshed each evaluation so a match that vanishes
mid-incident stops being exported. The id is stable and never reused,
since archives join on it.

---

## Assurance before breadth (#95)

The parsers read bytes from the air and the wire, and a unit test that
passes while reading past its buffer is a false green. Three blocking CI
jobs now close that gap — and each found real defects.

- **ASan + UBSan (`afc825c`)**, `-fno-sanitize-recover=all`, leak
  detection on. The one finding was in a test, not `src/`:
  `test_ja4_stable_across_extension_reorder` swapped two adjacent
  extensions with a `memcpy` whose 7-byte move overlapped its 6-byte
  destination. Fixed to read from the pristine fixture.
- **ThreadSanitizer (`b9ab0be`)**. Three earlier #95 slices each shipped
  a concurrency test and said in the same breath that without TSan the
  test catches its race only by chance. Verified as a real gate, not
  just a green run: removing the exact mutex the RF-quality slice added
  reproduced the race at `rf_quality.c:28` and aborted with exit 66,
  then the mutation was reverted and the suite passed clean.
- **cppcheck (`154079c`)** reads all of `src/` and `research/`,
  including code the suite never executes, and fails on any finding not
  listed with its reason in `tests/cppcheck.supp`. Its first pass found
  three defects, fixed rather than suppressed — most visibly that the
  alert detail pane's **"First seen" showed `last_seen`**, because
  `draw_alert_detail()` called `localtime()` twice and kept both
  pointers into the one static `struct tm`. Any alert that had fired
  more than once hid how long the condition had lasted.

Four concurrency fixes landed behind those gates. The **worker stop
flags** (`9bfb808`) were a bare `volatile int`: C99 `volatile` stops the
compiler caching a value but gives no atomicity or ordering, and the
stop paths tested and cleared the flag in two steps, so two concurrent
stoppers could both `pthread_join()` the same thread. **RF quality
counters** (`21d3c52`) were read by the poll loop while the probe thread
wrote them, so a snapshot could report one channel's counters under
another's number, or 99% retry on an all-retry channel. The **evil-twin
taint table** (`6730997`) was read from the probe thread while
`eapol_log.c` wrote a hashcat line. The **DNS result buffer**
(`d28d19b`) was one static shared by every caller, so the capture thread
could put a torn hostname into a QUIC record — the race #84 listed as
outstanding; all three entry points now take a caller-owned buffer.
Every new mutex is a documented strict leaf, so none can close a cycle.

Also: `pcap_export()` dereferenced `localtime()`'s result with no NULL
check (`7128e5e`) — the last unguarded one in `src/` — which would
segfault before the ring buffer reached disk, losing the only copy of
those packets. And `41ddbca` fixed a CI-only `-Wformat-truncation`
failure that had made the new sanitize job red on every push while the
local gate stayed green.

`8cd38ef` (#99) made the **six-variant warning-clean gate enforced in CI
with `-Werror`**, so the drift that let `WITH_WIFI=0` go unclean in
v1.8.2 cannot recur unnoticed.

---

## Forensics (#92)

- **Handshake pcap timestamps (`e6a2108`).** Each record's `ts_sec` came
  from `time(NULL)` at processing with a zero `ts_usec` — not when the
  frame was captured. A capture backlog shifted it and every M1..M4
  collapsed onto whole seconds, so the artefact claimed a capture time
  it never had. The real `hdr->ts` is threaded through; an out-of-range
  `ts_usec` is stored as 0 rather than written into a pcap header.
- **Alert-pcap retry and storage visibility (`ff4a640`).** Export marked
  an incident's evidence "dumped" even when the write failed, so a
  transient disk-full or permission loss lost that evidence for good
  instead of retrying next tick like every other sink. It now retries
  and records `pcap_path` / `pcap_write_failures` on the alert. Three
  sinks counted their own write failures but surfaced them only to
  stderr or a view header — invisible to a JSONL/socket consumer; they
  now ride the existing `sensor_health` singleton via `storage_failures`
  plus a per-sink breakdown.

---

## WPS decode groundwork (#82)

`2c4b831` lands `eap_wsc_parse()`, a stateless decoder for EAP-WSC
(WPS M1–M8) inside RFC 3748 §5.7 Expanded Type 254 — accepted only for
the WFA SMI `0x00372A` with Vendor-Type 1 (SimpleConfig), per WSC 2.0
§7.7. It decodes Op-Code, Flags and the optional Message Length, then
walks the §12 TLVs for Message Type `0x1022`, UUID-E `0x1047` and MAC
Address `0x1020`. The walk is bounded by the **EAP Length, not the
capture length**, and sets `truncated` on an overrun while keeping what
was decoded before it.

#82's PIN-brute and Pixie-Dust asks were declined in triage for want of
exactly this path; this is the slice a later WPS session table sits on.
No detector, no alert type and no view yet. Middle fragments (MF set, LF
clear) are not walked — their body starts mid-value, and reading it as
TLVs would invent attributes. Tests are hand-built frames per WSC 2.0;
12 guard mutations were run under ASan/UBSan and all were caught.

---

## Documentation pinned to the build (#96, #87)

`8931549` adds `tests/test_docs_consistency.c`, which extracts claims
with a fixed word-level grammar — no model, no network — and compares
them to the compiled constants: every "*N* views" against `VIEW_COUNT`,
every "*N* rules" against `ALERT_TYPE_COUNT`, in README, `SECURITY.md`,
the rendered help card and `print_usage()` read from `src/main.c`.
`SECURITY.md` may name no version other than `SLOTH_VERSION`, and README
and the help text may name none newer. The grammar is itself tested on
hand-written input, and README must yield its known claims, so a reword
past the grammar fails rather than going vacuous. Proven red on the
unedited `SECURITY.md`.

This was prompted by a real hole: after the v1.8.2 #96 sweep,
`SECURITY.md` still archived "v1.8.0 and below" once v1.8.1 was tagged,
so **v1.8.1 sat in no row of the supported-versions table**. The archived
row now reads "every tag before the newest", so cutting a tag can no
longer strand the previous one.

**This changes the release procedure:** `SECURITY.md` is now part of the
version bump. `test_security_names_only_current_version` goes red the
moment `SLOTH_VERSION` moves without it, so a release commit touches
`include/sloth.h`, `SECURITY.md` and the release notes — not the first
two alone. That is the test working as designed; it caught this release.

`cd4d4c0` documents the export permission contract #87 shipped — 0600
files, 0700 directories, existing paths refused rather than repaired —
in `docs/views/eapol.md` and a new `docs/wiki/retention.md` §4.1,
checked against `src/secure_file.c`, `src/db.c`, `src/eapol_log.c`,
`src/alert_pcap.c` and `src/pcap_write.c`. Kept out of `SECURITY.md` so
it does not pre-empt the still-open group-sharing question.

`a3f6820` is a METRICS erratum: the #87 row pointed at `dd6ed49` where
the shipped commit was `c588ba9`. Rows are append-only, so the
correction is a new row.

---

## Verification

Every variant built warning-clean and the suite green, on `main`, before
the tag:

```
make                  0 warnings
make WITH_NCURSES=0   0 warnings
make WITH_PCAP=0      0 warnings
make WITH_WIFI=0      0 warnings
make WITH_SQLITE=0    0 warnings
make embedded         0 warnings
make test             11229 assertions passed, 0 failed
```

CI on the verified SHA (`8acfefd`) was green across CI, CodeQL and the
Code Review job, including the new blocking `sanitize`, `tsan` and
`cppcheck` jobs.

Still no `.pcap` files in `tests/` — every detector test, including the
new EAP-WSC and handshake-timestamp cases, is hand-built bytes per the
relevant IEEE or WSC clause.
