# sloth v1.8.0 — the 802.11 management surface

Fourteen issues, closing the entire open backlog. Where v1.7 landed the
first passive detector batch, this release parses the 802.11 management
and control surface those detectors were guessing around — and adds ten
detectors on top of it.

Suite went **5906 → 6687 assertions**. Alert types **33 → 48**.

---

## ⚠️ Upgrade note — SQLite schema v3 → v4

**An existing `--db` file will refuse to open**, with:

```
sloth: db schema v3, this build writes v4 — use a separate file
```

That is deliberate and it is the designed behaviour, not a failure: the
version is checked before the schema is applied precisely so a mismatch
produces this message rather than an error on whatever statement first
hits a missing column.

Four columns wanted a bump across three issues, and each on its own was
a bad trade. Taken together it is one break instead of four:

| Column | Table | Why |
|---|---|---|
| `phy_confirmed` | `pnl_clients` | a PHY tier corroborated by an association request rather than inferred from probes |
| `downgrade_flags`, `akm_bits` | `beacon_aps` | historical posture — "was this AP in transition mode in March" |
| `nocert_sessions`, `nocert_no_hello`, `last_nocert_sta`, `last_nocert_ts` | `rogue_radius` | CVE-2023-52160 evidence behind the alert |

Start a new database file. The old one stays readable with any v1.7
build and with `sqlite3` directly.

**JSONL is additive only** — every new field is new, nothing changed
shape, and a consumer ignoring them sees exactly what it saw before.
The CLI is unchanged.

---

## New detectors

Ten alert types, each a passive rule over frames sloth now parses.

**`BTM_ABUSE`** (#59) — 802.11v BSS Transition Management used as a
deauth-equivalent. A Request with **Disassociation Imminent** set moves a
client with no deauth frame at all, so `DEAUTH_FLOOD` never saw this
attack. Gated on that bit rather than on rate alone: a Request without it
leaves the client free to decline, and rate alone fires on every busy
enterprise AP doing ordinary load balancing.

**`ASSOC_FLOOD`** and the association-request picture (#60) — what a
client *asked for*, beside what it settled for. There is no "granted
AKM" to compare against: an association response carries no RSN Element
outside FT and OWE (§9.3.3.7), so the downgrade is measured across
successive requests. A client that asked for SAE and came back asking for
PSK was moved, and that retry is the runtime signature of CVE-2023-52424
from the client side.

**`WPA_DOWNGRADE`** (#62) — an AP advertising a weaker lane beside its
primary one: PSK and SAE both on offer, an OWE BSS with an open
companion, MFP capable-but-not-required on SAE, or WPA1 beside RSN. None
is an attack; each is the prerequisite CVE-2023-52424 and Dragonblood
need. A 30-second observation floor keeps `--hop` from alerting on every
AP it brushes past.

**`PEAP_NO_SERVER_CERT`** (#65) — **CVE-2023-52160**. A TLS-in-EAP
session that reached EAP-Success with no ServerHello or Certificate ever
presented. `ROGUE_RADIUS` warns about attacker infrastructure; this warns
that *your own fleet would fall for it*, and stays silent until a device
actually does. Millions of Android and ChromeOS handsets shipped in that
state.

**`CSA_ABUSE`** (#63) — Channel Switch Announcement misused. Cheaper and
quieter than a deauth flood, and it works on firmware that ignores
deauth. Three shapes: a forged transmitter, a storm of distinct target
channels, or a destination hosting a known evil twin.

**`RRM_SURVEY_ABUSE`** (#61) — 802.11k Beacon Requests used to enumerate
the airspace *through someone else's radio*. The discriminator is not the
rate: a legitimate AP asks about networks it advertises.

**`RTS_FLOOD`** and **`BLOCKACK_ATTACK`** (#64, #70) — airtime denial of
service, and the **Bl0ck** attack (arXiv 2302.05899): a spoofed Block-Ack
Request that forces a peer's receive window past queued frames. Quiet by
design — what the operator sees is a client that stopped working.

**`CAPTIVE_PORTAL`** (#69) — a connectivity-check probe answered by
something other than the real endpoint. Three independent signals, so a
portal evading one still has to pass the others.

---

## New data

**HT / VHT / HE / EHT operation elements** (#66) — channel width
(20/40/80/160/320, and non-contiguous 80+80) and the **durable 6 GHz
channel fix**: the beacon channel came from the DS Parameter Set, which
much 6 GHz gear omits entirely. HE Operation's 6 GHz Operation Info is
authoritative and now wins. `channel_source` records which IE supplied
the number, so a wrong channel is attributable.

sloth previously treated every AP as 20 MHz, which makes any airtime
answer wrong by up to a factor of sixteen.

**Multi-Link Element decode** (#67) — not a new feature so much as a live
mis-count. Sequence-number correlation links a radio's randomised
addresses by their shared counter; a Wi-Fi 7 Multi-Link Device's radios
have *independent* sequence spaces and never correlate, so one handset
read as two or three devices. `transit_canonical_mac()` now consults the
MLE first — the protocol asserting the identity beats sloth inferring it.

**802.11 data frames reach the IP decoder** (#72) — the monitor radio and
the IP capture used to see disjoint worlds. On an open network they are
now one picture. Encrypted frames are rejected rather than parsed, per
MISSION §2.

**HTTP response-side parsing** (#71) — status, a bounded body, and
request/response pairing. The design decision that matters: sloth does
not reassemble TCP, so the parser reports **complete**, **partial** or
**chunked-and-undecoded** rather than pretending. "Different" and
"incomplete" are different answers.

**Control-frame counters** (#64) — RTS/CTS/ACK/Block-Ack per channel, the
*measured* half of occupancy against the QBSS Load an AP reports about
itself. CTS and ACK carry only a Receiver Address, so they attribute to a
channel and nothing finer.

**Tool-fingerprint matcher** (#68) — ships with an **empty signature
table, on purpose**. A frame layout can be built from a specification; a
tool's fingerprint cannot. Invented rows would pass every test and match
nothing on the air, which is worse than an empty table because it looks
like coverage. The PMKID-harvest half needs no signatures and works
today.

---

## Repo changes

- **`agents/AGENTS.md`** now records the hand-built-frames test policy
  explicitly, and the `needs-pcap-fixture` label means "wanted as
  follow-up validation" rather than "blocked".
- **`$(TEST_BIN)` gained header prerequisites.** A header-only change
  never rebuilt the test binary — every such change in this repo's
  history was tested against a stale build.

## Fixed

- Wi-Fi 7 PHY-tier labelling, broken mid-run by an operation-IE
  refactor that dropped the line setting `has_eht`. It compiled clean and
  the suite stayed green because nothing covered the PHY ladder from
  beacon IEs. Now one test per rung.
- `KARMA_SSID_THRESH` was defined twice with the same value.

## Known gaps

Named rather than hidden:

- A rogue portal that **chunks its HTTP response** evades the
  captive-portal body check. It does not evade the DNS or TLS checks.
- **`--hop` makes absence a sample, not a fact.** Every detector that
  could infer from "we never heard X" requires positive evidence first.
- **#68's signature rows** need captures from a lab rig.
- DHCP **option 114** is not parsed, so the RFC 8910 portal-origin
  cross-check has nothing to compare against.
- **Request bodies are not captured**, so the credential-POST hint in
  #69 is unbuilt — a request body is where passwords live, and that is a
  MISSION §2 conversation rather than a parser task.

---

Passive throughout. Nothing here transmits, scans, or modifies kernel
state — see [`MISSION.md`](MISSION.md) §2.
