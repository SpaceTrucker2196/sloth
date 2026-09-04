# Tool fingerprints — the mechanism, and two unverified rows

**Issue:** [#68](https://github.com/SpaceTrucker2196/sloth/issues/68) ·
**Code:** [`src/tool_fingerprint.c`](../../src/tool_fingerprint.c) ·
**Surfaces in:** `ALERT_TYPE_KARMA_AP`

`KARMA_AP` says *a suspicious AP echoed an SSID it has never
advertised*. That is a finding. It is not yet a response.

Naming the tool changes what an operator can do with it. "This is
hostapd-mana" tells you what the attacker's capabilities are, what else
to look for, and roughly how much effort went into being there.
"Something odd happened" is a ticket. It also lets one attacker be
correlated across SSIDs, sites and times — the same binary leaves the
same marks.

## Why there are no signatures in it

**A frame layout can be built from a specification. A tool's
fingerprint cannot.**

`hostapd-mana`'s default beacon interval, `eaphammer`'s vendor-IE hash,
an ESP32 Marauder's supported-rate set — these are empirical facts about
particular binaries at particular versions. There is no document to
derive them from. They come from putting the tool on a rig and looking.

sloth's test discipline is hand-built frames from first principles
(`agents/AGENTS.md` § Discipline), and that works because a frame layout
*is* specified. It does not extend to this. Signatures written from
imagination would produce a table that passes every test and matches
nothing on the air — which is worse than an empty table, because it
looks like coverage.

So the mechanism shipped and the data did not. The table was empty, and
a test asserted that it was, on purpose.

## The one row, and what its provenance is not

**Updated 2026-09-04 (#74).** The table now has two rows — **ESP32
Marauder** and **Pineapple MK7**. Neither has a capture behind it.

Their values came from a research task, not a rig. Nobody here has
watched either tool transmit. The owner's call was to land them flagged
rather than leave the table empty, and that is defensible — but only
because of where the flag lives:

```c
"UNVERIFIED - values from issue #74 research, 2026-09-04; "
"no capture. Replace with a rig capture + firmware version."
```

The flag is in the `evidence` string, which an operator reading the
alert can see. A test asserts **every** shipped row has a non-empty
`evidence` and at least one discriminating field, so the next hurried
addition cannot arrive silent about where it came from.

A row is unverified until someone captures the tool and replaces that
string with the capture and the firmware version. Until then it is a
hypothesis sloth is willing to state out loud.

### An unverified row can never report `high`

The row also carries an `unverified` flag, and it **caps the reported
confidence at `med`** however many fields agreed.

These are two different axes and conflating them is the whole risk of
shipping rows without captures. The field count measures *how much of
the beacon was compared*. Provenance measures *whether the values being
compared against are right*. A row can pin three characteristics
perfectly and still be three guesses — and an operator reading `high`
would reasonably assume both.

So the ESP32 Marauder row scores three fields, which the field-count
model calls `high`, and reports `med`. The cap is a ceiling and not an
assignment: the one-field Pineapple row still reports `low`.

The flag drives behaviour; the `evidence` string is what a human reads.
A test asserts they agree — `unverified` is set exactly when the
evidence starts with `UNVERIFIED` — because a row where they drift
reports a confidence its own provenance note contradicts.

### What the row can and cannot claim

| #74 gives | pinned? |
|---|---|
| beacon interval 100 TU | yes — 102 ms after the TU→ms conversion |
| no HT Capabilities IE | yes — `forbid_flags` |
| Espressif OUI | yes — `require_flags` |
| rates 1/2/5.5/11 Mbps | **no** |
| no Country IE | **no** |

The rate set is not pinned because beacons do not reach this matcher
with `supported_rates` populated — that field lives on `assoc_req_t` and
nothing fills it on the beacon path. Claiming it while never comparing
it would inflate the confidence score for a field nothing supplies.
There is no Country-IE flag on `ap_fingerprint_t` at all.

100 TU is the 802.11 default and legacy-only rates are shared by a
decade of cheap hardware, so neither means anything alone. The
discriminating part is the *combination* with an Espressif OUI and no HT
Capabilities: a 2026 access point that negotiates no HT is either very
old or not really an access point.

And the row sets `requires_karma_echo`, so it only ever names a tool
alongside a finding that already fired. That gate is what makes an
unverified row safe to ship: it enriches a `KARMA_AP` alert, it never
raises one.

### The Pineapple MK7 row

Much thinner: it pins exactly one characteristic, `AP_FP_FLAG_HAK5_OUI`.

That is the honest shape of what #74 supplies. Its Pineapple data is
"the default OUI list and the default SSIDs" — the OUIs (`00:13:37`,
`00:c0:ca`) were already in `kHak5Ouis`, and there is no SSID field in
the signature struct to put the rest in.

**Thin is not worthless here**, and the difference from the Espressif
row is the reason. `00:13:37` is a Hak5 vanity prefix and `00:c0:ca` is
the Alfa radio they ship with it; neither turns up in an air
conditioner. An Espressif OUI on its own says "some ESP32", which is why
that row needs three fields to say anything — a Hak5 OUI on an AP that
just echoed three SSIDs says "Pineapple" at `low` confidence by itself.

Not pinned, deliberately: `AP_FP_FLAG_DEFAULT_HOSTAPD_CAPS`. The MK7
runs hostapd and the flag exists, but **nothing in the tree sets it**. A
`require` on a flag nobody populates never matches; a `forbid` on one
always passes and scores a hit for a comparison that did not happen,
inflating confidence for nothing. Either way the row lies about how much
it checked, and neither failure is visible by reading the row — so a
test asserts no shipped row references it.

### The Flipper Zero OUIs

#74 also supplies `AC:0B:FB` and `24:6F:28` as "Flipper Zero devboard".
`24:6F:28` was already in `kEspressifOuis`; `AC:0B:FB` is new and went
in beside it.

Not into a Flipper table. The Flipper's Wi-Fi devboard is an ESP32-S2,
so these are Espressif blocks — and an OUI cannot separate a Flipper
devboard from an ESP32 Marauder from a hobbyist's weather station. A
function named `oui_is_flipper()` would claim it could.

## What does work today

One half of #68 needs no signature table at all.

**PMKID harvest is a protocol observable.** An AP that solicits PMKIDs
is doing something `hcxdumptool`-shaped whichever binary is doing it —
the behaviour is visible in the EAPOL exchange sloth already parses, not
in a vendor quirk. So a KARMA alert against a BSSID a PMKID was
harvested from carries `+PMKID` today.

The BSSID match matters: a PMKID harvested from a *different* AP says
nothing about this one, and crediting it would give every KARMA AP in
range someone else's evidence.

## How a row works

```c
typedef struct {
    sloth_tool_id_t tool;
    uint32_t vendor_ie_hash;      /* 0 = wildcard */
    uint16_t beacon_interval_ms;  /* 0 = wildcard */
    uint32_t supported_rates;     /* 0 = wildcard */
    uint8_t  require_flags;       /* AP_FP_FLAG_* that must be set   */
    uint8_t  forbid_flags;        /* AP_FP_FLAG_* that must be clear */
    uint8_t  requires_karma_echo; /* precondition, not a characteristic */
    uint8_t  requires_pmkid;
    uint8_t  unverified;          /* no capture — caps confidence at med */
    const char *human_label;
    const char *evidence;         /* where the values came from */
} sloth_tool_sig_t;
```

Three rules, each with a test:

- **A zero field is a wildcard.** It matches anything and contributes
  nothing to confidence.
- **Confidence is the count of non-wildcard fields that agreed.** One
  pinned field is `low`, two `med`, three or more `high`. A row that
  pins a beacon interval alone is a coincidence waiting to happen; one
  that pins three characteristics is a claim.
- **`unverified` caps that at `med`.** See above: thoroughness and
  provenance are different axes.
- **`requires_*` are preconditions, not characteristics.** They gate a
  row without scoring it, because "a KARMA event happened" is already
  why we are looking.
- **`require_flags` / `forbid_flags` score one each, not one per bit.**
  A row demanding two flags is pinning one aspect of the beacon's
  shape; letting it outscore a vendor-IE hash match would rank a weak
  row above a strong one. `require_flags` is a subset test — unrelated
  flags on the observation do not block a match — while
  `forbid_flags` rejects on any bit present.

**A forbid mask is not the same as omitting a field.** Omitting means
"do not care"; forbidding means "and this must not be there", which is a
distinct and much stronger claim. Half of what identifies a cheap rogue
is what its beacon *lacks*, and an all-positive schema cannot say that.

An all-wildcard row therefore matches nothing — the best-match
comparison is strict and starts from zero, so a row with no agreeing
field can never win. That is the failure mode a signature table falls
into when someone adds a row they were not sure about, and it is inert
here rather than catastrophic.

## Adding a tool

1. **Capture its beacons on a rig you control.**
2. Read the values sloth computes: the `beacon` JSONL record's
   `vendor_ies_hash` and `beacon_ms`, and the supported-rate set.
3. **Add one row** to `TOOL_SIGNATURES`, with `evidence` naming the
   capture *and the tool version*. Signatures drift as tools update, and
   a row with no provenance cannot be re-checked when it stops matching.
   If it is not from a capture, set `unverified` **and** start the
   evidence with `UNVERIFIED` — a test asserts the two agree — then say
   where it *did* come from.
4. **Add a test** asserting that observation matches your row and does
   not match any other, and one asserting each of its fields is
   load-bearing — a row whose OUI requirement does nothing is a row that
   fires on a smart plug.
5. Bump the count in `test_table_has_its_signatures` in the same commit.

One row per commit. **A signature that arrives without its capture is a
guess wearing a data structure.**

You do not need to understand the matcher to add a tool — that
separation is the point of shipping the mechanism first.

## A note on testing a nearly-empty table

The matcher's guards are unreachable through the normal entry point
while the table is empty, so a mutation to any of them survives. That is
not a hypothetical: it happened during development, twice.

The fix was `tool_fingerprint_match_table()`, which takes the table as a
parameter. `tool_fingerprint_match()` is a one-line wrapper over it, so
there is one implementation and the tests exercise the shipped code
rather than a copy of its logic written alongside it.

The second mutation found something else: an explicit
`if (hits == 0) continue;` guard that was provably redundant, because
the strict best-match comparison already rejected zero-hit rows. Removed,
with the reasoning moved onto the comparison that actually enforces it.

A third came with the first real row (#74): nothing proved that
`ap_fingerprint_t.flags` actually *reached* the matcher from the KARMA
rule. Zeroing that one assignment in `alerts.c` left every test green
while making the shipped row impossible to fire — the table would have
looked like coverage and been inert. A single-flag row also cannot tell
`require_flags` all-bits matching from any-bit matching, so that is
tested through `tool_fingerprint_match_table()` with a synthetic
two-flag row.

## See also

- [`docs/views/karma.md`](../views/karma.md) — the `[y]` view.
- [`docs/views/alerts.md`](../views/alerts.md) — `KARMA_AP`.
- [`docs/wiki/enterprise-rogue.md`](enterprise-rogue.md) — `eaphammer`
  and `hostapd-wpe` from the 802.1X side.
