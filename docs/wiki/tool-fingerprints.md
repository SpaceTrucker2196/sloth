# Tool fingerprints — the mechanism, and why it ships empty

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

So the mechanism ships and the data does not. `tool_signature_count()`
returns **0**, and a test asserts that it does, *on purpose* — a
contributor deleting a row by accident should see a failure rather than
silently shipping a detector that matches nothing.

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
    uint8_t  requires_karma_echo; /* precondition, not a characteristic */
    uint8_t  requires_pmkid;
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
- **`requires_*` are preconditions, not characteristics.** They gate a
  row without scoring it, because "a KARMA event happened" is already
  why we are looking.

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
4. **Add a test** asserting that observation matches your row and does
   not match any other.
5. Flip `test_table_is_empty_on_purpose` to `> 0` in the same commit.

One row per commit. **A signature that arrives without its capture is a
guess wearing a data structure.**

You do not need to understand the matcher to add a tool — that
separation is the point of shipping the mechanism first.

## A note on testing an empty table

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

## See also

- [`docs/views/karma.md`](../views/karma.md) — the `[y]` view.
- [`docs/views/alerts.md`](../views/alerts.md) — `KARMA_AP`.
- [`docs/wiki/enterprise-rogue.md`](enterprise-rogue.md) — `eaphammer`
  and `hostapd-wpe` from the 802.1X side.
