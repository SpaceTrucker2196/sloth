# Approved inventory (#89 slice 2)

The operator's written statement of **which BSSIDs are authorised to
serve which SSID**, loaded from a JSON file with `--inventory`.

It exists because of what [[alerts]] §"Nothing observed over the air is
a trust anchor" removed. Slice 1 of #89 took three things out of the
evil-twin rules that the code had been treating as proof of ownership —
a matching vendor OUI, an 802.11k neighbour report, and RSSI — because
all three are values an attacker writes into a frame. That left the
detector honest and *anchorless*: it could say "these two radios
disagree with each other" and never "that one is not mine".

This is the anchor, and it is the only trust input in the twin family
that does not arrive over the air.

## The file

```json
{
  "version": "2026-09-24.1",
  "site": "hq-3f",
  "networks": [
    { "ssid": "CorpWiFi",
      "security_profile": "wpa2-enterprise",
      "bssids": ["aa:bb:cc:00:11:22", "aa:bb:cc:00:11:23"] }
  ]
}
```

| Key | Required | Meaning |
|-----|----------|---------|
| `version` | no | Human-readable label, ≤32 bytes. A label only — see [Identity](#identity-is-the-content-hash). |
| `site` | no | Where this sensor is, ≤32 bytes, no `:`. Overridden by `--site`. |
| `networks` | **yes** | Array, may be empty. ≤64 entries. |
| `networks[].ssid` | **yes** | 1–32 bytes, exact and case-sensitive. Each SSID may appear once. |
| `networks[].security_profile` | no | ≤23-byte operator label. Carried and displayed, **not matched** — see [Not matched](#security_profile-is-carried-not-matched). |
| `networks[].bssids` | **yes** | Non-empty array of `aa:bb:cc:dd:ee:ff` (also `-` separated, any case). ≤512 across the whole file. Each address may appear once. |

Unknown keys at either level are **ignored**, the same
forward-compatibility rule `src/updater.c` applies to the release
manifest — but they are still parsed, so junk inside a key sloth does
not read still fails the file.

## Parsed as hostile data

This is operator-supplied *data*, not trusted input: a file on a sensor
several people edit, or one a script generates against a controller
API. Every one of these is refused with a message naming what was wrong
and the byte offset:

- a missing, unreadable, empty or over-large (>256 KiB) file
- malformed JSON: truncation, trailing content, a second document, a
  trailing comma, an unquoted key, an unterminated string
- wrong types anywhere — `"networks": "CorpWiFi"`, `"bssids": [42]`,
  `"version": 7`
- a missing `ssid` or `bssids`, an empty SSID, an empty BSSID list
- a duplicate key, a duplicate SSID, a duplicate BSSID (in one entry or
  across two — `aa:bb:…` and `AA-BB-…` are one address and are compared
  as such)
- a malformed BSSID, an over-long string, a control byte, a NUL byte
- nesting more than 8 deep, a `\u` escape, an unknown escape

**The load is all-or-nothing.** A file that half-parses loads nothing,
and a failed load leaves any previously valid inventory in force. A
partial inventory is the worst outcome available: the operator believes
their APs are approved while the dropped half of the list alerts as
rogue, or a dropped rogue reads as unremarkable. `--inventory` therefore
**exits non-zero** on a bad file rather than starting without the anchor
the operator asked for.

The reader is hand-rolled recursive descent in `src/inventory.c`. The
tree had no JSON *parser* — `src/jsonl.c` and `src/formatter.c` only
write, and `src/updater.c`'s `scan_str_field` says of itself that it is
not a general parser: a flat key scanner cannot express
`networks[].bssids[]`, and it would find `"ssid"` inside a string
*value* and read a file the operator did not write. A library would have
been the first third-party dependency in a tree whose embedded build
links nothing but pthread and libm.

## What it changes in the detector

`twin_evidence_score()` asks one question per half —
`inventory_verdict(ssid, bssid)` — with three answers:

| Verdict | When | Effect |
|---------|------|--------|
| `INV_NO_INVENTORY` | no file loaded, **or the SSID is not listed** | nothing; slice-1 heuristics stand exactly |
| `INV_APPROVED` | the SSID is listed and this BSSID is in its set | if *both* halves: the pair is not a candidate |
| `INV_MISMATCH` | the SSID is listed and this BSSID is **not** in its set | `+50` positive evidence, and **hard** |

Silence about an SSID is not approval of it. Treating it as approval is
how a trust anchor becomes a blind spot, so an undeclared network keeps
its heuristics untouched.

Two consequences worth stating plainly:

- **A same-OUI clone becomes visible.** Three matching bytes and nothing
  else is an empty evidence set, which is why slice 1 is silent on it
  and why a legitimate multi-BSSID deployment is silent too. The
  inventory is what turns "no evidence" into "that radio is not one of
  mine".
- **A spoofed neighbour declaration cannot erase a mismatch.** The
  mismatch is `hard`, and a neighbour claim may only demote a severity
  resting on soft signals. The claim still costs confidence — it is
  evidence of something, just not of ownership.

`inv_approved` is a **sole suppressor**, deliberately. That is not the
pre-#89 behaviour under a new name: what #89 removed were suppressors
sourced from frames the attacker writes. The test is not "does anything
suppress" but "can the adversary reach the input" — and here they
cannot. The one case it does *not* silence is the weak/strong branch: an
OPEN BSS beside a protected one under a single name is a downgrade lane
whoever owns it, so a declared pair is demoted to WARN and relabelled
`inventory-approved pair, weak/strong split` rather than withdrawn. The
inventory answers *whose radio is that*, never *is that configuration
safe*.

It also settles attribution in the `[x]` Twins view: a declared BSSID is
never named the impostor half, the same rank `--my-bssid` already had,
and for the same reason — a human asserted it out-of-band.

**Not detected:** an attacker that spoofs an *approved* BSSID outright.
Two APs sharing one address are one `beacon_ap_t` row, so there is no
pair to score. That is a sequence-number / RF-fingerprint problem, not
an inventory one.

## Merging with `--my-ssid` / `--my-bssid` (#52)

The flags keep working unchanged and are **unioned** with the file,
never intersected:

- A BSSID designated with `--my-bssid` counts as approved for any SSID
  the inventory lists. Both inputs are the same kind of statement — a
  human asserting ownership — so there is no ground for preferring one,
  and intersecting would mean that *adding* a flag could manufacture a
  rogue out of the operator's own AP. Union is the safe direction for an
  anchor whose failure mode is alerting on your own infrastructure.
- An SSID named by `--my-ssid` but absent from the file stays
  `INV_NO_INVENTORY`. The flag says the network is ours; it does not
  enumerate which radios may serve it, so no mismatch is computable
  from it.

Practically: the flags are the one-sensor case, the file is the fleet
case, and a radio the file has not caught up with can be waved through
with a flag.

## `site` is configuration only

Owner decision, 2026-09-25. `site` comes from `--site` or the file's
`site` field **and from nothing else**. It is never derived from the
uplink association, an observed SSID, or any captured frame.

Two reasons, and both matter:

1. An observed SSID is unauthenticated data. Deriving identity from it
   and then keying a finding on it is the neighbour-report hole wearing
   a different hat.
2. `site` is a field of the canonical pair key, so a site derived from
   the sensor's uplink would re-key on every roam, reconnect or uplink
   change. One physical impersonator would fragment into several
   incidents and the [[alerts]] lifecycle would open a fresh
   `alert.create` for each instead of escalating the one already open.

There is no `site_source` provenance field, because there is no second
source to distinguish. Unset means unset: the key carries an empty site
and its shape does not change.

`--site` is distinct from `--site-label` (#27), which names the
`--snapshot-out` report. Different axes: `--site` says *where this
sensor is*, `--site-label` titles a document.

When both the flag and the file supply one, **the flag wins**, whichever
order they appear in on the command line — argv order must not change a
dedup key.

## Identity is the content hash

`inventory_hash()` is the first 16 hex characters of SHA-256 over the
file's raw bytes. It is stamped into every alert and export that
consulted the inventory, as `"inventory"` on both the `alert` record and
the `alert.*` lifecycle events (see [[jsonl-schema]]), so a finding in an
archive names the exact file that produced it.

The `version` string cannot do that job — nothing stops two different
files from both claiming `2026-09-24.1` — so it rides along as a label,
printed at startup beside the hash.

Only the rules that actually read the inventory carry the field — an
`ARP_SPOOF` record never does. "Consulted" means the rule *read* the
inventory, not that the inventory had an opinion: an `EVIL_TWIN` for an
SSID the file does not declare still carries the hash, because a
different file might have declared that SSID and produced a different
finding, and which one was in force is precisely what makes the record
reproducible. Stamping *every* alert, by contrast, would assert the
anchor backed findings it never touched — the opposite of the
traceability the field exists for.

Hashing the *bytes* means a whitespace-only edit is a different
inventory. That is intended: the question the field answers is "which
file did sloth read", not "were the semantics equivalent".

## `security_profile` is carried, not matched

The field is parsed, validated, stored and shown; it is deliberately
**not** compared against the observed `enc` string. Doing that needs a
normalisation table between operator vocabulary (`wpa2-enterprise`) and
sloth's beacon-derived ciphers (`WPA2`), and a wrong entry in that table
alerts on the operator's own APs — the exact failure this anchor exists
to prevent. Until that mapping is specified it is a label for the human
reading the finding.

## Lifetime

Read once, at startup, from a local file. Never re-read, never fetched,
never written. The absence of a reload path is deliberate twice over: a
reload would be an inbound-configuration surface, which
[`MISSION.md`](../../MISSION.md) §4 puts out of scope, and it would let
the trust anchor change underneath a live incident.

## What it does not answer

The inventory says **whose radio a BSSID is**. It does not say what that
radio is plugged into, and no file the operator writes about their APs
could — a rogue is by definition not in it. Wired attachment is a
separate axis (#89 slice 3) answered only by a correlator that can see
the wire, registered through `src/wired_attach.h`; until one exists,
every twin reports `wired=?`. See
[`docs/views/twins.md`](../views/twins.md) for why that stays unknown
rather than being inferred.

## See also

- [[alerts]] — severity vs confidence, canonical pair keys, what #89
  removed
- [[jsonl-schema]] — the `inventory` field on alert records
- [`docs/views/twins.md`](../views/twins.md) — attribution in the `[x]`
  Twins view
- `src/inventory.h` — the contract, with the reasoning inline
