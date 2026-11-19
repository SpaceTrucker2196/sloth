# tool-fingerprints: attack-tool beacon signatures

`tool_fingerprints.csv` is sloth's `TOOL_SIGNATURES` less its terminator
row (sloth
[`src/tool_fingerprint.c`](https://github.com/SpaceTrucker2196/sloth/blob/fa366881644ad32160f5ca8e586af0fdedac00c4/src/tool_fingerprint.c)
at `fa366881`; the struct is `sloth_tool_sig_t` in
`src/tool_fingerprint.h`). One column per struct field, in order: `tool`
(a `SLOTH_TOOL_*` name), `vendor_ie_hash`, `beacon_interval_ms`,
`supported_rates` (0 is a wildcard in each), `require_flags` and
`forbid_flags` (`AP_FP_FLAG_*` names joined by `|`, or 0),
`requires_karma_echo`, `requires_pmkid`, `unverified` (0 or 1),
`human_label`, `evidence`, `id`, `version`. Moved and held byte for byte
to that source by sloth-comint's parity check. sloth's documentation
counts one row; there are two (`esp32-marauder-01` and
`pineapple-mk7-01`).

The rule the table carries (sloth's own words): "a tool's fingerprint
is an empirical fact about a binary, not something derivable from a
specification, and a table of invented rows would pass every test while
matching nothing on the air." A row lands with `evidence` naming the
capture and the tool version; a row without one is `unverified`,
capped at medium confidence, and its `evidence` starts
`UNVERIFIED - `. `evidence` is a required column for that reason
(pack-schema §3.4).

- **esp32-marauder-01** - "values came from a research task (sloth
  #74), not from a rig, and nobody here has watched an ESP32 Marauder
  transmit. The owner's call was to land it flagged rather than leave
  the table empty." 100 TU is the 802.11 default and legacy-only rates
  are shared by a decade of cheap hardware; "the discriminating part is
  the combination with an Espressif OUI and no HT Capabilities". The
  rate set #74 gives (1/2/5.5/11) is not pinned: beacons do not reach
  the matcher with supported rates populated.
- **pineapple-mk7-01** - also from #74, one characteristic: a Hak5 OUI
  (`packs/attacker-ouis`) on an AP that echoed SSIDs (KARMA), low
  confidence. `AP_FP_FLAG_DEFAULT_HOSTAPD_CAPS` is deliberately not
  pinned because nothing in sloth sets it.

Further reading in sloth: `docs/wiki/tool-fingerprints.md`,
`docs/wiki/attack-hardware-fingerprints.md`,
`research/tools/wifi-pineapple-mk7.md`.

**The #151 known-stack table** does not exist: sloth #151 waits on
owner rig captures, and plan #145's second ruling forbids a fingerprint
row without a primary source. No `known_stacks.csv` ships; the name is
reserved by pack-schema §3.4.

**Licence.** Written in sloth (SLOTH SOURCE-AVAILABLE LICENSE 1.0) by
the owner of both repositories. sloth carries them under its own
licence; sloth-comint publishes them under PolyForm Noncommercial 1.0.0.