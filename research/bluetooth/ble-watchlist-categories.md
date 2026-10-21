---
source_url: https://bitbucket.org/bluetooth-SIG/public/src/main/assigned_numbers/uuids/member_uuids.yaml
retrieved: 2026-10-21
topics: [bluetooth, ble, watchlist, finder-tag, tracker, smarttag, tile, chipolo, find-my, assigned-numbers]
alert_kinds: [ALERT_TYPE_BLE_WATCHLIST]
citation: Bluetooth SIG Assigned Numbers, uuids/member_uuids.yaml; Yu, Henderson, Tiu, Haines, "Privacy Analysis of Samsung's Crowd-Sourced Bluetooth Location Tracking System", USENIX Security 2024 (arXiv:2210.14702); Heinrich, Bittner, Hollick, "AirGuard - Protecting Android Users From Stalking Attacks By Apple Find My Devices" (arXiv:2202.11813)
---
# BLE watchlist categories — the schema, and why the table ships empty

What `ALERT_TYPE_BLE_WATCHLIST` (#144 slice 4) and `src/ble_watchlist.c`
rest on. The matcher is row-driven and **ships with no rows**: a row
lands with the primary source that documents its payload shape, one per
commit (owner standard, #145). This page is where each candidate stands.

## The schema

A row names a category and one advertisement field to match:
Manufacturer Specific Data by company ID, Service Data - 16-bit by UUID,
or a listed 16-bit Service UUID; optionally the first payload octet and
a payload-length range; and the source it rests on, which
`ble_watchlist_set_table()` requires. A match stores the category on the
device row and nothing else. Nothing is decrypted, resolved or linked
across addresses.

## The registry (primary for who owns a UUID)

Bluetooth SIG `member_uuids.yaml`, read 2026-10-21:

- **Tile, Inc.**: 0xFEED, 0xFEEC, 0xFD84.
- **CHIPOLO d.o.o.**: 0xFE65, 0xFE33.
- **Samsung Electronics Co., Ltd.**: 0xFD59 and 0xFD5A, among others
  (0xFDDB, 0xFD7E, 0xFD6C, 0xFD69, 0xFD4B, 0xFD1D, 0xFC91).
- **V2SOFT INC.**: 0xFD5B — not Samsung. The issue body's
  "0xFD5A/0xFD5B" for SmartTag is wrong on the second value (owner
  correction on #144, 2026-10-19).
- **Apple, Inc.**: 0xFD44, 0xFD43, 0xFD6F, 0xFE25 and others; Find My's
  offline-finding advertisement uses Manufacturer Specific Data under
  company 0x004C, not a member UUID.

The registry says who was **assigned** a UUID. It does not say what the
UUID is used for, that a product advertises it, or that an advertiser
under it is a tag rather than a phone. It is not by itself a row.

## Candidate rows and what each still needs

| Category | Shape | Status |
|---|---|---|
| Samsung SmartTag | Service Data 0xFD59 (unregistered) / 0xFD5A (registered) | Owner's fact-check cites Yu et al. §3 for the two states. Only the abstract was read here (the paper is PDF only); a row waits for that section to be read and quoted. |
| Tile | Service Data or UUID 0xFEED / 0xFEEC | Assignment only. Needs a document showing tags advertise it and with what payload. |
| Chipolo | 0xFE33 / 0xFE65 | Assignment only, and two UUIDs; needs a source saying which the tags use. A row of its own, not shared with SmartTag. |
| Apple Find My (offline finding) | Mfr 0x004C, first octet 0x12 (the issue body's shape) | AirGuard (arXiv:2202.11813) reverse-engineered Apple's tracking protection; only its abstract was read here. Needs the payload layout quoted from a primary text. |

The tests drive the matcher through an in-test table that uses these
shapes as fixtures; that is test data, not a claim that the shapes are
verified.

## Why sloth cites this

`ALERT_TYPE_BLE_WATCHLIST` fires per (category, sensor) when a matching
advertiser was heard in the last 120 s. Empty technique, on the
cited-basis list in `tests/test_research_corpus.c`: a tag in range is a
third party's device being present, and the same tag rides in its
owner's own bag, so T1430 (Location Tracking) would claim an intent the
advertisement cannot carry.

## What it does not say

- **Category, never identity** (the #94 posture). Finder tags use
  random addresses that rotate, so the alert counts addresses, not
  devices, and never says "this tag" or "this person".
- **No stalking verdict.** The issue's CRIT for a "stalk-grade" category
  from a "non-resident" source is deferred: "non-resident" has no
  definition yet.
- **No "same tag across days".** Linking a rotated address back to a tag
  needs the tag's keys, which sloth does not have and does not seek.
