# Vendor research: what slothweb knows about an OUI's holder

**Summary**: slothweb's device drawer and Lookup card show, under the
OUI card, a "vendor research" section: who the registrant of the block
is, what a MAC in its blocks usually is, the silicon documented in its
modules and products, the radios, FCC grantee codes, whether its devices
randomise, notable advisories, each field with a confidence word and
every claim with a numbered source. The research is committed data, one
Markdown file per vendor under `web/data/vendors/`, compiled into the
binary at build time by `web/tools/vendorkb.c`: slothweb fetches nothing
at run time. This page is the file format, the rules the generator
enforces, and how the section reaches the page.

**Sources**: `web/data/vendors/*.md`, `web/data/vendors/COVERAGE.md`,
`web/data/vendors/REFERENCE_HOST.txt`, `web/tools/vendorkb.c`,
`web/src/web_vendorkb.h`, `web/src/web_vendorkb.c`,
`web/src/web_devices.c` (`research_member()`), `web/ui/app.js`
(`vendorResearch()`), `web/tests/test_vendorkb.c`, `web/data/SOURCE.md`.

**Last updated**: 2026-11-01 (the research set:
<!-- count:vendors -->277<!-- /count --> entries, covering 160 of the
reference host's 163 vendor names, three pending; before it, the
pipeline and three sample entries; owner request of 2026-10-27).

## What is covered

`web/data/vendors/` holds <!-- count:vendors -->277<!-- /count -->
entries (`make docs-counts` keeps that number). They were written by two
research sessions on 2026-10-27, each entry from the sources it cites,
and each session re-fetched its entries' cited URLs to check the claims
before handing them over; the session that merged them fetched the
sources of ten more entries again (Ubiquiti, Nest Labs, ecobee, iRobot,
Sony Interactive Entertainment, D-Link International, MediaTek, Taiyo
Yuden, Sierra Wireless, Nintendo) and found every checked claim on the
cited page. No source was found by a web search in that last pass: the
search budget was spent, so verification fetched only URLs the entries
already cite.

The set leads with the reference host's vendors: every distinct IEEE
name the MACs on that host resolved to, 163 names over 1672 devices,
listed in `web/data/vendors/REFERENCE_HOST.txt`. `COVERAGE.md` beside
the entries splits that list in two. Under Have are the 160 names (1667
devices) that find an entry, each with the file it finds. Under Pending
are three names (5 devices) that have no entry, because no public page,
filing or teardown was found tying them to a company or a product:

- `SJI Industry Company` and `SJIT Co., Ltd.` - the registry gives the
  same Hwaseong-si (KR) street address it gives Seongji Industry Company,
  which has an entry;
- `Reliance Communications LLC` - the registry gives the Hauppauge (NY)
  address it also gives Orbic North America.

A shared registry address is not documentation that two names are one
company, so neither is an alias of the other. The rest of the set is
the commonest registrants beyond the reference host (network equipment,
phones, PCs, modules, automotive).

Where the two sessions both covered a company, the merge kept one file
per IEEE string. Roku was written by both under one slug; the kept file
is the one with a cited value in every field and four security notes
against one. `Alps Alpine` (an alias file for `ALPSALPINE CO,.LTD`) was
dropped for `alpsalpine-co-ltd.md`, which documents the Marvell 88W8887
and CSR8311 silicon the other lacked. Six pairs named two distinct
registry strings, one file listing the other's name as an alias (FN-LINK
and HUNAN FN-LINK, Intel Corporate and Intel Corporation, Microsoft
Corporation and Microsoft, Panasonic Automotive Systems Co.,Ltd and its
Company of America, Vantiva USA and Vantiva Technologies Belgium,
Visteon Corporation and Visteon Portuguesa): both files were kept and
each string left to the file named for it, the alias dropped from the
other.

## Why a vendor, not a product

An OUI identifies the registrant of a block: usually a module maker
(Murata, AMPAK), a brand (Tesla) or a contract manufacturer, never a
product. So "chipset" here means the silicon documented in that
vendor's modules and products, each claim cited, with a confidence per
field, and "unknown" where nothing is documented. Nothing is guessed: a
field with no source is written `unknown`, and the summary says what
could not be consulted. A vendor the registry names but no file covers
shows "no research yet for <name>" plus the IEEE identity the OUI card
already gives.

## The file

One file per vendor, `web/data/vendors/<slug>.md`. The slug is the
vendor's IEEE name lower-cased, every run of characters that are not
ASCII letters or digits turned into one `-`, leading and trailing `-`
dropped: `Murata Manufacturing Co., Ltd.` is
`murata-manufacturing-co-ltd.md`, `AMPAK Technology,Inc.` is
`ampak-technology-inc.md`, `Tesla,Inc.` is `tesla-inc.md`. The
generator refuses a file not named for its `name` field.

```
---
name: <the exact IEEE "Organization Name" string, quoted when it holds a comma>
aliases: [<the registry's other spellings of the same company, exact; may be empty>]
country: <ISO 3166 alpha-2 and a source index, "JP [1]", or unknown>
parent: <"independent [n]", a parent company with [n], or unknown>
founded: <"1944 [1]" or unknown>
kind: <brand | module-maker | odm/ems | chip-vendor | carrier/isp | automotive | network-equipment | other>
device_classes: [<phone, laptop, tablet, wearable, tv, speaker, camera, iot-sensor, smart-home, ap/router, switch, printer, console, automotive-telematics, automotive-infotainment, drone, pos, medical, industrial, module-in-other-brands, unknown; each may carry [n]>]
found_in: [<brands/products carrying this vendor's OUI or modules, each with [n]>]
radios: [<"Wi-Fi 4/5/6/6E/7", "2.4 GHz", "5 GHz", "6 GHz", "BT Classic", "BLE 4.x/5.x", "Thread/Zigbee (802.15.4)", "LTE/5G", "LoRa", each with [n]>]
silicon: [<"<family> in <product> [n]">]
fcc_grantee: [<grantee codes, each with [n]>]
randomization: <"randomizes by default (OS X) [n]", "fixed [n]", "mixed [n]", or unknown>
security_notes: [<advisories / CVE classes, each with [n]; may be empty>]
confidence: {country: documented|inferred|unknown, silicon: ..., radios: ..., found_in: ..., randomization: ...}
researched: YYYY-MM-DD
---
## Summary

<3-8 sentences for a network operator. Every sentence with a fact
carries a [n]. Paragraphs are separated by a blank line.>

## Sources

1. <title> - <URL> (accessed YYYY-MM-DD)
2. ...
```

The front matter is the subset of YAML shown: `key: scalar` to the end
of the line (one pair of double quotes dropped), `key: [a, b, "c, d"]`
with items split on commas outside quotes and outside an item's own
`[n]` brackets (a list may run on over several lines until its closing
bracket), and the `confidence: {...}` map. A citation is `[` digits,
separated by commas or spaces, `]`: `[3]`, `[2][5]` and `[2, 5]` all
work. The summary is plain text: no Markdown link, emphasis or code
marks (the page sets it with `textContent`, so markup would show as
markup). A source line is `N. title - URL (accessed YYYY-MM-DD)`, one
per line, numbered 1, 2, ... in order; an indented line continues the
one above.

## The rules the build enforces

`make web`, `make web-test` and `make web-vendorkb` run
`web/tools/vendorkb.c` over every `.md` under `web/data/vendors/`. It
stops the build, naming the file and the defect, when:

- a required field is missing, misspelt, given twice or (for a scalar)
  empty; an unknown field is present;
- `country` is not two capitals or `unknown`; `founded` is not a year or
  `unknown`; `kind` or a device class is outside its word list;
  `confidence` lacks one of its five keys or uses a word other than
  `documented`, `inferred`, `unknown`; `researched` is not a date;
- a `[n]` anywhere names no source line n;
- `country`, `parent`, `founded` or `randomization` is not `unknown` and
  carries no `[n]`; an item of `found_in`, `radios`, `silicon`,
  `fcc_grantee` or `security_notes` carries no `[n]`; the summary cites
  nothing;
- the source list is not numbered 1..n in order, a line lacks
  ` - <URL>` or `(accessed YYYY-MM-DD)`, or anything other than a source
  line follows `## Sources`;
- the file is not named for its `name` field;
- a name or alias, once spelling is folded, is already another file's.

A source that is never cited is noted on stderr, not refused.
`COVERAGE.md` is passed over by name (`WEB_VKB_COVERAGE` in
`web_vendorkb.h`): it is about the entries, not one.

## How the page finds an entry

The generated table (`build/web/web_vendorkb_table.c`, never committed)
keys each entry by its name and each alias after `web_vkb_norm()`
(`web/src/web_vendorkb.h`): ASCII letters lower-cased, digits and bytes
outside ASCII kept, every run of anything else one space, trimmed. So
`FLEXTRONICS`, `Flextronics` and `Flextronics, Inc.` meet, and the
registry's `AMPAK Technology,Inc.`, `AMPAK Technology, Inc.` and
`AMPAK Technology Inc.` all find one file. `web_vendorkb_find()` is a
binary search over the sorted keys; `research_member()` in
`web_devices.c` calls it with the OUI card's vendor and writes the
`"vendor_research"` member of `/api/device/{mac}` and `/api/lookup`
(for a MAC): `{found, file, name, aliases, kind, country, parent,
founded, device_classes, found_in, radios, silicon, fcc_grantee,
randomization, security_notes, confidence, summary, sources [{n, title,
url, accessed}], researched}`, or `{"found":false}` when the vendor has
no file, when the OUI is in no block, and for an IP. Every value goes
through the JSON writer like any other string.

`vendorResearch()` in `web/ui/app.js` draws the section under the OUI
card in the drawer and on the Lookup card: the fields as a kv list with
the confidence word beside the five fields that carry one, the summary
as paragraphs with its `[n]` marks, the sources as plain text lines
(`n. title - URL (accessed date)`). A source is never a link: the page
holds no `href` but fragments (`test_routes.c`) and fetches nothing.

## Tests

`web/tests/test_vendorkb.c`: every `.md` is an entry and every entry a
file named for its name; every `[n]` resolves and every cited field
carries one; the name and each alias are exact `Organization Name`
strings in the committed registry (`web/data/oui.csv`, `mam.csv`,
`oui36.csv`, `iab.csv`), else the entry is dead and the test red; the
lookup folds spelling and matches no prefix; the drawer and Lookup
carry the section for a researched vendor and `{"found":false}` for one
without; the page draws it through one function with no `href` and no
markup sink; and `COVERAGE.md` matches `REFERENCE_HOST.txt` (its two
lists together are exactly the reference names, each once, with its
device count), every name under Have finding the file it names and
every name under Pending finding none, so deleting an entry turns the
test red. `tests/test_docs_consistency.c` holds every
`count:vendors` marker to the number of entry files. Each
absence assertion was seen red under a named mutation (in the test's
comments) and the files restored byte for byte.

## Adding or refreshing an entry

1. Name the file for the IEEE spelling you lead with; list the
   registry's other spellings under `aliases` (each must be an exact
   registry string, or `test_vendorkb.c` is red).
2. Fill every field; write `unknown` or `[]` where nothing is
   documented, and say in the summary what could not be consulted.
   Prefer the vendor's own pages, the FCC ID databases for grantee codes
   and radio modules, FCC internal photos and teardowns for silicon,
   Wikipedia for corporate facts, vendor advisories and NVD for security
   notes. Never another model's summary, never memory.
3. `make web-vendorkb` to check the file alone; `make web-test` for the
   registry check and the rest. If the vendor is one of the reference
   host's, move its line in `COVERAGE.md` from Pending to Have with the
   file it finds; `make docs-counts` for the entry count.
4. The registry CSVs beside the entries are the IEEE's and are refreshed
   only by `make update-oui` (`web/data/SOURCE.md`); an entry is never a
   reason to edit them.

## Related pages

- [[slothweb]] — the dashboard this section is part of (M4's drawer and
  Lookup).
- [[research-corpus]] — the same habit for alert rules: one document per
  source, cited.
- [[mac-randomisation]] — what the `randomization` field is about.
- [[wifi-sigint-guide]] — the radio cloud around a device, which the
  `radios` field summarises per vendor.
