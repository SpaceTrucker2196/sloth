---
source_url: https://www.theta44.org/karma/aawns.pdf
retrieved: 2026-11-11
topics: [karma, probe-response, rogue-ap, pnl, hidden-ssid, directed-probe]
alert_kinds: [ALERT_TYPE_KARMA_PROBE_FORGE]
citation: "D. A. Dai Zovi and S. A. Macaulay, \"Attacking Automatic Wireless Network Selection\", 2005-03-18 (paper PDF as served by theta44.org)"
---
# KARMA as its authors built it: an access point that answers any probe

The basis for `KARMA_PROBE_FORGE` (#187 S2). This is the paper that
named the attack, read from the PDF on 2026-11-11 (text extracted with
`pdftotext`); every quotation below is from that text.

## What the paper says the attack is

The attack is an access point that claims to be whatever network a
station asks for by name. The paper's own words: "We created a special
access point that responded to any Probe Request, allowing us to serve
any SSID requested by a client within range", and, for the attack
driver, "This attack may be performed by modifying the firmware of an
Access Point to respond with Probe Responses to Probe Requests for any
SSID." The summary section names the construction "a special software
access point that masquerades as any SSID".

That is the observable sloth now reads: **one BSSID sending Probe
Responses that name SSIDs the stations asked for, where those SSIDs are
not the BSSID's own.** A real BSS has one SSID; a radio answering to
several names it never advertised is the construction this paper
describes.

## What it says about legitimate behaviour, and why the detector
## filters what it filters

The paper is also the source for the case that must *not* fire. Of
ordinary access points it says they "typically respond to both
broadcast Probe Requests and Probe Requests containing their SSID with
a Probe Response frame", and that "many Access Points support an option
to ignore broadcast Probe Requests and not broadcast the SSID in Beacon
frames. Such access points are referred to as a closed or hidden."

So an AP answering a directed probe for *its own* name, hidden or not,
is the protocol working. `karma_observe_frame()` drops any answer whose
SSID is the BSSID's current name as the beacon table knows it, and the
capture path reveals a hidden AP's name from its probe response before
that check runs, so the hidden AP's own answer is its own name by the
time it is judged. An answer to a broadcast (wildcard) probe carries the
responder's own SSID and pairs with no directed request, so it is not
recorded either.

## What it does not say

- **No threshold.** The paper describes the mechanism, not a count. The
  rule's "two distinct never-beaconed names" is sloth's: the smallest
  number one BSS cannot produce by being itself (`src/karma_detect.h`
  argues it). It is a tunable (`karma.forge_ssids`), not a value from
  this source.
- **No timing signature.** Nothing in the paper measures how fast the
  attack driver answers. #187's S3 (probe-response latency) is not
  built for that reason: no primary source for it was found.
- **Modern clients.** The paper's experiments are on Windows XP and Mac
  OS X clients of 2005. Clients that no longer send directed probes for
  their whole preferred list give this detector less to see; that
  narrows what it catches, it does not create false positives.

## Related

- `research/tools/airbase-ng.md` — the same behaviour as a shipped
  tool option.
- `research/mitre/T1557.md` — the technique `KARMA_AP` and
  `KARMA_PROBE_FORGE` both map to.
