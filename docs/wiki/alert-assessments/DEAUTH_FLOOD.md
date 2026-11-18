---
type: DEAUTH_FLOOD
technique: T1498.001
rule_file: src/alerts/rules_wifi_mgmt.c:64 (rule_deauth_flood)
count_semantics: per poll tick (default 250 ms) while the (BSSID, victim) aggregate's `flood` flag is set - the flag holds for DEAUTH_FLOOD_HOLD_SECS = 10 s after the last window that met the threshold; not per frame (the frame tallies are in the detail as `observed N frames, peak P in Ws`)
severity_assessment: agree - WARN at another network's BSSID, CRIT at a `--my-bssid` network is the right split; the rule honestly states it cannot prove sender or effect
false_positive_risk: medium - a real AP or WLAN controller also emits deauth bursts (rogue containment, band-steering, mass disconnect on reconfig); retries are already excluded, which removes the main innocent cause
noise_verdict: quiet on the reference host - 28 keys, 52,979 fires, max_sev CRIT. Fires count re-evaluations (<= 4/s), not frames; 52,979 across 28 (BSSID,victim) pairs is roughly 1,900 evaluations per pair, about 8 minutes of held flood state each - consistent with a handful of real bursts per pair, not a firehose. The key already dedupes per victim, so no extra throttle is needed; if a noisy RF environment inflates it, raise deauth.flood_thresh or widen deauth.flood_window_s
prevalence: very common - the single most widely available Wi-Fi attack; every commodity pentest distro and sub-$50 microcontroller ships it ([4],[5],[6],[7]); also emitted lawfully by WLAN "rogue containment" features ([8]) and unlawfully by venue Wi-Fi blocking ([9])
tuning: [deauth.flood_thresh (default 5, 2..32; DEAUTH_FLOOD_THRESH), deauth.flood_window_s (default 5, 1..600), --my-bssid (sets CRIT vs WARN, #52), --collect-handshakes + --eapol-dir (gates the evidence pcap), pcap.min_severity, pcap.key_cooldown_secs]
researched: 2026-10-27
---
## What the rule checks

`rule_deauth_flood()` (`src/alerts/rules_wifi_mgmt.c:46-82`) walks
`s->deauth_victims[]` and, for every aggregate whose `flood` flag is
set, fires `ALERT_TYPE_DEAUTH_FLOOD`. Severity is `ALERT_SEV_CRIT` when
`ownership_is_my_bssid(v->bssid)` is true (the BSSID was designated with
`--my-bssid`, #52), `ALERT_SEV_WARN` otherwise. Key is
`deauth:<victim>@<bssid>`, so each (victim, BSSID) pair is its own
incident and two APs' broadcast deauths are two alerts. The detail
reports what was observed and nothing it cannot support:
`victim=<mac> bssid=<mac> observed <frames> frames, peak <peak> in <W>s,
reason=<code|encrypted|unknown>, <streams> streams; sender unverified,
disruption not confirmed`, with ` - YOUR network` inserted before the
semicolon when the BSSID is `--my-bssid` designated (so a CRIT and a
WARN at the same pair also differ in detail text).

The aggregates are built in `src/deauth_snoop.c`, fed from the monitor
path. The parser (`deauth_parse_frame()`, `deauth_snoop.c:122+`) accepts
only type-0 management subtype 10 (disassociation) or 12
(deauthentication), reads the +HTC Order bit to find the body offset
(IEEE 802.11-2020 §9.2.4.1.10, §9.3.3.2), and decodes the Reason Code
(§9.4.1.7) only from a cleartext individually-addressed body; a
PMF-protected body is ciphertext and the reason stays `encrypted`, a
truncated one `unknown`.

The flood decision is a sliding window (`flood_window.c`, used via
`src/deauth_snoop.c:256-268`): `flood` latches when at least
`deauth.flood_thresh` (default 5) **distinct** frames fall inside some
`deauth.flood_window_s` (default 5 s) half-open window `(t-W, t]`.
Critically, retransmissions are not distinct: a frame with the Retry bit
set and the same sequence number as the previous frame in its stream is
the same MPDU the receiver's duplicate filter discards (§10.3.2.14), so
it is counted as observed (`retries`) but cannot build a flood
(`deauth_snoop.c:240-254`, `docs/views/deauth.md:72`). The window runs on
the monotonic clock, so an NTP step neither creates nor breaks a flood.
`flood` decays `DEAUTH_FLOOD_HOLD_SECS` = 10 s after the threshold was
last met (`HOLD_MS`, `deauth_snoop.c:16`) - longer than the window so a
1 s poll cannot miss a short burst. Rows and aggregates age out after
`DEAUTH_AGE_SECS` = 60 s of monotonic idle; each table holds 128 rows and
evicts the least-recently-heard, counted as `evict_deauth_obs` /
`evict_deauth_victim` (#143).

Count semantics: `fire_ev()` re-asserts the key every tick the flag is
set, bumping `evaluations`/`count` (`engine.c:478`); `observations` moves
only when the detail string changes. The incident resolves 300 s after
the last assertion.

## The attack

A deauthentication or disassociation frame is a management frame that
tells a station it has been disconnected. In the original 802.11 design
these frames are unauthenticated, so a receiver "has no way to tell a
real one from a forged one" [1]: anyone in radio range can transmit a
frame claiming any source address and knock a client off its network.
Because the shared resource on 802.11 is airtime, not bandwidth, the
attack is cheap and indiscriminate - MITRE files it as T1498.001, Direct
Network Flood, "send enough of something that nothing else gets
through" [1][3].

What an attacker gains is one of two things. Either disruption for its
own sake - keeping a specific device (a camera, a laptop) off the
network - or, more often, forcing a client to reconnect so its WPA
handshake can be captured for offline password guessing. The aircrack-ng
documentation lists exactly these uses: "Capturing WPA/WPA2 handshakes
by forcing clients to reauthenticate", recovering a hidden ESSID, and
ARP generation [4]. Tooling is abundant and requires no skill: mdk4
mode d "sends deauthentication and disassociation packets to stations
based on data traffic to disconnect all clients from an AP" [5];
bettercap's `wifi.deauth` will deauthenticate "every client" of a BSSID
or a selected one [6]; hcxdumptool lists "Disconnecting a CLIENT from
an associated ACCESS POINT to get a complete handshake (M1M2M3M4) and a
PMKID" among its default attack vectors [7]; and the same attack runs
on sub-$50 ESP8266 boards - the esp8266_deauther project calls
deauthentication "the main feature" and warns "Use it only against your
own networks and devices!" [11].

The same frames are also sent lawfully by infrastructure. WLAN "rogue
containment" works by spoofing deauthentication with the rogue AP's MAC
so associated clients are kicked off, and vendors warn it "can have legal
implications when launched against neighbor networks" [8]. And it has
been used unlawfully by venues: the FCC fined a hotel operator $600,000
in 2014 after employees "used containment features of a Wi-Fi monitoring
system" to stop guests using their own personal hotspots, a Section 333
violation [9].

The defence is the protocol fix. IEEE 802.11w (Protected Management
Frames, folded into 802.11-2020) authenticates individually-addressed
robust management frames, so a spoofed deauth is simply dropped by a
PMF-associated station; the Wi-Fi Alliance now requires PMF "for all
new certified devices" [10].
This is why sloth also watches the shapes attackers moved to once PMF
spread - `SA_QUERY_FLOOD` and `BTM_ABUSE` [1][3].

## Evidence that proves it

What sloth records:

- The alert detail: victim, BSSID, total observed frames, peak frames in
  one window, decoded reason (or `encrypted`/`unknown`), stream count,
  and the explicit caveat `sender unverified, disruption not confirmed`.
- The `deauth` JSONL record per (bssid,src,dst,subtype):
  `src`/`dst`/`bssid`/`reason`/`subtype`/`first_seen`/`last_seen`/`count`/
  `flood`, plus `reason_valid` (reason is meaningless at 0), `retries`,
  `protected`, `truncated`, and `flood_last`
  (`docs/wiki/jsonl-schema.md:702`). `src` is the *claimed* transmitter -
  spoofable.
- The evidence-ring citation: this is the first wireless rule to cite its
  own frames (#92). Because a deauth carries no IP there is no flow to
  export on, so up to 8 evidence-ring event IDs ride the `alert`/`alert.*`
  records (`evidence_count`, `evidence_id_N`). It cites the *newest*
  frames, not the opening ones, because a flood of thousands evicts its
  own opening frames from the ring before anyone reads the alert
  (`deauth_snoop.c:32-42`).
- The evidence pcap (DLT 127, radiotap + 802.11) at
  `<eapol-dir>/<incident_id>-<event_id>-DEAUTH_FLOOD.pcap`, written only
  with `--collect-handshakes` and `--eapol-dir` set, under the same
  `pcap.min_severity` (default CRIT) and `pcap.key_cooldown_secs` floor -
  so a WARN flood at a neighbour's BSSID writes nothing until it
  escalates (`docs/wiki/pcap-export.md § evidence pcap`).
- `sensor_health`: `evict_deauth_obs`, `evict_deauth_victim` if the
  128-row tables overflow.

To call it real: the pcap/`deauth` rows show deauths claiming the AP's
BSSID as source with sequence numbers that do not continue the AP's own
sequence, frames alternating direction (AP->client and client->AP) or
alternating deauth/disassoc subtype, reason codes in bulk (1
"unspecified", 7 "class-3 frame from nonassociated"), and - the strongest
tell - unprotected deauths aimed at a station that negotiated PMF, which
a real AP on that link would protect (`docs/views/deauth.md:150-160`).
Then look for the *effect* elsewhere, since sloth cannot see it: the
client re-associating (assoc table `[b]`), EAPOL handshakes restarting,
or `SA_QUERY_FLOOD` as the AP's reaction.

What refutes it: the frames carry routine roaming reason codes (4
inactivity, 8 leaving) at a low rate; the "flood" is one roaming station's
own leaving-deauth plus the old AP's class-3 deauths over a channel switch
(retries excluded, this usually stays below threshold); or the BSSID
belongs to a WLAN controller running sanctioned containment [8].

## Benign causes

- **Roaming and channel switches.** "A handful per day during legitimate
  roaming, channel switches, or client wake-ups. Reason codes 4
  (inactivity), 6, and 8 (leaving) are routine" (`docs/views/deauth.md`).
  A roaming station can put several frames on the air in under a second;
  retries are excluded, which keeps the honest case below threshold.
- **Band/load steering.** Enterprise APs disconnect a client to move it
  to another band or a less loaded AP.
- **Rogue containment by a WLAN controller** - identical frames, sent on
  purpose by infrastructure [8]. The BSSID identifies it; `--my-bssid`
  separates "my own gear doing this" from a stranger's.
- **Mass reconfiguration** - an AP disconnecting all clients on a config
  change.

Tell them apart by reason code, rate, retry fraction, whether the target
link uses PMF (a flood of *unprotected* deauths at a PMF station is
suspicious because the real AP would protect them), and whose BSSID it is.

## Assessment

The WARN/CRIT split is correct and well-reasoned: severity encodes stakes
(my network vs a neighbour's), not confidence, and the detail refuses to
overclaim - it never names a sender, because address 2 is whatever the
frame asserts, and never claims a disconnection, because a passive
receiver sees frames and not their effect (`docs/views/deauth.md:112+`).
That restraint is the rule's strength; a responder gets an honest
"someone transmitted a deauth flood at this pair" and must confirm sender
and effect from other evidence.

Prevalence is high: this is the most accessible Wi-Fi attack there is,
available on commodity hardware and in every pentest toolkit [4][5][6][7],
and the same frames appear in lawful containment [8] and in documented
unlawful venue blocking [9]. So firing is expected on any monitored RF
neighbourhood, and the useful signal is the context - victim identity,
whose BSSID, PMF state, and what followed - not the bare fact of a flood.

Reference-host noise is low and does not need intervention. 52,979 fires
are re-evaluations at up to 4/s, not frames; spread over 28 (victim,
BSSID) pairs that is roughly 8 minutes of held flood state per pair -
consistent with a modest number of genuine bursts, each holding the flag
for 10 s past its last qualifying window, re-asserted each tick. The key
already dedupes per pair, so there is no firehose to tame. If an RF-busy
site did inflate the count, the right lever is `deauth.flood_thresh`
(raise it) or `deauth.flood_window_s` (widen it), both in the registry;
`observations` (not `count`) is the figure to trend, since it moves only
when the detail changes.

The evidence is sufficient to act on with one caveat: it proves frames
were on the air, not that the named AP sent them or that anyone dropped.
First response: note victim and BSSID (not the spoofable transmitter);
confirm clients actually dropped from the AP's own logs; check for PMF
and, if the frames are unprotected at PMF stations, treat as hostile;
enable/require PMF (802.11w) as the fix [1][10]; and watch for
`SA_QUERY_FLOOD` / `BTM_ABUSE` as the post-PMF successors.

## Bibliography

1. research/mitre/T1498.md - MITRE ATT&CK T1498 Network Denial of Service (and .001 Direct Network Flood), the repo's corpus document for this kind; retrieved 2026-09-07 from https://attack.mitre.org/techniques/T1498/ (accessed 2026-10-27)
2. research/ieee/802.11-2020-9.6.14.md - repo corpus note on management-frame mechanisms and why spoofed-frame attacks evade deauth detection (accessed 2026-10-27)
3. Direct Network Flood, Technique T1498.001 - MITRE ATT&CK - https://attack.mitre.org/techniques/T1498/001/ (accessed 2026-10-27)
4. aircrack-ng, "Deauthentication" - https://www.aircrack-ng.org/doku.php?id=deauthentication (accessed 2026-10-27)
5. mdk4 README (attack modes b and d), aircrack-ng/mdk4 - https://github.com/aircrack-ng/mdk4 (accessed 2026-10-27)
6. bettercap, Wi-Fi module (`wifi.deauth`) - https://www.bettercap.org/modules/wifi/ (accessed 2026-10-27)
7. hcxdumptool README (disassociation to capture handshakes/PMKIDs), ZerBea/hcxdumptool - https://github.com/ZerBea/hcxdumptool (accessed 2026-10-27)
8. Cisco, "Rogue Management in the Cisco Unified Wireless Network" (containment via spoofed deauth; legal caution) - https://www.cisco.com/c/en/us/support/docs/wireless/4400-series-wireless-lan-controllers/112045-handling-rogue-cuwn-00.html (accessed 2026-10-27)
9. FCC Enforcement Bureau Order DA 14-1444, Marriott consent decree, Oct 3 2014 ($600,000; Wi-Fi containment at Gaylord Opryland) - https://docs.fcc.gov/public/attachments/DA-14-1444A1.pdf (accessed 2026-10-27)
10. Wi-Fi Alliance, "Security" ("PMF is required for all new certified devices") - https://www.wi-fi.org/discover-wi-fi/security (accessed 2026-10-27); IEEE 802.11-2020 §9.6 / Protected Management Frames (802.11w, folded into the 2020 roll-up) - https://standards.ieee.org/ieee/802.11/7028/ (accessed 2026-10-27; the page now marks 802.11-2020 as superseded by IEEE 802.11-2024, which does not change the clause numbers cited here)
11. SpacehuhnTech/esp8266_deauther README ("The deauthentication attack is the main feature"; "Use it only against your own networks and devices!") - https://github.com/SpacehuhnTech/esp8266_deauther (accessed 2026-10-27)

## Verification notes

Verified 2026-10-27 against the working tree (HEAD c5650a3) and every
external source re-opened.

Code: `rule_deauth_flood()` is `src/alerts/rules_wifi_mgmt.c:46-82`;
walks `s->deauth_victims[]`, fires only when `v->flood`, CRIT iff
`ownership_is_my_bssid(v->bssid)` else WARN, key `deauth:<victim>@<bssid>`,
`fire_ev()` with `v->evidence_ids`, `match_ip` NULL - all as written.
Thresholds: `DEAUTH_FLOOD_THRESH` 5 / `DEAUTH_FLOOD_WIN_SECS` 5 /
`DEAUTH_FLOOD_HOLD_SECS` 10 / `DEAUTH_AGE_SECS` 60 (`sloth.h:1199-1211`),
`deauth.flood_thresh` 2..FLOOD_WIN_CAP and `deauth.flood_window_s`
1..600 in `src/tune.c:183-184`; both 128-row tables are `stab_t`
STAB_OLDEST with `evict_deauth_obs` / `evict_deauth_victim`
(`jsonl-schema.md:801`). `flood_window_note()` trips when the
thresh-th most recent frame is younger than `win_ms` (half-open
`(t-W, t]`), `flood_window_active()` holds for `hold_ms` after the trip
- confirmed in `src/flood_window.c:20-47`. The Retry+same-seq duplicate
rule and `DEAUTH_EVIDENCE_IDS == ALERT_EVIDENCE_IDS == 8` confirmed.
Evidence pcap gate (`--collect-handshakes` + `--eapol-dir`) and file
name `<incident_id>-<event_id>-DEAUTH_FLOOD.pcap` confirmed at
`docs/wiki/pcap-export.md:198-209`. Noise arithmetic (52,979 / 28 =
1,892 evaluations per pair; at 4/s about 7.9 min of held flood state
per pair) checks.

Changed: the detail string omitted the ` - YOUR network` suffix the
code appends when the BSSID is designated - added. Line references
corrected: `deauth_parse_frame()` is at `deauth_snoop.c:122`, the
duplicate/retry logic at `:240-254`, the two `flood_window_note()`
calls at `:256-268`. The hcxdumptool sentence was presented as a
quotation but did not match the README; replaced with the README's
actual wording. The ESP8266/Flipper sentence had a bracketed unsourced
aside; replaced with a quoted, sourced statement from the
esp8266_deauther README (new [11]). "PMF is mandatory for
WPA3-certified devices [10]" re-worded to what the cited page actually
says ("PMF is required for all new certified devices"); the
https://www.wi-fi.org/discover-wi-fi/wi-fi-certified-wpa3 page and the
WPA3 specification download were both unreadable (404 / download
shell), so the WPA3-specific statement is not asserted here.

Sources: [3] T1498.001 exists. [4] aircrack-ng three uses quoted
verbatim. [5] mdk4 mode d text verbatim. [6] bettercap "every client is
deauthenticated" verbatim. [7] fixed as above. [8] Cisco: "Containment
works with the spoof of de-authentication packets with the spoofed
source address of the rogue AP so that any clients associated are
kicked off" and "Containment can have legal implications when launched
against neighbor networks" - both verbatim. [9] FCC DA 14-1444 PDF read:
$600,000, Gaylord Opryland, Section 333, "one or more of its employees
used containment features of a Wi-Fi monitoring system" - all verbatim.
[10] see above; IEEE 802.11-2020 page exists. [1] `research/mitre/
T1498.md` lists `ALERT_TYPE_DEAUTH_FLOOD` and names `DEAUTH_FLOOD`;
[2] `research/ieee/802.11-2020-9.6.14.md` exists and names
`ALERT_TYPE_DEAUTH_FLOOD` at line 46 (its `alert_kinds` is `BTM_ABUSE`
only; it is cited here for the "no deauth frame at all" point, not as
this kind's corpus document - that is [1]).

Second pass, 2026-10-27, HEAD 0d60387. No source file this entry cites
changed since c5650a3. Re-read: `rule_deauth_flood()`
`rules_wifi_mgmt.c:46-82` (key `deauth:%s@%s` = victim@bssid, CRIT iff
`ownership_is_my_bssid()`, ` - YOUR network` before the semicolon,
`fire_ev()` with `v->evidence_ids`, no `match_ip`); `deauth_snoop.c`
`:14-17` (WIN_MS/THRESH from the registry, HOLD_MS/AGE_MS from the
`#define`s), `:122-127` (type 0, subtype 10/12 only), `:237-254` (Retry
+ same seq = duplicate, counted in `retries`, bails before the window),
`:256` / `:268` (the two `flood_window_note()` calls), `:270-271`
(`peak_win`); `flood_window.c:20-47`; `sloth.h:1192-1193`
(`MAX_DEAUTH_ENTRIES` / `MAX_DEAUTH_VICTIMS` = 128) and `:1199-1211`;
`tune.c:183-184`. The IEEE clause numbers in the text are the ones the
parser and `docs/views/deauth.md:45,75` cite (9.2.4.1.10, 9.3.3.2,
9.4.1.7, 10.3.2.14). Line span fixed: `flood_window.c:22-46` ->
`:20-47`. [9] could not be text-extracted by the fetcher; the PDF was
pulled down and read with `pdftotext`: DA 14-1444, "Consent Decree for
$600,000", "Gaylord Opryland Hotel and Convention Center in Nashville,
Tennessee", "Section 333 of the Communications Act", "used containment
features of a Wi-Fi monitoring system at the Gaylord Opryland" - all
verbatim. [3] [4] [5] [6] [7] [8] [10] [11] and the T1498 page re-opened
and re-confirmed verbatim; [10]'s IEEE page now flags 802.11-2020 as
superseded by 802.11-2024, noted in the bibliography.
