---
name: exposure-report
description: What the operator's own site reveals to an outside observer, grouped by what the observer learns; each group with the coverage status of the rules behind it, so "nothing found" is not read as "nothing there"
type: reference
---

# Exposure report: what this site reveals

**Summary**: sloth has many exposure findings, each on its own. The exposure report groups them by what an observer outside the site learns: network names, device makes and presence, clear-text credentials, self-announcing devices, weak encryption lanes, devices in setup mode. It is a section of `--report` and `--report-json` ("What this site reveals") and a JSONL record, `exposure_summary` (JSONL 2.11.0). It covers the operator's designated networks and rostered devices only, and each group states whether its rules could see anything ([[coverage-assessment]]). Receive-only: it summarises findings sloth already holds.

**Sources**: issue #243 (from #241 item 6); FM 2-0 (2004) 1-30 (a commander lists the information to protect) and 1-111 (counterintelligence finds how an observer could collect it); `include/sloth_exposure.def` (the table); `src/exposure.c`; `docs/wiki/alert-remediation.md` (each line's fix); `tests/test_exposure.c`.

**Last updated**: 2026-11-24 (#243: first version)

## 1. The groups

`include/sloth_exposure.def` puts each alert kind in at most one group. It is a sibling of `include/sloth_alerts.def`, like `sloth_alert_inputs.def` and for the same reason (that file is in the contract with a two-argument `X`), and `tests/test_exposure.c` holds it to that file row for row: every kind classified, same order. A kind not listed here is in no group: an attack, an anomaly or the sensor's own state is not something the site reveals.

| # | Group (`group` word) | Kinds | What the observer learns |
|---|---|---|---|
| 1 | Network names and their history (`network_names`) | `MY_NETWORK_RECON` | a device probing for a designated network's name: the name is known outside, and the probing device's list of remembered networks says where it has been |
| 2 | Device makes, models and presence times (`devices`) | `SURV_CLOUD_SNI`, `SURV_DNS`, `RECURRING_TRANSIT`, `TPC_ABSENT_HIGH_BAND`, `COUNTRY_ABSENT` | a surveillance vendor's cloud named in a TLS SNI or a DNS query says which make of camera or body-worn system is on site; a rostered device's repeated passes give its presence times; an AP whose beacons lack the TPC or Country elements discloses a build with 802.11d/h switched off (a judgement: the finding is a hygiene one, and what it gives an observer is the class of equipment) |
| 3 | Credentials and user names in clear text (`credentials`) | `CLEARTEXT_CRED`, `PEAP_NO_SERVER_CERT` | a user name (and that a password was sent) over a clear-text protocol; a client that completed PEAP without the server proving itself will give its inner credentials to anyone who answers |
| 4 | Cameras and other devices that announce themselves (`self_announcing`) | `CAM_WS_DISCOVERY`, `CAM_MDNS_SERVICE`, `CAM_SSDP_DEVICE`, `CAM_RTSP_UNAUTH` | a camera's existence, vendor and model from its own WS-Discovery, mDNS or SSDP announcement; an RTSP stream that answers without authentication |
| 5 | Weak encryption lanes a device can be moved to (`weak_lanes`) | `WPA_DOWNGRADE`, `SAE_PSK_SPLIT`, `SAE_PSK_REGRESSION`, `SSID_CONFUSION`, `MLE_CROSS_LINK_CIPHER_DOWNGRADE` | a designated network offering, beside its primary posture, a weaker one (PSK beside SAE, MFP optional, TKIP, a weaker link of a Wi-Fi 7 MLD): the lane an attacker would move a client to |
| 6 | Devices in setup mode (`setup_mode`) | `OPEN_SETUP_AP`, `CAM_SETUP_SSID`, `CAM_SETUP_OUI` | an unconfigured device's open setup network, by name or by a camera vendor's address block |

`tests/test_exposure.c :: test_named_groups` writes this list out and holds the table to it, so a change here and there go together.

## 2. Scope: the operator's own site

The report is about the operator's site, not the neighbourhood. A site is named with `--my-ssid`, `--my-bssid`, `--known-mac` or `--known-macs` ([[cli-reference]]). **With none of them** the section says so and names those flags; it lists no group and no finding, and the stream's rows read `needs_designation`.

With a designation, each finding is tied to it by its kind's `SCOPE` column, read from the alert's dedup key (the components `src/alert_key.h` builds, so an address is a whole component and a prefix never matches):

- **OWN**: the rule fires only about a designated network (`MY_NETWORK_RECON`, `TPC_ABSENT_HIGH_BAND`). Always in scope.
- **AIR** (heard over the air): in scope when an address in the key is a designated BSSID, a rostered device, or a BSSID the beacon table has beaconing a designated SSID; or when the key names a designated SSID, raw or as `akey_remote()` writes it (matched by the hash of the whole SSID, so a long or sanitised name still matches).
- **LAN** (the IP capture): in scope when an address in the key is a rostered device's address (its `device` row's IP), or when the managed link is associated to a designated network, since what the IP capture then sees is that network's. A wired sensor's LAN findings are in scope through the roster only.

A finding of a grouped kind that cannot be tied to the designation is counted (`outside`) and not described.

## 3. Each group's statement

Every group carries the coverage status of its kinds ([[coverage-assessment]] § 3): how many are `observable`, `partly`, `blind`, and the reason words of those that are not observable. The statement is then one of:

| State | Report sentence |
|---|---|
| `found` | `Found: N findings of K kinds.` and one line per kind |
| `none_observable` | `Nothing found, rules observable.` |
| `none_partly` | `Nothing found; rules partly observable: <reasons>.` |
| `not_observable` | `Not observable: <reasons>.` (every rule blind) |
| `not_assessed` | `Nothing found; coverage not assessed: <why>.` (before the first status sample, or a `--replay`) |
| `needs_designation` | the section's one paragraph naming the flags |

So an empty group is never silent: "nothing found" always comes with whether the rules could have found anything. Example, a sensor with one hopping radio, no IP capture and a roster of seven devices but no designated network (Beta-Site's set-up on 2026-11-24): group 1 reads `Not observable: no_own_net.` and group 4 `Not observable: no_source.`.

## 4. In the report

**`--report`**: a "What this site reveals" section after "Finding quality". Each group is a `### N. <title>` with its statement and its rules (`Rules: 3; observable 3, partly 0, blind 0.`), then one line per kind found:

```
- `OPEN_SETUP_AP`: 1 finding, evidence 4, first `2027-01-15T08:00:00Z`, last `2027-01-15T08:05:00Z`. Fix: If the device is the operator's: finish setting it up so it leaves the open SoftAP, or power it off.
```

The finding count is incidents (distinct alert keys) in scope; the evidence count is their `observations` summed; first and last seen are the earliest and newest sighting. The fix is the first **Fix** step of the kind's section of [[alert-remediation]], compiled in from `include/sloth_exposure.def`: `tests/test_exposure.c :: test_remedy_is_the_pages_first_fix_step` reads the page and fails, printing the page's current text, when the two differ. The section names kinds only, not the addresses or user names behind them; the report's own "Cleartext credential exposures" table is where those are.

**`--report-json`**: the member `exposure`, after `risky_devices` and before `findings` (`coverage` stays last): `{"designated":false,"needs":[...]}`, or `{"designated":true,"ssids","bssids","rostered","groups":[...]}` with, per group, `group`, `title`, `state`, `findings`, `evidence`, `outside`, `assessed`, `rules`, the coverage counts and `why` when assessed, and `lines` (`kind`, `findings`, `evidence`, `first_seen`, `last_seen`, `remedy`).

## 5. On the stream

`exposure_summary` ([[jsonl-schema]], JSONL 2.11.0), sloth-wifi's: one row per group, **change-only with the heartbeat**, keyed by group. The question it answers ("what does the site reveal, and could we see it") changes when a finding, a kind, a state or a coverage status changes, and the stream's other summaries (`coverage`, `rule_status`) are change-only for the same reason; a report cadence would write six unchanged rows each interval. The signature holds the words and the counts of findings; the evidence total and the times move with every observation of a finding already counted, so they ride the row and are not signed (agents/AGENTS.md, change-only emission).

The row carries **kinds, counts, words and times only**: never an address, a host name, an SSID or a user name, whichever capture the findings came from.

## Fleet

Three groups (credentials, self-announcing devices, device makes through SNI and DNS) are learnt through the managed interface or the wire, which the fleet rule (ADR 0009, agents/AGENTS.md) forbids sharing. `exposure_summary` does not travel, by construction:

- it is a stream record only; nothing writes it to `sloth.db`;
- sloth-mesh's fleet export (`src/web_fleet.c`) writes a fixed set of line types (`fleet_export`, `wifi`, `ble`, `ap`, `probe`, `alert`, `verdict`, the GNSS lines, `fleet_end`) read from `sloth.db`, each with a fixed member list that `jk()` refuses to extend, and the importer (`check_line()`) refuses a line whose members are not on the list; no path copies a stream record into an export;
- the alerts behind the wire-learnt groups are on `web_fleet_withheld_alerts[]` (`src/web_fleetshare.c`) and never travel as `alert` lines either.

A future fleet view of the exposure report would need the owner's ruling on which groups may travel; the record carries no address so that question is about counts only.

## 6. Limits

- The scope test reads the alert key. A rule whose key names neither an address nor an SSID (`CAM_MDNS_SERVICE` keys the service instance) is in scope only through the designated managed link.
- `MLE_CROSS_LINK_CIPHER_DOWNGRADE` keys the MLD address, which is matched against the designated BSSIDs and the beacon table; an MLD address that is no BSSID is in scope only when it is designated itself.
- The groups are a judgement about what each finding discloses; § 1 says why for each, and the table and that list change together.
- Not built: a dashboard page (a separate issue in sloth-mesh once the record exists), a TUI view, and the PNL of rostered devices as a line of its own: group 1 has the designated-network probes `MY_NETWORK_RECON` reports, and a rostered device's own probe list is not yet a finding.

## Related pages

- [[coverage-assessment]] — the statuses each group carries
- [[posture-report]] — the report the section is in
- [[alert-remediation]] — each line's fix
- [[jsonl-schema]] — `exposure_summary`
- [[fleet]] — what travels and what does not
- [[camera-detection]] — the camera kinds of groups 4 and 6
