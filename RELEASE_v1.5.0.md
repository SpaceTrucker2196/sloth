# sloth v1.5 — synthesis, provenance, operator posture

The synthesis release. v1.4 broadened protocol detection; v1.5
finishes the loop between "what did we see" and "what does it mean":
every alert now carries a MITRE ATT&CK technique, TLS handshakes get
JA4 alongside JA3, cleartext credentials are surfaced as first-class
events (with an ironclad "no password value, ever" guardrail),
devices carry an explainable risk bucket, and shutdown produces a
signed-off posture report. A locally-populated manifest also gives
the operator opt-in version-awareness without sloth ever touching
the network.

## MITRE ATT&CK tagging

Every alert type now maps to a canonical ATT&CK technique via
`alert_technique()` in `src/alerts.c`. The value is populated on
`fire()`, shown on the alert detail panel, and emitted as a
`"technique"` field in the JSONL log. Host-posture alerts (like
`NO_MONITOR_MODE`) correctly map to the empty string so the field is
omitted rather than tagging the operator's own rig as an adversary
technique.

Coverage: the brute-force family maps to T1110.001; Kerberos
pre-auth spray to T1110.003; LDAP enumeration to T1087.002; the
threat-intel / DNS-tunnel family to T1071 / T1071.004; ARP spoof to
T1557.002; rogue DHCP / RA / evil-twin to T1557; weak TLS to T1600;
HTTP attack path to T1190. See `docs/views/alerts.md` for the full
table.

## JA4 client fingerprinting

TLS ClientHellos now carry a **JA4** fingerprint alongside the
existing JA3 (`ja4` field in `tls_log_entry_t`, emitted in JSONL as
`"ja4"`). JA4 solves JA3's extension-order sensitivity by sorting the
cipher and extension lists before hashing, so Chrome/Firefox
extension randomization no longer changes the fingerprint.

Format (FoxIO spec) is 36 chars total:

```
t 13 d 15 16 h2 _ 8daaf6152771 _ b0da82dd1658
```

Section a encodes protocol / version / SNI flavour / cipher count /
extension count / ALPN edge chars. Sections b and c are truncated
SHA-256 over the sorted lists. New embedded SHA-256 module
(`src/sha256.c`) verified against RFC 6234 test vectors.

## Cleartext credential exposure

New `CLEARTEXT_CRED` alert (WARN, T1040 Network Sniffing) fires when
sloth observes authentication material sent in the clear over:

- HTTP Basic (TCP/80, 8080, 8000)
- FTP `USER`/`PASS` (TCP/21)

**Guardrail — no password field, ever.** The recorder module has no
code path that accepts, stores, or hashes password bytes; the JSONL
schema has no field for it; the alerts detail panel doesn't show it.
The posture report calls the rule out explicitly. Adding a password
field would be a scope violation on the passive-observation contract
in `MISSION.md §2`. See `docs/wiki/jsonl-schema.md` for the schema
policy.

Additional protocols (POP3, IMAP, SMTP AUTH LOGIN, Telnet) are staged
for a follow-up landing.

## Passive device risk scoring

Every device row in `[g]` Devices now carries a **Risk** column with
a heat-graded bucket: **LOW** / **MED** / **HIGH** / **CRIT**. The
score is a transparent weighted sum of six independently-observable
signals — no ML, no black box:

| Signal            | Weight | Meaning |
|-------------------|-------:|---------|
| `RANDOM_MAC`      | 1      | locally-administered MAC (privacy MAC) |
| `UNKNOWN_VENDOR`  | 1      | OUI not in the embedded table |
| `NO_HOSTNAME`     | 1      | no DHCP/mDNS/NBNS resolution |
| `PROBE_ONLY`      | 1      | probe frames, no STA/beacon association |
| `CLEARTEXT_CRED`  | 3      | device leaked a credential in the clear |
| `ALERT_TAGGED`    | 3      | an active alert names this device's IP |

The signal bitmask is emitted in JSONL (`risk_signals`) so external
consumers can reproduce the score.

## Posture report export

New `--report FILE.md` and `--report-json FILE.json` write a
session-summary artifact at shutdown. Rollup covers:

- Alert counts by severity (LOW / WARN / CRIT).
- MITRE ATT&CK technique breakdown with hit counts.
- Cleartext credential exposures, with the "never a password value"
  reminder inline.
- High-risk devices (HIGH + CRIT only, with signal bitmask).
- Session start / end / duration.

Written once at shutdown after the main loop drains, so the file is a
signed-off session record rather than a mid-run snapshot. See
`docs/wiki/posture-report.md`.

## Version check-in

New `--check-manifest FILE` reads a locally-populated JSON manifest
and displays "update available" in the help view when its `"latest"`
field exceeds `SLOTH_VERSION`. sloth **never fetches from the network
itself** — populating the manifest is the operator's responsibility.
The reference script at `examples/updater/check-latest.sh` is the
recommended producer, but a systemd timer, cron job, or any other
policy-appropriate process works.

Reader is cache-aware: `stat()`s the manifest at most once per 60 s
and only re-reads on mtime change. Missing / malformed files set an
error flag and preserve last-good state so a transient failure
doesn't clobber the display.

Manifest format is documented in `docs/wiki/manifest-format.md`;
architecture in `docs/wiki/version-checkin.md`.

## Platform parity

BSD / macOS now detects WiFi monitor-mode via `SIOCGIFMEDIA` +
`IFM_IEEE80211_MONITOR`, matching Linux's `/sys/class/net/<if>/type`
detection. `NO_MONITOR_MODE` fires identically across both platforms.

## Bugs fixed

Three reporter-filed bugs closed pre-v1.4 tag (rolled up here for
completeness against the last release cadence):

- **#13** — active view gets first refusal on shadowed keys via a
  centralized `view_claims_key` table.
- **#14** — TLS `supported_versions` extension GREASE-filtered so
  Chrome/Firefox TLS 1.3 handshakes no longer mislabel as `"TLS"`.
- **#15** — dashboard interfaces band honours the iface hide election.

## Security policy

`SECURITY.md` replaced the stock GitHub template with a real
supported-version policy (1.4.x archived, 1.5.x now current),
vulnerability reporting instructions via the GitHub Security
Advisory flow, and a pointer to `MISSION.md` for the passive-only
guarantee.

## Stats

- 16 commits since v1.4.0
- 28 alert rules (+1)
- 31 views (unchanged)
- 3117 test assertions (+371)
- 2 new external modules: SHA-256, semver

## Upgrade

```
git pull
make
sudo ./sloth --data-socket unix:/tmp/sloth.sock \
             --eapol-dir /tmp/sloth-eapol \
             --check-manifest /var/lib/sloth/version-manifest.json \
             --report /tmp/sloth-posture.md \
             -o /tmp/sloth.jsonl
```

Nothing removed; the JSONL schema is additive (`technique`, `ja4`,
`risk`, `risk_signals` fields, plus a new `cleartext_cred` record
type). Existing consumers keep working.
