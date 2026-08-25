# Rogue RADIUS  `[z]`

Table of 802.1X EAP conversations — one row per BSSID seen running an
EAP exchange, with the inner methods it offered and any identities that
leaked in the clear. The browsable surface for the `ROGUE_RADIUS`
detector (#31); the view itself shipped in #38.

## Protocol / data source

WPA-Enterprise carries an EAP conversation (RFC 3748) inside EAPOL
EAP-Packet frames — captured on the air by the monitor radio, decoded
by `eap_parse()`, and accumulated per BSSID by `eap_track_observe()`.
`eap_track_snapshot()` copies the table into `s->rogue_radius[]` each
poll; the view reads only that snapshot. Passive only — sloth decodes
bytes already captured, it never speaks EAP.

## What sloth captures

Per BSSID:

- **EAP methods** — every inner method type observed, decoded from the
  `eap_types_seen` bitmap (`MD5`, `GTC`, `TLS`, `TTLS`, `PEAP`,
  `MSCHAPv2`, …; unnamed type codes render as `T<n>`). Identity /
  Notification / Nak frames are RFC 3748 "special" types, not methods,
  and are not listed.
- **weak** — `YES` when the AP offered EAP-MD5 (offline-crackable
  challenge/response) or EAP-GTC (password crosses in cleartext to the
  server). Honest enterprise APs negotiate TLS-protected methods;
  offering a weak method is the `eaphammer` / `hostapd-wpe`
  credential-harvest lure.
- **leaks** — count of Response/Identity frames carrying a real
  username (anonymous outer identities — `anonymous@…`, bare `@realm` —
  don't count). Clients configured without outer-identity privacy leak
  their username to anyone listening, rogue or not.
- **Last identity** — the most recent leaked username, with seconds
  since the AP was last heard.

Rows sort weak-method APs first, then most recently active, so the row
most likely to be hostile floats to the top. The same signals drive the
`ROGUE_RADIUS` alert in `[v] Alerts`.

## View

```
 ── Rogue RADIUS ──────────────────────────────────────────────────
 802.1X EAP conversations: 2 APs / max 32  weak-method APs: 1  identity leaks: 2
 BSSID              EAP methods           weak  leaks  Last identity / seen
 -----------------  --------------------  ----  -----  --------------------
 00:11:22:33:44:55  MD5,PEAP              YES       2  jdoe@corp.example (3s)
 66:77:88:99:aa:bb  TLS                   -         0  - (11s)
 weak = MD5/GTC offered (eaphammer / hostapd-wpe lure); leaks = non-anonymous Response/Identity
```

The BSSID is bright; `weak` and `leaks` go bright when set to draw the
operator's eye.

## What's normal

- Zero rows on a home/PSK network — 802.1X EAP only appears around
  WPA-Enterprise.
- Rows showing `TLS`, `TTLS`, `PEAP` (often with `MSCHAPv2` as the
  tunnelled inner method) and zero leaks: a healthy enterprise ESS.
- A small leak count with no weak method: clients missing anonymous
  outer identities — a hygiene finding, not an active attack.

## What's suspicious

- **weak = YES** — an AP offering MD5/GTC is either badly misconfigured
  or a credential-harvesting rogue (`eaphammer --creds`,
  `hostapd-wpe`). Cross-check the BSSID against `[x] Twins` and
  `[b] Beacons`: a weak-method AP advertising your corporate SSID from
  an unknown BSSID is an active harvest.
- **Leaks climbing on one BSSID** while other APs of the same ESS show
  none — clients are being steered to (or answered by) that radio.
- **A new BSSID appearing mid-day** with your SSID and an EAP
  conversation — enterprise evil twins fire this view and the twin
  detector together.

## The `TLS?` column — CVE-2023-52160 (#65)

`ROGUE_RADIUS` above is about the AP: which methods it offers, whose
usernames it collects. The `TLS?` column answers the opposite question,
about the **client**.

In a sound TLS-in-EAP exchange the AP sends a **ServerHello** and a
**Certificate** before the client commits, and both travel unencrypted
inside EAP-Request frames where a monitor-mode radio can see them. If
EAP-Success arrives and neither was observed, a client on this network
authenticated to a server that never proved who it was — the runtime
signature of [CVE-2023-52160](https://nvd.nist.gov/vuln/detail/CVE-2023-52160),
which shipped on millions of Android and ChromeOS handsets.

| Shown | Meaning |
|---|---|
| `-` | no TLS-in-EAP session has completed here — nothing to judge |
| `NONE` | a session completed with **no server identity presented** |

A tick is deliberately never shown. The absence of a finding is not
proof the handshake was sound, only that this one was not caught
missing — sloth does not reassemble EAP-TLS fragments, so a long
certificate chain can cross a boundary it does not follow.

`NONE` fires `ALERT_TYPE_PEAP_NO_SERVER_CERT`, and the alert detail
distinguishes the confident case (`no TLS ServerHello` — the AP never
started a handshake) from the weaker one (`no Certificate observed`).

Full write-up, including what to do when it fires:
[enterprise-rogue](../wiki/enterprise-rogue.md).

## See also

- [eapol.md](eapol.md) — the EAPOL-Key / handshake capture the same
  frames flow through.
- [twins.md](twins.md) — evil-twin episodes; an enterprise rogue
  usually trips both.
- [beacons.md](beacons.md) — per-BSSID RSN/AKM inventory to confirm
  what the AP advertises.
- [alerts.md](alerts.md) — the `ROGUE_RADIUS` rule.
