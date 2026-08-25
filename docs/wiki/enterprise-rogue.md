# Rogue enterprise APs — the two halves of the problem

**Issues:** [#31](https://github.com/SpaceTrucker2196/sloth/issues/31),
[#65](https://github.com/SpaceTrucker2196/sloth/issues/65) ·
**Alerts:** `ROGUE_RADIUS`, `PEAP_NO_SERVER_CERT` ·
**View:** `[z]` RADIUS

WPA-Enterprise (802.1X) moves authentication off the AP and into a
RADIUS server, reached over an EAP conversation the client and server
run through the access point. That conversation is the attack surface,
and it fails in two directions that need two different detectors.

## The AP side — `ROGUE_RADIUS` (#31)

An attacker stands up an AP advertising a corporate SSID and offers a
**weak inner method**: EAP-MD5 or EAP-GTC. A client that agrees hands
over either an offline-crackable challenge/response pair or, with GTC,
the password in the clear. `eaphammer` and `hostapd-wpe` exist to do
exactly this.

sloth watches the EAP methods each BSSID offers and the
Response/Identity frames that cross it. A weak method offered is CRIT;
a real username leaked with no anonymous outer identity is WARN.

**This warns you about infrastructure you do not control.** It fires the
moment a lure appears in range, whether or not anyone falls for it.

## The client side — `PEAP_NO_SERVER_CERT` (#65)

The other direction is worse, because nothing looks wrong.

[CVE-2023-52160](https://nvd.nist.gov/vuln/detail/CVE-2023-52160) is a
`wpa_supplicant` flaw: with a common misconfiguration, a client will
complete a PEAP authentication against a server that presented **no
valid TLS certificate at all**. Millions of Android and ChromeOS
handsets shipped in that state. The client associates, EAPOL completes,
traffic flows, and from the outside the session is indistinguishable
from a correct one.

The passive signal is an absence. In a sound TLS-in-EAP exchange the AP
sends a **ServerHello** and a **Certificate** before the client
commits — and those records travel unencrypted inside EAP-Request
frames, in plain view of a monitor-mode radio. If EAP-Success arrives
and neither was ever seen, the client authenticated to a server that
never proved who it was.

**This warns you that your own fleet would fall for the attack.** It is
silent until a device actually does it — which makes it the more
uncomfortable of the two, because a firing `PEAP_NO_SERVER_CERT` is not
a statement about an attacker. It is a statement about your devices.

## Why both

| | `ROGUE_RADIUS` | `PEAP_NO_SERVER_CERT` |
|---|---|---|
| Subject | the AP | the client |
| Fires when | a lure is in range | a device accepts an unverified server |
| Tells you | someone is fishing | you would be caught |
| Fix | not yours — report it | supplicant config on your own devices |
| MITRE | T1557.004 | T1557 |

Neither subsumes the other. An attacker running a *correct-looking*
rogue with a self-signed cert and PEAP-MSCHAPv2 trips neither rule on
methods alone — but trips the client-side rule the moment a vulnerable
handset completes against it.

## What sloth measures, precisely

Parsing is in [`src/eap_parse.c`](../../src/eap_parse.c)
(`tls_scan_handshake`) and [`src/eap_track.c`](../../src/eap_track.c),
fed from `eapol_log.c` where the EAPOL frame's direction and both MAC
addresses are already derived.

Per `(BSSID, STA)` session, between the first TLS-bearing EAP frame and
the EAP-Success or EAP-Failure that resolves it:

- `server_hello` — the **AP** sent a TLS ServerHello (handshake type 2)
- `certificate` — the **AP** sent a TLS Certificate (handshake type 11)

Three constraints worth stating because each is a way to get this wrong:

- **Direction matters.** Only AP→STA frames can establish a server
  identity. A Certificate travelling STA→AP is the *client*
  authenticating — counting it would let a client with a cert mask an
  AP with none.
- **EAP-Failure is not a finding.** The client refused. That is the
  supplicant behaving correctly, and alerting on the safe outcome would
  be exactly backwards.
- **Non-TLS methods are not tracked.** EAP-MD5 has no TLS layer to be
  missing; `ROGUE_RADIUS` covers it, and counting it here would
  double-report the same AP.

## The honest limit: fragmentation

sloth does **not** reassemble EAP-TLS fragments, and this bounds what
the two flags mean.

A ServerHello is the first server handshake message and is small, so it
lands in the first server fragment and is reliably visible. A
Certificate usually shares that record — the server flight routinely
packs them together — but a long certificate chain can push it past a
fragment boundary sloth does not follow.

So the two halves carry different confidence, and the alert says which:

| Detail wording | Means |
|---|---|
| `no TLS ServerHello` | the AP never started a TLS handshake. Unambiguous. |
| `no Certificate observed` | a ServerHello was seen, a Certificate was not. Probably certless — possibly a chain that crossed a fragment boundary. |

A continuation fragment carries no TLS record header, and
`tls_scan_handshake` refuses to interpret one. That matters more than it
sounds: reading mid-certificate DER bytes as a record header invents
handshake types out of certificate data, which for this detector
produces a **false negative dressed as evidence** — it would look like
the parser checked and found nothing.

## Severity

WARN by default. **CRIT** when the BSSID is `--my-bssid`, or the client
is on the `--known-macs` roster. Both are the same judgement: this is
the operator's own fleet demonstrating it would fall for a rogue
enterprise AP, which is the population the CVE actually affects.

## What to do when it fires

1. **Identify the client.** The alert names the STA. Check `[8] ARP` and
   `[d] Devices` to put a name to it.
2. **Check the AP.** If the BSSID is yours, the finding is the client's
   configuration. If it is not, you may be looking at a live rogue — and
   `ROGUE_RADIUS`, `EVIL_TWIN` and `KARMA_AP` on the same BSSID would
   corroborate.
3. **Fix the supplicant.** The client needs `ca_cert` set and
   `domain_suffix_match` (or `domain_match`) configured. Without a CA
   pin, "verify the server" has nothing to verify against. The
   [upstream patch](https://w1.fi/cgit/hostap/commit/?id=8e56d189c48c9b34da2c14a5f6da1ed2b6ce4ec7)
   closes the bypass, but a handset that has not taken the update is
   still vulnerable and still yours to configure.

## Export

- **`[z]` RADIUS view**: a `TLS?` column. `NONE` means a session
  completed here with no server identity presented; `-` means no
  TLS-in-EAP session has completed at all, so there is nothing to judge.
  A tick is deliberately never shown — the absence of a finding is not
  proof the handshake was sound, only that this one was not caught
  missing.
- **SQLite**: the alert persists in `alerts`. The per-AP
  `nocert_sessions` counter is **not** in the `rogue_radius` table — a
  column on an existing table needs a schema-version bump, which makes
  every existing database refuse to open. See the note in
  [sqlite-schema](sqlite-schema.md).

## References

- [CVE-2023-52160](https://nvd.nist.gov/vuln/detail/CVE-2023-52160) —
  wpa_supplicant PEAP bypass.
- [MITRE ATT&CK T1557](https://attack.mitre.org/techniques/T1557/) —
  Adversary-in-the-Middle. (`T1557.004` is in ATT&CK's deprecated
  candidate set; `T1557` is the safe mapping.)
- [CERT/CC VU#871675](https://www.kb.cert.org/vuls/id/871675) —
  background on supplicant trust assumptions.
- [RFC 5216](https://datatracker.ietf.org/doc/html/rfc5216) §3.1 —
  EAP-TLS packet format, the Flags octet and fragmentation.
- IEEE 802.1X-2020 — the exchange sequence this rule observes.

## See also

- [`docs/views/rogue-radius.md`](../views/rogue-radius.md) — the view.
- [`docs/views/alerts.md`](../views/alerts.md) — the rule table.
