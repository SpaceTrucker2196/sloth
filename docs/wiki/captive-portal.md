# Captive-portal interception

**Issue:** [#69](https://github.com/SpaceTrucker2196/sloth/issues/69),
graded and extended by [#169](https://github.com/SpaceTrucker2196/sloth/issues/169) ·
**Alert:** `ALERT_TYPE_CAPTIVE_PORTAL` · **Surfaces in:** `[h]` HTTP,
`[v]` Alerts · **Last updated:** 2026-10-26 (#169)

**Sources:** `research/mitre/T1557.md`, `research/mitre/T1557-004.md`,
`research/tools/connectivity-check-sentinels.md`,
`research/tools/captive-portal-kits.md`.

Every modern OS probes a fixed URL to decide whether it is behind a
captive portal, and expects a published, byte-exact answer:

| OS | URL | Expected |
|---|---|---|
| Apple | `captive.apple.com/hotspot-detect.html` | `<HTML>…<BODY>Success</BODY></HTML>\n` (69 bytes, one trailing LF) |
| Microsoft | `www.msftconnecttest.com/connecttest.txt` (and the IPv6 probe, `ipv6.msftconnecttest.com`) | `Microsoft Connect Test` |
| Microsoft, Windows 8.1 and earlier (#169) | `www.msftncsi.com/ncsi.txt` (and `ipv6.msftncsi.com`) | `Microsoft NCSI` |
| Firefox | `detectportal.firefox.com/success.txt` | `success\n` |
| Firefox up to ESR 140 (captive-portal service) | `detectportal.firefox.com/canonical.html` | the 90-byte `<meta http-equiv="refresh" …/>` page |
| Firefox release | `firefox-portal-detection.com/generate_204`, `/success.txt` | HTTP 204, no body; `success\n` |
| Android / Chrome | `connectivitycheck.gstatic.com/generate_204` (also `www.gstatic.com`, `connectivitycheck.android.com`) | HTTP 204, no body |
| Android 5.x and older (#169) | `clients3.google.com/generate_204` | HTTP 204, no body |

That probe is **deliberately unauthenticated and deliberately
plaintext**. It has to be — the whole point is to work before the user
has any network credentials. Which is also what makes it the cleanest
interception target on the network: answer it wrongly and the victim's
OS obligingly opens a browser at whatever page you serve.

**This is not a heuristic.** The expected answer is documented and
fixed. Anything else on that host and path is an interception, and the
only genuinely hard part is knowing whether the whole answer was seen.

## Three independent signals

A portal that evades one still has to pass the others, which is why
there are three rather than one good one.

| Kind | Fires when |
|---|---|
| `CP_KIND_HIJACK` | a **complete** response on a sentinel URL differs from the sentinel |
| `CP_KIND_DNS_SPOOF` | a sentinel host resolves into RFC1918, CGNAT or link-local space |
| `CP_KIND_DNS_UNEXPECTED` | it resolves to a public address outside the range that host is known to use |
| `CP_KIND_TLS_MITM` | a TLS ClientHello for a sentinel host goes to a private address |

`DNS_UNEXPECTED` is deliberately the soft one, one grade below the
others at every step (below). These are large operators whose addressing
changes, and being wrong about a CDN range must not produce a CRIT.

## Grading (#169)

That the answer is *wrong* is not a heuristic. That a wrong answer is an
*attack* is: a hotel, airport or guest-Wi-Fi portal answers the probe in
exactly the same way, because answering it is what a captive portal is
for. #69 shipped every interception as CRIT, which made a hotel lobby
read as the worst finding sloth has. Since #169:

| Context | `HIJACK`, `DNS_SPOOF`, `TLS_MITM` | `DNS_UNEXPECTED` |
|---|---|---|
| nothing else known | **LOW** — detail ends "legitimate captive portals do this too" | LOW |
| the network is the operator's own (`--my-ssid` / `--my-bssid`) | **CRIT** — "on your own network" | WARN |
| the client's BSS, or the sensor's own link, is a live evil-twin finding | **CRIT** — "AP … is a known evil twin" | WARN |
| the same client was served a named kit's page (below) in the last 10 min | **CRIT** — "client was served fluxion" | WARN |

"The network" is resolved per event, two ways, both stated rather than
guessed. The event is keyed by the client's IP and the monitor table by
MAC, so the first route joins them through the sensor's neighbour (ARP)
table: the client's MAC, then the BSS that MAC was last heard associated
with. A station heard on a twin that is *not* the event's client proves
nothing about it, and nothing escalates. The second route is the
sensor's own station link, used only when the client or the responder is
a neighbour on a Wi-Fi station interface, so a wired client is never
graded by what the sensor's Wi-Fi is attached to. An operator's AP that
is merely *in range* does not count.

Neither route resolves the sensor's own probe answered from a public
address (a portal that DNATs the sentinel's own IP): sloth keeps no list
of its own addresses, and such an event stays LOW rather than being
guessed into CRIT.

The own-network rule is the DET0379 shape (`research/mitre/T1557-004.md`):
a portal is suspicious relative to a baseline of known networks, and the
operator's own network should have none. DET0379 does not name the OS
connectivity probes; the probe mechanism is cited from the vendors.

## Attack-kit portal pages (#169)

A second finding on the same alert type, keyed
`portalkit:<kit>:<server>`: a response on **any** host whose first
segment matches the default portal of a public evil-twin kit. Every row
needs two features from the kit's own source, all present; one feature
alone (a Tornado banner, a "Plugin Manager" title, a 307) occurs on
ordinary sites and is never enough.

| Kit | Row | Features (both required) |
|---|---|---|
| wifiphisher | firmware-upgrade, oauth-login, plugin_update, wifi_connect | `Server: TornadoServer/` **and** that scenario's title or credit line |
| WiFi Pineapple Evil Portal | default page | `<title>Evil Portal</title>` **and** `This is the default Evil Portal page.` |
| WiFi Pineapple PortalAuth | injection set | `#pa_overlay-back {` **and** `/captiveportal/index.php` |
| airgeddon | captive portal | its `portal.css` link **and** its `check.htm` login form tag |
| fluxion | redirect | status 307 **and** `Location: http://captive.gateway.lan/` |
| fluxion | emulated Apple check | its add-on-injected `_gaUserPrefs` script **and** `<title>Success</title>` |
| fluxion | login page | `<title>Wireless Protected Access: Login</title>` **and** `jquery.mobile-1.4.5.min.css` |

Repository URLs, pinned commits and line numbers for every feature are
in `research/tools/captive-portal-kits.md`. T1557.004 is the step these
pages are: a user who joins the impostor "may be directed to a fake login
page or captive portal webpage to capture the victim's credentials".

- **Always CRIT.** No innocent network serves wifiphisher's
  firmware-upgrade page. The benign trigger is someone running the kit
  on purpose — a lab, a training, an authorised test — and the operator
  should know that is happening in range either way.
- **One kit on one server is one finding**, however many clients and
  hosts it answers: the kit serves its page to every URL. For the same
  reason a repeat (same kit, server and client) refreshes its one slot
  in the 64-event ring instead of taking a new one, so a fluxion 307 on
  every host a phone touches cannot evict the probe events it
  escalates.
- **Nothing is kept from the page** beyond the matched row's label, and
  nothing a client sent is read. No form field, no POST body.
- **First segment only.** sloth does not reassemble TCP (#71). A feature
  past the first segment is missed; PortalAuth's injection in particular
  follows the cloned page's own head and reaches the first segment only
  when that head is small. A portal behind TLS shows none of this.
- **Trivially edited.** A match is strong evidence of the kit; no match
  is no evidence of absence.

## The gate everything rests on

**A body sloth did not see whole cannot be compared.**

sloth does not reassemble TCP ([#71](https://github.com/SpaceTrucker2196/sloth/issues/71)),
so a response body larger than the segment carrying its status line
arrives short. A prefix that differs from the sentinel is evidence of a
**segment boundary**, not of interception — and comparing anyway would
report every large page on port 80 as a hijack.

So `cp_check_response()` returns 0 unless `body_complete` is set. The
`[h]` view shows this as a third state rather than hedging:

```
 Time      Src              Method   Host                      Path
 14:02:11  10.0.0.5         GET      captive.apple.com         /hotspot-detect.html [check]
 14:02:11  17.253.144.10    200      captive.apple.com         /hotspot-detect.html [ok]
 14:07:45  10.0.0.5         GET      captive.apple.com         /hotspot-detect.html [check]
 14:07:45  192.168.1.1      302      captive.apple.com         /hotspot-detect.html [HIJACK]
```

`[?]` means the response was not seen whole — sloth cannot judge it, and
says so rather than guessing.

Every sentinel body is small enough that this is rarely the limiting
factor: Apple's is ~90 bytes, Microsoft's 22, Firefox's 8, Google's is a
204 with none at all. All fit comfortably in one segment.

## The evasion, stated plainly

**A rogue that chunks its response evades the body check.** `chunked`
responses are never `body_complete`, because the body is interleaved
with chunk-size lines and sloth does not decode them — and calling the
raw bytes "the body" would produce a mismatch on a response that is
actually correct.

It does not evade the DNS or TLS checks. A portal still has to answer
the DNS query for `captive.apple.com`, and if it answers with a local
address `CP_KIND_DNS_SPOOF` fires regardless of what it does over HTTP.
That independence is the reason for three signals.

## What it looks like when it is nothing

- **A real captive portal you are deliberately using.** A hotel or
  airport network *is* a captive portal; intercepting the check is what
  it is for. The alert is correct and uninteresting, which is why it is
  LOW unless something else is known (Grading, above), and why the
  detail says so in as many words.
- **A DNS filter or a Pi-hole-style resolver** answering for the
  sentinel host from local space. `DNS_SPOOF` fires. It is doing the
  same thing a portal does, by design.
- **A CDN range sloth's list has not caught up with**, which is what
  `DNS_UNEXPECTED` exists to be gentle about.

## Not implemented from the issue

Two parts of #69 are deliberately absent, and both are honest gaps
rather than oversights:

- **DHCP option 114 (RFC 8910) cross-check.** `dhcp_snoop.c` does not
  parse option 114, so the "portal on a different origin than the
  advertised one" signal has nothing to compare against. It wants the
  option parsed first.
- **The credential-POST hint.** #71 added response-side parsing; the
  *request* body is still not captured, so form fields cannot be
  inspected. That is a separate parser and a separate MISSION §2
  conversation, since a request body is where passwords actually live.

There is also **no dedicated `[C]` view**. Portal events are episodic
and rare; a view for them would be empty almost always. The `[h]`
decoration puts the verdict where the traffic already is, and `[v]`
carries the alert. Say if you want the view and it is the standard
eleven-step addition.

## Export

- **JSONL**: `captive_portal_event` with `host`, `src`, `kind`,
  `kind_label`, `evidence` and, since #169, `server` / `server_port`
  (the responder; `""` / `0` for a DNS-sourced event) and `kit`
  (`wifiphisher`, `pineapple-evilportal`, `pineapple-portalauth`,
  `airgeddon`, `fluxion`, or `""`).
- **`[v]` Alerts**: one `ALERT_TYPE_CAPTIVE_PORTAL` per (host, kind),
  plus one per (kit, server). Both carry the responder as `match_ip` /
  `match_port` since #169, so per-alert pcap export works.

## References

- [RFC 8908](https://datatracker.ietf.org/doc/html/rfc8908) — Captive
  Portal API. [RFC 8910](https://datatracker.ietf.org/doc/html/rfc8910)
  — the DHCP/RA option 114 that would supply the cross-check above.
- [MITRE ATT&CK T1557](https://attack.mitre.org/techniques/T1557/) —
  Adversary-in-the-Middle, the alert type's tag: a wrong probe answer is
  AiTM whether or not an evil twin is the middle.
- [MITRE ATT&CK T1557.004](https://attack.mitre.org/techniques/T1557/004/)
  — Evil Twin, and its detection strategy
  [DET0379](https://attack.mitre.org/detectionstrategies/DET0379/), for
  the kit findings and the own-network grading.
- [MITRE ATT&CK T1056.003](https://attack.mitre.org/techniques/T1056/003/)
  — Web Portal Capture, for the credential-harvest stage.
- [CISA — Securing Wireless Networks](https://www.cisa.gov/news-events/news/securing-wireless-networks)
  — rogue-AP guidance calling out portal capture.

## See also

- [`docs/views/http.md`](../views/http.md) — the `[h]` view.
- [`docs/wiki/btm-abuse.md`](btm-abuse.md) — one way a client gets moved
  onto the AP that then runs the portal.
