# Captive-portal interception

**Issue:** [#69](https://github.com/SpaceTrucker2196/sloth/issues/69) ·
**Alert:** `ALERT_TYPE_CAPTIVE_PORTAL` · **Surfaces in:** `[h]` HTTP,
`[v]` Alerts

Every modern OS probes a fixed URL to decide whether it is behind a
captive portal, and expects a published, byte-exact answer:

| OS | URL | Expected |
|---|---|---|
| Apple | `captive.apple.com/hotspot-detect.html` | `<HTML>…<BODY>Success</BODY></HTML>` |
| Microsoft | `www.msftconnecttest.com/connecttest.txt` | `Microsoft Connect Test` |
| Firefox | `detectportal.firefox.com/success.txt` | `success\n` |
| Android / Chrome | `connectivitycheck.gstatic.com/generate_204` | HTTP 204, no body |

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

`DNS_UNEXPECTED` is deliberately the soft one — WARN, not CRIT. These
are large operators whose addressing changes, and being wrong about a
CDN range must not produce a CRIT. The other three are unambiguous: a
connectivity-check host does not resolve to `192.168.1.1` by accident.

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
  it is for. The alert is correct and uninteresting — which is why the
  BSSID matters, and why the detail says whether the AP is also a known
  evil twin.
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
  `kind_label` and `evidence`.
- **`[v]` Alerts**: one `ALERT_TYPE_CAPTIVE_PORTAL` per (host, kind).

## References

- [RFC 8908](https://datatracker.ietf.org/doc/html/rfc8908) — Captive
  Portal API. [RFC 8910](https://datatracker.ietf.org/doc/html/rfc8910)
  — the DHCP/RA option 114 that would supply the cross-check above.
- [MITRE ATT&CK T1557](https://attack.mitre.org/techniques/T1557/) —
  Adversary-in-the-Middle.
- [MITRE ATT&CK T1056.003](https://attack.mitre.org/techniques/T1056/003/)
  — Web Portal Capture, for the credential-harvest stage.
- [CISA — Securing Wireless Networks](https://www.cisa.gov/news-events/news/securing-wireless-networks)
  — rogue-AP guidance calling out portal capture.

## See also

- [`docs/views/http.md`](../views/http.md) — the `[h]` view.
- [`docs/wiki/btm-abuse.md`](btm-abuse.md) — one way a client gets moved
  onto the AP that then runs the portal.
