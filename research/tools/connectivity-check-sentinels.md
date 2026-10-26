---
source_url: https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/internet-explorer-edge-open-connect-corporate-public-network
retrieved: 2026-10-26
topics: [captive-portal, connectivity-check, ncsi, sentinel, android, windows]
alert_kinds: [ALERT_TYPE_CAPTIVE_PORTAL]
citation: Microsoft KB 4494446, NCSI active probes; Microsoft "Overview of NCSI" and the Windows 11 connection-endpoint list (ipv6.msftconnecttest.com); AOSP NetworkMonitor.java (android-5.0.0_r1), DEFAULT_SERVER and the 204 test; Firefox modules/libpref/init/all.js captivedetect.canonicalURL/canonicalContent (esr140 02f6079, release 8678d2e); the Apple, NCSI-v6 and Firefox bodies as served on 2026-10-26
---
# Connectivity-check sentinels — the rows #169 added

`CAPTIVE_PORTAL`'s body check compares the answer to an OS connectivity
probe with the answer its vendor publishes (`src/captive_portal.c`
`SENTINELS[]`). #69 shipped six hosts. #169 adds the rows below, each
from the vendor's own text, and corrects #69's Apple row.

The comparison is exact, length included, so every body here is given
as bytes, measured with `curl -sD- <url> | xxd` on 2026-10-26 from a
residential connection with no portal. A vendor's prose ("contains
Microsoft NCSI") names the string; the fetch fixes the bytes around it.

## Apple — the trailing newline #69 dropped

`http://captive.apple.com/hotspot-detect.html` answered `200 OK`,
`Content-Length: 69`, and a body ending

    ...  3c2f 424f 4459 3e3c 2f48 544d 4c3e 0a   </BODY></HTML>.

i.e. `<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>`
followed by one LF: 69 bytes. #69's row held the 68 bytes without the
LF, and because `cp_check_response()` compares lengths exactly and
`http_log` marks a 69-of-69 body complete, every genuine Apple answer
was reported as a hijack. The row now carries the LF.

## Microsoft NCSI over IPv6

Microsoft, "Overview of Network Connectivity Status Indicator"
(`https://learn.microsoft.com/en-us/windows-server/networking/ncsi/ncsi-overview`,
read 2026-10-26): "NCSI sends separate IPv4 and IPv6 active probes in
parallel." The v6 probe has its own host: Microsoft's "Manage connection
endpoints for Windows 11 Enterprise"
(`https://learn.microsoft.com/en-us/windows/privacy/manage-windows-11-endpoints`,
read 2026-10-26) lists, under "Network Connection Status Indicator
(NCSI)", `www.msftconnecttest.com*` and `ipv6.msftconnecttest.com` over
HTTP.

- `http://ipv6.msftconnecttest.com/connecttest.txt`: `200 OK`,
  `Content-Length: 22`, body `Microsoft Connect Test` (no LF), the same
  file as the v4 host.
- `http://ipv6.msftncsi.com/ncsi.txt`: `200 OK`, `Content-Length: 14`,
  body `Microsoft NCSI` (no LF), the legacy file. No Microsoft page read
  for this note names this host; it is the pre-1607 counterpart of the
  v6 probe, and the row rests on the KB's "contains Microsoft NCSI"
  together with the live answer. A wrong answer here grades LOW unless
  the context escalates it, like every other row.

Not added: `dns.msftncsi.com`, NCSI's DNS probe. Its expected answer is
a unique-local IPv6 address, so the private-space DNS check would call
the correct answer a spoof.

## Firefox — the URL the captive-portal service fetches

Firefox has two probes. The connectivity service fetches
`network.connectivity-service.IPv4.url` / `IPv6.url`; the captive-portal
detector fetches `captivedetect.canonicalURL` and compares the body with
`captivedetect.canonicalContent`. Both are prefs in
`modules/libpref/init/all.js`
(`https://github.com/mozilla-firefox/firefox`, read 2026-10-26):

- branch `esr140` at `02f6079d3858a90d5533e84edd6fdb7701f58040` (and
  `esr128`, `esr115`):
  `pref("captivedetect.canonicalURL", "http://detectportal.firefox.com/canonical.html");`
  `pref("captivedetect.canonicalContent", "<meta http-equiv=\"refresh\" content=\"0;url=https://support.mozilla.org/kb/captive-portal\"/>");`
  and the connectivity URLs `http://detectportal.firefox.com/success.txt?ipv4` / `?ipv6`.
- branch `release` at `8678d2e4bd6e1038edde0a20f5db0428f5bd9b56`:
  `pref("captivedetect.canonicalURL", "http://firefox-portal-detection.com/generate_204");`
  `pref("captivedetect.canonicalContent", "");` with the comment "The
  canonical endpoint answers with an empty 204 when there is no captive
  portal", and the connectivity URLs moved to
  `http://firefox-portal-detection.com/success.txt?ipv4` / `?ipv6`.

Live answers: `detectportal.firefox.com/canonical.html` gave `200 OK`,
`Content-Length: 90`, exactly the canonicalContent string with no LF;
`firefox-portal-detection.com/generate_204` gave `204` with no body;
`firefox-portal-detection.com/success.txt?ipv4` gave `200 OK`,
`Content-Length: 8`, `success\n`. #69 had only `detectportal`'s
`success.txt`, so the detector Firefox actually uses for the portal
decision was not checked on either generation. All three rows are added.

## Microsoft NCSI, Windows 8.1 and earlier

Microsoft KB 4494446 ("An Internet Explorer or Edge window opens when
your computer connects to a corporate network or a public network",
updated 2026-02-12, read 2026-10-26), section "NCSI active probes":

- Windows 10 and later: "NCSI sends a plain HTTP GET request to
  `http://www.msftconnecttest.com/connecttest.txt` ... it makes sure that
  the file contains Microsoft Connect Test." (Already in #69's table.)
- Windows 8.1 and earlier: "NCSI sends a plain HTTP GET request to
  `http://www.msftncsi.com/ncsi.txt` ... it makes sure that the file
  contains Microsoft NCSI."

So the row is `www.msftncsi.com` `/ncsi.txt`, status 200, body
`Microsoft NCSI`. Microsoft's word is "contains"; the table compares the
whole body exactly, as #69 does for connecttest, because the published
file is exactly that string and a portal page that merely contains it
would be an odd thing to excuse. The KB also states the design premise
of the whole detector: when the probe fails "the default browser opens,
and shows a web page such as a sign-in page for the network" — the
legitimate captive-portal behaviour #169's LOW grade exists for.

## Android, `clients3.google.com`

AOSP `frameworks/base`, tag `android-5.0.0_r1`,
`services/core/java/com/android/server/connectivity/NetworkMonitor.java`
(`https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-5.0.0_r1/services/core/java/com/android/server/connectivity/NetworkMonitor.java`,
read 2026-10-26):

- `private static final String DEFAULT_SERVER = "clients3.google.com";`
- the probe is `new URL("http", mServer, "/generate_204")`;
- `if (httpResponseCode == 204)` the network is validated.

So the row is `clients3.google.com` `/generate_204`, status 204, no body.
Later Android releases moved the default to
`connectivitycheck.gstatic.com` (already in #69's table); older devices
and images still probe `clients3`. fluxion's lighttpd configuration
answers for `clients[0-9]*.google.com` alongside the gstatic hosts
(`research/tools/captive-portal-kits.md`), which is independent
confirmation that the host is still worth a kit's while.

## Related

- `docs/wiki/captive-portal.md` — the full sentinel table.
- `research/tools/captive-portal-kits.md`.
