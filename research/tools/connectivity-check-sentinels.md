---
source_url: https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/internet-explorer-edge-open-connect-corporate-public-network
retrieved: 2026-10-26
topics: [captive-portal, connectivity-check, ncsi, sentinel, android, windows]
alert_kinds: [ALERT_TYPE_CAPTIVE_PORTAL]
citation: Microsoft KB 4494446, NCSI active probes; AOSP NetworkMonitor.java (android-5.0.0_r1), DEFAULT_SERVER and the 204 test
---
# Connectivity-check sentinels — the two #169 added

`CAPTIVE_PORTAL`'s body check compares the answer to an OS connectivity
probe with the answer its vendor publishes (`src/captive_portal.c`
`SENTINELS[]`). #69 shipped six hosts. #169 adds two, each from the
vendor's own text.

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
