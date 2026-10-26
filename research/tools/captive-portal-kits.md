---
source_url: https://github.com/wifiphisher/wifiphisher/tree/4ae336518bf29eed13d3b09f2ee6a16e7973c997
retrieved: 2026-10-26
topics: [captive-portal, evil-twin, phishing, wifiphisher, pineapple, airgeddon, fluxion, fingerprint]
alert_kinds: [ALERT_TYPE_CAPTIVE_PORTAL]
citation: Public source of wifiphisher (4ae3365), WiFi Pineapple Evil Portal (EvilPortalNano 0864a2d) and PortalAuth (dedc272), airgeddon (700ad7d) and fluxion (f064d24); Tornado web.py (v6.4.0, v4.5.3)
---
# Evil-twin kit portal pages — what each kit puts on the wire first

What the `portalkit:` findings of `ALERT_TYPE_CAPTIVE_PORTAL` (#169)
match on. Every feature below was read from the kit's own repository at
the commit named, retrieved 2026-10-26; none was inferred from a capture
or from a write-up. A kit changed after that commit may no longer match,
and the matcher says nothing about a kit not listed here.

## Why kit pages, and why two features

MITRE ATT&CK T1557.004 (Evil Twin) names the step these pages are: a
user who joins the impostor "may be directed to a fake login page or
captive portal webpage to capture the victim's credentials" (see `research/mitre/T1557-004.md`). The four kits
below automate that step and ship default pages. An operator who sees one
of those pages served has learnt something no RF signal can say: not
"there is a portal" but "this portal is wifiphisher's".

Every fingerprint needs **two features together**, because each feature
alone occurs elsewhere. A Tornado server banner is any Tornado app. A
`<title>Plugin Manager</title>` exists on ordinary sites. A lighttpd 307
is a configuration choice. Together they are the kit.

## What is matched, and what is not

One HTTP response segment as it arrived: the status line, the header
block, and whatever part of the body shares that segment. sloth does not
reassemble TCP (#71), so a feature that lands past the first segment is
not seen; this is stated per kit below. Only the server-to-client
response is read. Nothing a client sent — no form field, no POST body —
is inspected, and nothing from the page is stored: a match keeps the
row's label ("wifiphisher firmware-upgrade") and the responder's address.

## wifiphisher

Repository `https://github.com/wifiphisher/wifiphisher`, commit
`4ae336518bf29eed13d3b09f2ee6a16e7973c997` (2026-05-22).

- `wifiphisher/common/phishinghttp.py:80` `CaptivePortalHandler`, routed
  at line 198 as `(r"/.*", CaptivePortalHandler)`: every GET on every
  path is answered with the active scenario's `index.html`.
  `wifiphisher/common/firewall.py:44` DNATs port 80 to it.
- The server is Tornado (`setup.py:153`, `tornado>=5.0.0`). Tornado's
  `RequestHandler.clear()` sets `"Server": "TornadoServer/%s" %
  tornado.version` — `tornado/web.py:328` at tag v6.4.0 and `:290` at
  v4.5.3 (`https://github.com/tornadoweb/tornado`).
- Per scenario, under `wifiphisher/data/phishing-pages/`:
  - `firmware-upgrade/html/index.html:4` —
    `<title>Router Configuration Page</title>`
  - `oauth-login/html/index.html:6` — the credit comment
    `codepen.io/andytran/pen/PwoQgO`
  - `plugin_update/html/index.html:6` — `<title>Plugin Manager</title>`
  - `wifi_connect/html/index.html:11` —
    `(C) viazenetti GmbH (Christian Ludwig)` (its title is empty)

Each row is `Server: TornadoServer/` **and** that scenario's line. All
four lines sit in the first few hundred bytes of the page.

## WiFi Pineapple — Evil Portal and PortalAuth

Evil Portal is the Pineapple module that serves the portal; PortalAuth
writes portals for it.

Evil Portal, `https://github.com/frozenjava/EvilPortalNano`, commit
`0864a2dae4e09bbd0916e0626d1e762bcd59d72e` (2019-03-20):
`EvilPortal/includes/skeleton/index.php` line 8
`<title>Evil Portal</title>` and line 18
`This is the default Evil Portal page.` — the page a portal created from
the skeleton serves until it is edited. `includes/evilportal.sh:13` DNATs
port 80 from `172.16.42.0/24` to `172.16.42.1:80`.

PortalAuth, `https://github.com/sud0nick/PortalAuth`, commit
`dedc272b3b0ff5dbb842bdd4eaa649e75c810198` (2020-07-18), marked
unmaintained in its README: `includes/scripts/PortalCloner.py:282-291`
clones a real portal and appends an injection set's `injectJS.txt` and
`injectCSS.txt` to its `<head>`. Each non-blank set
(`includes/scripts/injects/{Harvester,Free_WiFi_Week,Payloader}`) carries
`#pa_overlay-back {` in its CSS (lines 36, 24, 37) and
`/captiveportal/index.php` — Evil Portal's authorisation endpoint — in its
JS. The row is both.

**Limit:** the injection follows the *cloned* page's own head content. A
cloned portal with a large head pushes it past the first segment and is
missed. The `Blank` set injects nothing and cannot be fingerprinted.

## airgeddon

`https://github.com/v1s1t0r1sh3r3/airgeddon`, commit
`700ad7d63df04e565bcd14d2aec6f935fcec5185` (2026-09-23).
`airgeddon.sh` `set_captive_portal_page()` (from line 13545) generates
`index.htm` with `cssfile="portal.css"` (line 335) linked as
`<link rel="stylesheet" type="text/css" href="portal.css"/>`, and the
form at line 13641,
`<form method="post" id="loginform" name="loginform" action="check.htm">`.
The row is both. Both precede the page's text and fall in roughly the
first 500 body bytes. The title (`et_misc_texts[...,15]`, "Internet
Portal" in English) is localised and so is not used. lighttpd serves it
(`set_webserver_config()`, from line 13379); its banner is not used,
since the CGI-generated page is what is specific.

## fluxion

`https://github.com/FluxionNetwork/fluxion`, commit
`f064d246a020a50fa4ded8cd440427e30c7a3818` (2026-09-19),
`attacks/Captive Portal/attack.sh`:

- **Default ("disconnected") connectivity** — the auto-mode choice
  (line 750): lines 1096-1104 configure lighttpd with
  `url.redirect-code = 307` and every host but `captive.gateway.lan`
  redirected to `http://captive.gateway.lan/`. The row is status 307
  **and** `Location: http://captive.gateway.lan/`. This is the only kit
  row that is headers alone, and it is the one most likely to be seen,
  because the redirect is what answers every OS's connectivity probe.
- **"Emulated" connectivity** — lines 1082-1093 serve
  `lib/connectivity responses/Apple/hotspot-detect.html` for
  `captive.apple.com`. That file is not Apple's page: it opens with
  `window["_gaUserPrefs"] = { ioo : function() { return true; } }`, a
  script a browser add-on injected into whatever copy it was saved from.
  The row is that script **and** `<title>Success</title>`. The same
  response is also a `portal:` HIJACK finding, because it is not the
  sentinel's bytes.
- **The generic login page** — line 1471
  `<title>Wireless Protected Access: Login</title>` and line 1474
  `css/jquery.mobile-1.4.5.min.css`. The row is both. The `sites/*.portal`
  alternatives are vendor look-alikes and are not fingerprinted.

## What this cannot say

- A kit's pages are trivially edited. A match is strong evidence of the
  kit; no match is no evidence of absence.
- A portal fronted by TLS shows none of this. The DNS and TLS signals of
  `CAPTIVE_PORTAL` (`docs/wiki/captive-portal.md`) are what remain there.
- The benign case is real: someone running the kit on purpose — a lab, a
  training, an authorised assessment. The finding is CRIT because the
  operator should know it is happening in range either way.

## Related

- `research/mitre/T1557-004.md` — the technique and DET0379.
- `research/tools/connectivity-check-sentinels.md` — the probes these
  portals answer.
- `docs/wiki/captive-portal.md` — the detector.
