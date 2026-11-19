# camera-vendor: camera-maker identity tables

Four files, moved from sloth's
[`src/camera_vendor.c`](https://github.com/SpaceTrucker2196/sloth/blob/fa366881644ad32160f5ca8e586af0fdedac00c4/src/camera_vendor.c)
at `fa366881` and held byte for byte to that source by sloth-comint's
parity check. The sources the rows rest on are in sloth's
[`research/papers/camera-vendor-identity.md`](https://github.com/SpaceTrucker2196/sloth/blob/fa366881644ad32160f5ca8e586af0fdedac00c4/research/papers/camera-vendor-identity.md)
and
[`research/papers/camera-setup-softap.md`](https://github.com/SpaceTrucker2196/sloth/blob/fa366881644ad32160f5ca8e586af0fdedac00c4/research/papers/camera-setup-softap.md),
which stay in sloth with the rules that cite them (ADR 0002).

## camera_vendors.csv (`g_cam_oui`, 455 rows)

Columns `oui`, `vendor` (brand), `org` (the registry's Organization
Name verbatim), `mixed` (0 or 1). From the source: "Every row is one
MA-L (24-bit) assignment from the IEEE Registration Authority public
listing, oui.csv, as distributed by Debian's ieee-data package
(.lastupdate 2024-07-22). The second string is the registry's
\"Organization Name\" column verbatim, so a row is its own citation:
look the assignment up at
https://regauth.standards.ieee.org/standards-ra-web/pub/view.html#registries
and the assignee must read exactly as written here."

"A camera-vendor row (mixed 0) is an assignee whose own published
material describes it as a camera maker. ... A mixed-vendor row (mixed
1, sloth #155) is Ubiquiti, TP-Link or Wyze: they sell cameras, but
most of what their blocks put on the wire is an AP, a router, a plug or
a bulb ... so such a match names the vendor and is a +1 prior in
camera_join.c's score, never a class and never CAM_SETUP_OUI on its
own." The mixed-vendor rows are "every assignment the same registry
snapshot lists under these three companies' Organization Names, all of
them: a partial list would make the prior depend on which block a
device happened to be built in. Generated from oui.csv, sorted per
assignee." (owner ruling 2026-10-21). Row order is the source's.

## camera_server_brands.csv (`g_cam_server_brands`, 9 rows)

Column `brand`. "The same vendor set as the OUI table, by brand - a
firmware that names its maker in SERVER names the brand, not the
registry's legal name. Not a list of observed SERVER strings: nobody
publishes those, and a row for one would be a guess. What is matched is
the vendor naming itself in the field UDA 1.0 §1.1.2 reserves for the
product name."

## camera_services.csv (`g_cam_svcs`, 3 rows)

Columns `service` (DNS-SD label, leading `_`), `label`,
`camera_specific` (0 or 1). "Each row is a Service Name in the IANA
Service Name and Transport Protocol Port Number Registry (RFC 6335)":
`axis-video` ("Axis Video Cameras"), `cctv` ("IP and
Closed-Circuit Television for Securitiy applications", registry
spelling) and `rtsp` (port 554, "Real Time Streaming Protocol
(RTSP)"; a protocol, not a device class, hence camera_specific 0).
"Vendor-specific names the issue proposed (_hikvision, _dahua,
_reolink, _wyze, _arlo, _nest-cam, _ubnt) are not registered and no
vendor document naming them was found, so they are not here."
Registry: <https://www.iana.org/assignments/service-names-port-numbers/>.

## camera_setup_ssids.csv (`g_camera_setup_ssid_pats`, 4 rows)

Columns `prefix`, `label`, `brand`. "Every row cites the vendor's
own onboarding documentation - see research/papers/camera-setup-softap.md":

- `HAP_` - "Hikvision Access Point": HAP_ + the verification code
  from the device label.
- `DAP-` - "Dahua Access Point", DAP-<serial fragment>; Amcrest is a
  Dahua OEM and uses the same prefix (DAP-AMC...).
- `EZVIZ_` - EZVIZ (Hikvision's consumer brand) AP mode,
  EZVIZ_<9-digit serial>.
- `Tapo_Cam_` - TP-Link Tapo camera setup SoftAP,
  Tapo_Cam_<last 4 of MAC>; the trailing underscore keeps it off Tapo
  plugs and bulbs.

**Licence.** OUI rows are the IEEE's public listing and service names
IANA's public registry; selections, labels and brands were written in
sloth (SLOTH SOURCE-AVAILABLE LICENSE 1.0) by the owner of both
repositories. sloth carries them under its own licence; sloth-comint
publishes them under PolyForm Noncommercial 1.0.0.