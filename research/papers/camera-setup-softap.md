---
source_url: https://www.hikvision.com/content/dam/hikvision/en/support/how-to/how-to-document/network-cameras/How-to-Set-Wi-Fi-Connection-of-Wi-Fi-Camera-via-Mobile-Phone-Web-Broswer.pdf
retrieved: 2026-10-13
topics: [camera, cctv, onboarding, provisioning, softap, ssid, exposure, iot]
alert_kinds: [ALERT_TYPE_CAM_SETUP_SSID]
citation: Vendor onboarding documentation — Hikvision ("HAP_"), Dahua/Amcrest ("DAP-"), EZVIZ ("EZVIZ_"), TP-Link Tapo ("Tapo_Cam_"); with NIST SP 1800-36 (NCCoE) for the onboarding-window exposure itself
---
# Camera setup-mode SoftAP SSIDs — vendor onboarding documentation

What `ALERT_TYPE_CAM_SETUP_SSID` (#106 slice 2) detects from. The
exposure of the onboarding window itself is already on file in
`research/papers/nist-sp1800-36-onboarding.md`, which
`ALERT_TYPE_OPEN_SETUP_AP` cites; this document supplies the part that
rule does not have — **which SSID names identify the device as a
camera**, sourced per vendor.

## Why a camera is a separate finding from a generic setup AP

`OPEN_SETUP_AP` (#80) answers "an open SoftAP exists". That is a true
statement about a printer, a robot vacuum and a camera alike. #106's
own framing is that the operator needs the other sentence — *a camera
is still in setup mode* — because the follow-on facts differ: a camera
that was never joined to a WLAN was also never taken through the
password change its first-boot wizard performs, and the SoftAP is the
surface that reaches that unchanged account. The device class changes
what the operator does next, so it belongs in the alert.

## Per-vendor SSID shapes

Each row of `g_camera_setup_ssid_pats[]` in `src/alerts.c` appears here
with the document it came from. A prefix that could not be sourced to a
vendor document was not shipped — see the last section.

### Hikvision — `HAP_`

Hikvision Wi-Fi cameras broadcast their own access point for initial
configuration. The SSID is `HAP_` ("Hikvision Access Point") followed
by the verification code printed on the device label; joining it
requires a key, and that key is **the last 8 characters of the serial
number**, printed on the same label.

This is the case that forced the rule's central design decision. The
AP is *encrypted*, so a rule gated on OPEN — as `OPEN_SETUP_AP` is —
can never fire on it, and #106's headline example would be
undetectable. A pre-shared key printed on the outside of the chassis
the camera is mounted in is not a secret from anyone who can see the
camera, which is the population that can also reach its RF. The rule
therefore reports provisioning *state* and records the encryption in
the detail rather than gating on it.

### Dahua, and Amcrest as its OEM — `DAP-`

Dahua Wi-Fi cameras expose a SoftAP named `DAP-` ("Dahua Access
Point") plus a serial fragment. Amcrest sells Dahua-derived hardware
and inherits the mechanism and the prefix, so the observable SSID is
of the form `DAP-AMC…` on Amcrest units. One table row covers both
brands, which is why its label names the OEM rather than the reseller:
the bytes on the air say `DAP-`, and inferring "Amcrest specifically"
from them would be a claim the beacon does not support.

Amcrest's own support material describes the flow as "SoftAP" and
instructs the installer to join the camera's hotspot from the phone's
Wi-Fi settings before the app can continue.

### EZVIZ — `EZVIZ_`

EZVIZ is Hikvision's consumer brand. Its AP-mode onboarding — entered
by holding reset until the LED flashes blue — broadcasts
`EZVIZ_<9-digit serial>`, keyed on the verification code from the
device label. Same shape as `HAP_`, same reason the encryption is not
a gate.

### TP-Link Tapo — `Tapo_Cam_`

TP-Link's Tapo camera troubleshooting documentation instructs the user
to join the camera's own network manually when app discovery fails,
and names it: the SSID is `Tapo_Cam_XXXX`, where `XXXX` is the last
four digits of the device's MAC address.

The trailing underscore is part of the shipped prefix on purpose.
`Tapo_` alone also matches Tapo smart plugs and bulbs, which are not
cameras; the alert's whole value is the device class, so a prefix that
blurs it would be worse than no row.

## Considered and not shipped

Named explicitly because the absence is a deliberate decision, not an
oversight, and because the next person to touch the table will
otherwise re-propose them:

- **`Reolink-`** — Reolink's published setup paths are Ethernet-first
  configuration and app pairing. Their support documentation on
  Wi-Fi setup does not describe the camera broadcasting its own
  `Reolink-` AP, so the prefix is unsourced.
- **`WyzeCam`** — Wyze's documented default onboarding is QR-code
  scanning, not a SoftAP. An "Access Point" feature exists for
  hard-to-reach devices such as floodlights, but its SSID shape is
  not stated in the documentation reviewed.
- **`Arlo_`, `Verkada-`, `UVC-`, `Lorex_`, `Swann-`, `Blink-`** —
  no vendor document found describing a setup SSID of that shape.
  Verkada and Ubiquiti's UVC line are PoE devices, for which a
  provisioning SoftAP would not be the onboarding path at all.
- **Substring matches on `CCTV` or `surveil`** — these are
  self-labelling, not setup-mode signals. An AP a homeowner named
  "CCTV" is a configured network, and firing on it would teach the
  operator to ignore the type, which is the failure #80's table
  comment is written against.

Any of these becomes shippable the moment somebody can point at the
document. That is the whole bar.

## What the rule does not claim

- **Not an attack.** Nobody has to be present for this to fire. The
  camera is advertising its own provisioning state to everyone in RF
  range, unprompted; `alert_technique()` returns `""` for the same
  reason it does for `OPEN_SETUP_AP` and `CAM_WS_DISCOVERY`.
- **Not a credential check.** The rule never tries the label-derived
  key, and sloth has no path that could. It reports that a key of that
  kind is what stands between the segment and the camera's
  configuration.
- **Not a verdict on whether the camera should be there.** A unit
  genuinely mid-installation produces this alert, correctly — that
  window is exactly when the exposure exists. Whose camera it is
  remains the operator's call.
