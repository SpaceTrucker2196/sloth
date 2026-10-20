---
source_url: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
retrieved: 2026-10-20
topics: [camera, cctv, mdns, dns-sd, ssdp, upnp, oui, ieee-registry, exposure, iot]
alert_kinds: [ALERT_TYPE_CAM_MDNS_SERVICE, ALERT_TYPE_CAM_SSDP_DEVICE, ALERT_TYPE_CAM_SETUP_OUI]
citation: IANA Service Name and Transport Protocol Port Number Registry (RFC 6335); UPnP Forum DigitalSecurityCamera:1 Device Template v1.01 (2005-03-24), Basic:1.0 Device Definition v1.0 (2002-12-12), UPnP Device Architecture 1.0 §1.1; IEEE Registration Authority MA-L public listing; IEEE Std 802-2014 §8.2
---
# Camera identity from what the device announces — IANA, UPnP Forum, IEEE RA

What `ALERT_TYPE_CAM_MDNS_SERVICE`, `ALERT_TYPE_CAM_SSDP_DEVICE` and
`ALERT_TYPE_CAM_SETUP_OUI` (#106 slice A) detect from. All three read
tables sloth already keeps — mDNS service rows, SSDP NOTIFY rows,
beaconing BSSIDs — against an embedded table in `src/camera_vendor.c`
(#145 ruling 8: embedded, no runtime CSV). Grouped in one document
because the vendor set is shared: the OUI table and the SERVER-token
list name the same vendors, sourced once, here.

A match **corroborates, it never confirms** (#145 ruling 2). Each source
below says what a field means; none of them says what the box on the
wall is. The alert details say that in so many words.

## 1. DNS-SD service types — IANA Service Name registry

DNS-SD (RFC 6763) names a service by an IANA-registered Service Name
(RFC 6335). The registry was retrieved on 2026-10-20 as
`service-names-port-numbers.csv`. Rows shipped, Description quoted:

| Service name | Registry description | Shipped as |
|---|---|---|
| `axis-video` | "Axis Video Cameras" | camera service |
| `cctv` | "IP and Closed-Circuit Television for Securitiy applications" (registry spelling) | camera service |
| `rtsp` (554) | "Real Time Streaming Protocol (RTSP)" | streaming service, *not* a device class |

`rtsp` is in the table because #106 Case D is an RTSP advertisement and
cameras do make it, but the registry entry describes a protocol, so the
row carries `camera_specific = 0` and the alert detail says the
advertisement corroborates a camera and does not establish one.

**Considered and not shipped.** `_onvif._tcp`, `_hikvision._tcp`,
`_dahua._tcp`, `_amcrest._tcp`, `_wyze._tcp`, `_reolink._tcp`,
`_arlo._tcp`, `_nest-cam._tcp` and `_ubnt._tcp`+`uvc` were proposed by
the issue. None is in the IANA registry, and no vendor document naming
one was found, so each would be a guess. ONVIF discovery is
WS-Discovery, already read by `CAM_WS_DISCOVERY`. `axis-nvr` ("Axis
Network Video Recorders") is registered but names a recorder; left out
to keep the rule to cameras. Apple HomeKit's `_hap._tcp` carries the
accessory category in TXT (`ci`), which `mdns_snoop.c` does not store.

## 2. SSDP device types — UPnP Forum DCPs and UDA 1.0

- **DigitalSecurityCamera:1 Device Template Version 1.01**, Standardized
  DCP, 2005-03-24 (authors: Axis Communications AB). §2.1: "The following
  device type identifies a device that is compliant with this template:
  `urn:schemas-upnp-org:device:DigitalSecurityCamera:1`". Its scope is
  "live snapshot still images" and "live motion images (video)". A NOTIFY
  with this NT is the device naming itself a camera in the field that
  exists for that. Retrieved from
  `https://upnp.org/specs/ha/UPnP-ha-DigitalSecurityCamera-v1-Device.pdf`.
- **Basic:1.0 Device Definition Version 1.0**, 2002-12-12. §1: Basic:1.0
  "provides a mechanism for products that wish to use UPnP, but for which
  there is not yet an appropriate standard base device type". So Basic:1
  on its own says nothing about a device class, which is why the rule
  takes it only with a camera-vendor SERVER token (#145 ruling).
  Retrieved from `https://upnp.org/specs/basic/UPnP-basic-Basic-v1-Device.pdf`.
- **UPnP Device Architecture 1.0** §1.1.2 (NOTIFY ssdp:alive): SERVER is
  "Required. Concatenation of OS name, OS version, UPnP/1.0, product
  name, and product version. Specified by UPnP vendor." That is the
  basis for reading the product-name token as the device's own claim
  about its maker. §1.1.3 (ssdp:byebye) carries no SERVER, which is why
  `ssdp_snoop.c` keeps the last one an alive gave. §1.1.4 gives USN as
  `uuid:device-UUID::type`; the rule keys on the UUID so one camera's
  several NOTIFYs are one finding. Retrieved from
  `https://upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.0.pdf`.

An M-SEARCH's ST is what the *searcher* wants, so an M-SEARCH for
cameras is not a camera and is skipped. M-SEARCH *responses*
(`HTTP/1.1 200 OK`) are unicast to the asker and are not parsed by
`ssdp_snoop.c` today; parsing them is a follow-up, not this slice.

## 3. Transmitter OUI — IEEE RA MA-L listing and IEEE 802-2014 §8.2

Every OUI row in `g_cam_oui[]` is one MA-L (24-bit) assignment from the
IEEE Registration Authority public listing, `oui.csv`, as distributed by
Debian's `ieee-data` package (`.lastupdate` 2024-07-22). Each row
carries the registry's Organization Name verbatim, and
`tests/test_camera_vendor.c` holds the table to that file wherever the
host has it. Assignees shipped:
"Hangzhou Hikvision Digital Technology Co.,Ltd.", "Hangzhou Ezviz
Software Co.,Ltd.", "Zhejiang Dahua Technology Co., Ltd." and
"ZHEJIANG DAHUA TECHNOLOGYCO.,LTD" (two registry spellings of one
company), "Amcrest Technologies", "Axis Communications AB", "Reolink
Innovation Limited", "Mobotix AG", "Lorex Technology Inc.", "Arlo
Technology".

**Why these vendors are camera vendors.** The registry names an
assignee, not a product line, so the second leg is the vendor's own
description, retrieved 2026-10-20: Hikvision, Dahua/Amcrest and EZVIZ
from their camera onboarding documentation already on file in
`research/papers/camera-setup-softap.md`; Axis ("Leader in network
cameras", axis.com title; also the author of the DigitalSecurityCamera
DCP and registrant of `axis-video`); Reolink ("Security Cameras and
Systems for Home & Business"); Mobotix ("High-Resolution German IP
Security Cameras"); Lorex ("Smart Cameras, Video Doorbells, and Security
Systems"); Arlo ("Smart Home Security: Cameras, Video Doorbells &
Floodlights"). This is a vendor test: a Hikvision block is on an NVR as
readily as on a camera, which is why the detail says "camera vendor;
device class not observed".

**U/L bit.** IEEE Std 802-2014 §8.2: bit 1 of the first octet is the
universal/local bit (1 = locally administered), bit 0 the
individual/group bit. #106 records a UniFi setup AP beaconing
`B6:FB:E4` for registered `B4:FB:E4`, i.e. that one bit set. The table
compares the first three octets with only that bit masked ("mask bit 1
of octet 0, compare all 24 bits", the reading of #106's "22 bits" the
triage comment proposed). A locally administered address is by
definition not a registry assignment, so such a match rests on the 22
free bits of a local prefix coinciding with a camera block; the detail
reports it as `randomized-local` and leaves the inference to the
operator. The I/G bit is not masked: a group address never transmits a
beacon.

**Considered and not shipped.** Ubiquiti (the issue's own example),
TP-Link and Wyze sell cameras, but most of what their blocks put on the
air is an AP, router, plug or bulb — every UniFi AP would match.
"Verkada Inc" (homepage describes "Security Systems"), "Hanwha Vision",
"Zhejiang Uniview Technologies", "Vivotek" and "Swann" are registered
but no vendor self-description naming cameras was retrieved; "Prama
Hikvision India" and "ZHEJIANG DAHUA ZHILIAN" are distinct assignees
whose product line was not sourced. MA-M and MA-S blocks are 28- and
36-bit prefixes; this table compares 24.

## Why WARN with no ATT&CK technique

The same position as `CAM_WS_DISCOVERY` and `CAM_SETUP_SSID`: each is
the camera's own announcement, read from traffic sloth did not solicit.
T1046 (Network Service Discovery) describes an adversary enumerating
services; naming it would claim a step sloth never takes. WARN on first
sighting, one alert per device with a rising count; the issue's
INFO -> WARN -> CRIT join across signals is not attempted (#145: it
cannot be observed reliably from these inputs).

## Related

- `docs/views/alerts.md` — the three rows.
- `research/papers/ws-discovery-onvif.md` — `CAM_WS_DISCOVERY`.
- `research/papers/camera-setup-softap.md` — `CAM_SETUP_SSID` and the
  vendor onboarding documents the vendor set leans on.
