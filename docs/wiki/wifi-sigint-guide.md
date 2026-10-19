---
name: wifi-sigint-guide
description: A plain-language guide to the radio environment around an ordinary person — what phones, cars, body cameras, plate readers and Bluetooth gadgets broadcast, what a listener can infer from it, and where sloth fits
type: reference
---

# Wi-Fi SIGINT: a guide for everyone

**Summary**: You are inside a cloud of radio chatter all day. Every Wi-Fi
router within a few hundred metres announces itself about ten times a
second; your phone asks the air for networks while it sits in your
pocket; your car, your printer, your earbuds and the camera on the
lamp post all carry radios that say something about themselves without
being asked. None of this needs to be decrypted, joined or provoked —
it only needs to be *heard*. This page explains, for a non-specialist,
what is in that cloud, how much can be inferred by only listening, and
exactly where the limits are. Every factual claim here names its source; where a primary document
could not be opened and an abstract, summary or indexed copy stands in,
the Sources entry says so, and where the evidence is community
reporting rather than a vendor document or a peer-reviewed paper, the
text says so.

**Sources**: the numbered list at the end of this page; sloth-side
behaviour from `src/beacon_snoop.c`, `src/probe_pnl.c`,
`src/presence.c`, `src/seqnum_track.c`, `src/vendor_watchlist.c`,
`src/alerts/rules_wired.c`, `src/ble_snoop.c`, `docs/views/{beacons,
probe,pnl,seqnum,channel}.md`, `docs/wiki/mac-randomisation.md`,
`MISSION.md` §2.

**Last updated**: 2026-10-19.

---

## The one idea

Radio does not know who is listening. A transmitter puts energy into
the air and anyone with a suitable receiver in range gets a copy. For
Wi-Fi and Bluetooth, the *management* traffic — "I am a network called
X", "is network Y here?", "I am a tracker, my battery is fine" — is
sent in the clear by design, because the devices have not agreed on
any key yet. Encryption protects what you *send over* a network. It
does not hide that your device exists, what it is, roughly where it
is, or what it is looking for.

"SIGINT" — signals intelligence — is the discipline of learning from
those emissions without transmitting anything yourself. This page is
about the passive kind only. Nothing described here sends a frame (a single radio packet), joins a
network or breaks a cipher, and that is also the rule sloth is
built around (see [[sloth]] and `MISSION.md` §2).

A warning that the rest of the page keeps repeating, because it
matters: everything a listener learns is about a **radio**. A radio is
not a person. The gap between "this chipset was near this sensor at
09:12" and "Jane was here" is where most of the real harm, and most of
the overclaiming, lives. See [Limits](#limits-what-a-listener-cannot-honestly-say)
and [[mac-randomisation]].

## 1. The air around you

### Routers never stop talking

Every Wi-Fi access point sends a **beacon** frame on a fixed schedule.
The interval is set in units of 1.024 ms and the conventional value is
100 of them — one beacon every 102.4 ms, roughly ten a second, per
network name, whether or not anyone is connected [1]. The beacon
carries the network name (SSID), the hardware address (BSSID), the
channel, the security settings, and a grab-bag of optional elements.
On 6 GHz an access point advertises *more* often, not less: in
addition to beacons it sends discovery frames about every 20 ms so
that clients can find it on a wide, quiet band [2].

How many of these are around you? A 2008 study drove the streets of Salt Lake City mapping its Wi-Fi [3],
but the reports of it that could be opened disagree on the counts, so
none is quoted here. A
2021 UK wardriving study found roughly 3,000 access points per km² in
urban areas when counted tightly around the sampling point, with the
authors themselves warning that the figure is inflated by the method,
that street-level sampling only hears the first couple of floors, and
that urban and suburban counts came out similar [4]. The honest
summary is: in a town, dozens at any one spot; in a city block,
hundreds within radio reach.

### Even WPA3 sends the interesting part in the clear

Wi-Fi encryption (WPA2, WPA3) covers the *data* frames. Beacons, probe
requests and responses, authentication and association frames are
transmitted unencrypted; 802.11w / "management frame protection"
protects only a specific set of frames (deauthentication,
disassociation, some action frames) against *forgery*, and does not
make them private [5]. The December 2020 WPA3 update added "beacon
protection", which lets a connected client detect a *tampered* beacon
— it does not encrypt anything, and the beacon stays fully readable by
any listener [6].

A "hidden" network is not hidden either. The beacon leaves the name
blank, but the access point's own probe responses and (re)association
responses carry the real name in the clear, and sloth fills it in from
those frames (`src/capture/probe.c` → `beacon_reveal_hidden_ssid()` in
`src/beacon_snoop.c`); the Beacons view (`src/views/beacon.c`) then
marks the row `* (revealed via probe response)`.

### What the names and elements give away

- **Manufacturer, model and serial number.** Many routers carry a WPS (Wi-Fi Protected Setup, the push-button
  pairing feature) element in their beacons that includes the manufacturer, model name,
  model number and sometimes the serial number as plain text [7].
  sloth shows these on the Beacons view (`docs/views/beacons.md`, #77).
- **How busy the router is.** Many access points include a BSS Load
  element reporting how many stations are connected and how utilised
  the channel is [8]. It is optional, so absence is not zero.
- **Printers and TVs as access points.** A device offering Wi-Fi Direct
  acts as an access point whose network name must begin `DIRECT-`
  followed by two random characters, and must use WPA2 with a random
  key handed over by WPS [9]. That is why idle printers show up in
  everyone's Wi-Fi list.
- **Things waiting to be set up.** A headless smart-home gadget often
  gets its Wi-Fi password by first *being* an access point your phone
  joins. NIST notes that this onboarding method is sometimes done over
  an open network and "risks credential disclosure" [10]. Espressif's
  firmware names its setup network `PROV_XXXX` [10]; a Netgear range
  extender out of the box broadcasts `NETGEAR_EXT` with no password or
  the password `password` until configured [11]; several Wi-Fi cameras
  announce their own setup network by name — Hikvision `HAP_<code>`,
  EZVIZ `EZVIZ_<serial>`, Dahua `DAP-…`, TP-Link `Tapo_Cam_XXXX` —
  with a key printed on or derived from the camera's label for the
  vendors whose documents state it [12]. sloth has two alert rules for
  this class, `OPEN_SETUP_AP` and `CAM_SETUP_SSID` ([[alerts]]).
- **Mesh systems.** Higher-end mesh kits use a dedicated band for the
  router-to-satellite backhaul [13], so a mesh home can put more
  distinct BSSIDs on the air than it has visible network names.

**Where sloth shows it:** Beacons `[b]` is the per-network table;
Channel `[m]` is the per-channel activity histogram
([[views-catalog]]).

## 2. The phone in your pocket

### It asks the air for networks

A phone or laptop with Wi-Fi on sends **probe requests** whenever it
scans for networks, connected or not, and anyone with a cheap radio
nearby receives them without transmitting a thing [14]. For a decade
this was the single richest leak in consumer radio, because early
phones put the *names of every network they remembered* into those
probes.

- In 2012–2014 Cunche, Kaafar and Boreli showed that this list — a
  device's "Wi-Fi fingerprint" — could link devices to each other and
  infer social ties between their owners, on a Sydney dataset of more
  than 8,000 devices [15].
- By 2015 recent mobile operating systems had mostly stopped naming
  networks in probes unless the network was marked hidden [16].
- But Android 8 and older treat any *manually added* network as hidden,
  so in a 2021 German city-centre capture **23.2 % of probe requests
  still carried a network name**. Among those names the researchers
  found probable Wi-Fi passwords (11.8 % of the probe requests carried 16-digit-or-longer numeric
  strings, which the authors take to be the default passwords of common
  German home routers), 106
  distinct first or last names, and three e-mail addresses — people
  had typed them into the SSID box [17].

**Where sloth shows it:** Probe `[7]` lists each client radio, the
names it asked for, and its signal; PNL `[k]` — the Preferred Network
List, the set of names a device remembers — aggregates them per radio
(`docs/views/pnl.md`); the Probe page (`docs/views/probe.md`) rightly
calls the PNL "gold for social engineering" and tells you to treat it
as sensitive. ([[how-wifi-works]] §3 and [[wifi-sigint-techniques]]
technique 2 still describe this list as leaking verbatim; on current
phones that is the minority case above, not the rule.)

### Random addresses helped, and then not as much as hoped

Every Wi-Fi frame carries the sender's hardware (MAC) address. Modern
systems randomise it:

- **Apple** has used random addresses for scanning since iOS 8 (2014),
  and since iOS 14 (macOS 15 on the Mac) the *connected* address is a
  private one too; from iOS 18 / macOS 15 it is fixed per network on
  WPA2-or-better networks and rotates every two weeks on open or weakly
  secured ones, while earlier versions changed it only after six weeks
  away from the network [18].
- **Android** has randomised the scanning address since Android 8
  (2017) and the connected address by default since Android 10; that
  connected address is normally the same for a given network until
  factory reset [19].
- **Windows** 10/11 can randomise for all networks or per network when
  the switch is on [20].

Randomisation protects the *address*. It does not protect everything
else in the frame:

- The **capability elements** a phone includes in every probe request
  describe the chipset, and Apple's vendor element from iOS 10 onward
  "made identification of iOS 10 Apple devices trivial regardless of
  the use of MAC address randomization" [22]. The fingerprint has not improved the way addresses have: the 2021
  follow-up found that "nearly all modern devices" still sent
  non-generic signatures allowing "fairly granular device binning" —
  typically to a manufacturer and a generation of handsets — although
  the WPS element that once carried a unique identifier has been
  absent since Android 8 [22, 23].
- The **sequence counter** in the frame header counts up across
  address changes on many chipsets. In 2016 Vanhoef and colleagues
  combined it with the capability fingerprint and could track "as much
  as 50 % of devices for at least 20 minutes" from a passive capture
  [21]. A 2017 field study found passive fingerprinting could defeat
  randomisation on about 96 % of the Android phones of that era, and
  a control-frame flaw made 100 % of randomising devices answer from
  their real address [22]. A 2021 follow-up on 264 phones found the
  share of captured probes sent from a real hardware address had
  fallen from 81.6 % (2016) to 56.0 % (2019–20), and that newer
  hardware increasingly randomises the counter too [23].
  ([[mac-randomisation]] still describes counter randomisation as rare
  and confined to custom firmware; [23] is the later measurement and
  that page has not yet been reconciled with it.)
- **Timing.** Probes come in tight bursts — in one public dataset just
  over 98 % of consecutive probes from a device were under 65 ms apart
  — so burst shape is a weak fingerprint that a random address does
  not hide [24].

sloth implements the passive sequence-counter half of this as the
Seqnum `[j]` view, with a calibrated score and an explicit charter
that a match is a hypothesis about a radio and never an identification
of a person. Read [[mac-randomisation]] before using it.

### The map your phone carries is the bigger leak

The most consequential recent finding is not about the phone's own
signal at all. Phones locate themselves by asking a **Wi-Fi
positioning service** "where are these BSSIDs I can hear?". In 2024
Rye and Levin showed that Apple's service answered unauthenticated
queries with the locations of up to 400 *nearby* access points per
request, which let them geolocate over two billion access-point
identifiers in a year and follow *mobile* ones — travel routers and
Starlink terminals — in and out of Gaza, Ukraine and the Maui fires
[25]. Apple has since added a `_nomap` opt-out and SpaceX began
randomising Starlink BSSIDs in 2023 [25]. Separately, with about seven
months of Wi-Fi scan logs from 63 volunteers and a single GPS fix per
person per day, researchers could account for about 80 % of the
group's movements [26] — the data came from an app on the volunteers'
own phones, but it shows how completely "which networks can I see"
stands in for "where am I".

## 3. Your car is a radio station

A modern car carries several radios, and they are not all the same
kind. Only the 802.11 ones are visible to a Wi-Fi monitor such as
sloth; the sub-GHz ones need a software-defined radio, which sloth does
not have today ([[non-ip-sensors]]).

### The built-in hotspot (802.11 — visible)

- **GM / OnStar.** GM's own FAQ says the hotspot is "automatically on
  after initial setup", works with the ignition in Run or Accessory,
  reaches "up to 50 feet", and takes up to 18 devices (7 on some
  models); data plans are from AT&T [27]. While the ignition is on it
  is therefore an operating, password-protected access point — which
  on the air means beaconing. Chevrolet's support page says it can be
  switched off from the centre display or the app [27]; one owner of a
  2023+ Silverado ZR2 reported on a forum that their truck's menu
  offered only name and password changes and no off switch, which is a
  single-model owner report, not a GM statement [28]. GM's troubleshooting guidance lists a lapsed data plan among the
  causes of "connected to Wi-Fi but no internet" [29], which would mean
  the access point can stay on the air after the plan ends; but GM's
  own FAQ says "an OnStar Plan is required to power the vehicle's Wi-Fi
  Hotspot" and blames a missing internet connection on carrier coverage
  or ignition position [27]. GM's two pages pull in different
  directions, so whether a plan-less GM hotspot beacons is not settled
  by GM's text — check your own driveway. GM publishes nothing about
  the default network name, the band or the module's address prefix.
- **Ford** says FordPass Connect connects up to 10 devices, is
  reachable "from up to 50 feet outside your vehicle", and is toggled
  from the SYNC screen; a plan is required after a 3-month / 3 GB
  trial [30].
- **Toyota's** hotspot switch is documented by Verizon, the carrier,
  under Menu → Setup → Wi-Fi, not by Toyota itself; **VW** documents one
  under Settings → Wi-Fi → "Infotainment system as hotspot"; neither
  source says anything about default-on behaviour, band or naming [31].
- **Tesla's** Model 3 manual describes the car's Wi-Fi only as a
  *client* — it joins Tesla Service Wi-Fi and your phone's hotspot —
  so the documented 802.11 behaviour is that of a client, not an
  access point [32].

One gap is worth stating: no manufacturer document was found
that says what a factory hotspot's default SSID looks like or which
address prefix the telematics module uses. If you want to know whether
your own car beacons, the Beacons view in the driveway answers it in a
minute; this page does not guess.

### Wireless CarPlay and Android Auto (802.11 — visible)

Apple's requirements for a wireless CarPlay head unit are explicit:
Bluetooth is "used for discovery and reconnection only", and the head
unit must be a Wi-Fi Alliance certified **access point**, 5 GHz
802.11ac recommended, that the iPhone joins [33]. Google's help page says only that the phone needs 5 GHz Wi-Fi and
Android 11 or later; that the link is set up over Bluetooth and then
carried on a 5 GHz Wi-Fi Direct connection is press reporting (Engadget,
2026), and neither source says which end hosts it [34]. Either way, a
car with a wireless phone link is running a Wi-Fi network while you
drive — 5 GHz for Android Auto, and for CarPlay units that follow
Apple's recommendation; Apple's own session allows that some head units
"might have to use" 2.4 GHz [33, 34].

### Your passengers' phone hotspots (802.11 — visible, anonymous)

Rye and Levin found the largest single "vendor" bucket in their
corpus — about 13 % of all BSSIDs — was addresses with no registered
manufacturer, which they believe are phones in hotspot mode: iOS 17
and Android 14 choose a random BSSID when the hotspot is turned on
[25]. A phone hotspot heard from a passing car therefore cannot be
attributed to a handset maker from its address.

### Tyre sensors and key fobs (sub-GHz — not visible to sloth)

Direct tyre-pressure sensors commonly transmit at 315 or 433 MHz. Each
message carries a sensor ID that does not change during the sensor's
lifetime, is not encrypted, and was received by researchers at up to
10 m with a cheap antenna and 40 m with a low-noise amplifier; the
sensors studied transmitted roughly once a minute and "even when cars
are stationary" [35]. A classic push-button key fob transmits a short
rolling-code burst at 315 MHz (US/Japan) or 433.92 MHz (Europe) and by
regulation must stop within five seconds of the button being released
[36]. Both are outside 802.11 entirely.

### Tesla's Bluetooth phone key (BLE — decodable, see §6)

Martin Herfurt's Project TEMPA (CanSecWest 2022) documents that a Tesla
Model 3 with Phone Key advertises over Bluetooth LE with a device name
derived from a SHA-1 hash of the VIN — unique to the vehicle, always
on, visible to anyone with a BLE radio, and not changing over time;
Tesla's 2019 reply, quoted by The Parallax, was that randomising the
identifier "would not result in significant privacy gains due to the
ubiquity of automated license plate readers" [37].

### Travel routers move, and the map notices

In Rye and Levin's year of data, 4.6 % of GL.iNet travel-router BSSIDs
moved more than a kilometre — 76 times the rate in a random sample —
with a median journey of 97 km over the one-month comparison window
(120 km over six months), between "campgrounds, RV parks, and
marinas" [25]. A router that lives in a vehicle is a vehicle tracker
in any database that geolocates BSSIDs.

**Where sloth shows it:** a car's hotspot or head unit is a row on
Beacons `[b]`; the passengers' phones are rows on Probe `[7]`, where
the Presence column (`passing` / `visitor` / `resident`) is built
precisely for telling a vehicle moving through range from a device
that stayed (`docs/views/probe.md`).

## 4. Body-worn cameras: what Axon documents, and what it does not

Police body cameras are cloud products with several radios. Axon is
used here because it publishes the most, not because it is unusual.

**What is documented.** Axon's Body 3 user guide lists transmit ranges of 2402–2480 MHz (the
Bluetooth band), 2.4 and 5 GHz Wi-Fi, and LTE bands by model, and its
regulatory label carries FCC ID X4GS01200 containing the LTE module
X4GAB7610 [38]. The Body 4 (AX1037 US /
AX1038 international) carries Bluetooth, 2.4 and 5 GHz Wi-Fi and an
LTE module whose US bands include B14, the FirstNet public-safety
band; no 6 GHz Wi-Fi appears on either grant [39]. Both guides describe the camera's Wi-Fi as a *client* of an
administrator-approved access point — the agency enters the SSID and
password in Axon Evidence, and the camera uses it for evidence upload,
firmware download, clock and settings sync — plus a "Wi-Fi Positioning"
setting that "enables gathering of location information from Wi-Fi
access points", i.e. the camera scanning nearby networks to fix its
position; whether that scan is passive or sends probe requests is not
stated. The Body 3 FCC grant's added 5 GHz bands are authorised "in
client mode". No Axon document
read for this page describes the camera hosting an access point [40].
A docked camera communicates over the dock's wired connection and
halts Wi-Fi [40]. The "Location in Video" setting embeds GNSS/GPS position in
recordings; Body 4's "Watch Me" opens the wearer's livestream to
supervisors and, with drone support enabled, "the officer's location
is shared with Command"; the guide's connected features (Axon
Assistant, Real-Time Translation) list "LTE or trusted Wi-Fi
connection" as their requirement [41].

**Axon Signal.** The Signal family triggers recording over short-range
radio. The Fleet 3 guide says a trigger "can also trigger other nearby
Axon cameras within Bluetooth range of about 30 feet (9.1 meters)"
and will not wake a powered-off camera; an Axon "Firearm Sensor,
Camera Activator" grant from 2017 (X4GS01105) is a 2402–2480 MHz Part
15 digital transmitter [42]. On a
Body 4, when the wearer double-presses the Event button, "the camera
broadcasts an activation signal for up to 30 seconds" over a Bluetooth
beacon with a range of about 30 ft line-of-sight, to activate other
Body 4s nearby [43].

**Axon Fleet 3.** The in-car system's Fleet Hub has "Wi-Fi 6 and BLE"
and GNSS with dead reckoning, uses a Cradlepoint router (IBR900
documented) for LTE/5G or Wi-Fi-as-WAN, and has an interior antenna
whose purpose is "communication between Fleet Hub and Axon Body Worn
cameras" [44]. A police car so equipped is therefore a Wi-Fi 6 network
plus a cellular router plus Bluetooth, which is to say it is a loud
object.

**What is not published — and so what sloth does not do.** In the
Body 2 spec sheet, Body 3 and Body 4 user guides, Body Mini specs,
Fleet 3 guide, the AX1024 EU declaration of conformity and the FCC
grant summaries, no SSID pattern, BLE device name, advertisement
payload or MAC-prefix mapping is published for any Body, Signal or
Fleet product; the only SSID mentioned anywhere is the agency's own
[45]. Public mirrors of the IEEE registry list one address block for
Axon Enterprise (00-25-DF, registered 2010) [46], and nothing says
which products, if any, use it. Becker et al.'s address-carry-over
method [57] would apply to any advertiser whose payload carries a
token that persists across address changes; whether an Axon beacon
does is unpublished, so it is a possibility the method raises, not a
finding about Axon. A 2018 DEF CON talk reported that body cameras from Vievu (an Axon
subsidiary since May 2018), Patrol Eyes, Fire Cam and Digital Ally had
Wi-Fi radios that "broadcast unencrypted identifying information about
the devices" [47]; the Axon Body line was not among the products
named.

sloth therefore ships **no Axon radio fingerprint**. Its one
Axon-related rule, `SURV_CLOUD_SNI`, fires when a host on the
*monitored wired/Wi-Fi network* opens an encrypted (TLS) web connection that names Axon's evidence
platform as its destination (`evidence.com`, `axon.com`), and its
own text says it cannot tell a docked camera uploading from an analyst
with the portal open in a browser [48]. An LTE upload never crosses
the monitored network, so it cannot produce that alert. The reasoning
is in `research/papers/surveillance-vendor-endpoints.md`: a domain the
vendor tells its customers to allow-list is checkable by anyone; a
guessed on-air signature carrying a vendor's name is not.

## 5. Plate readers and other street furniture

### Flock Safety: vendor documents vs. what people have heard

Flock's own documents describe the Falcon as "solar-powered,
motion-activated and infrastructure free", "connected to the cloud
through LTE, like a mobile phone", the Falcon Flex as portable + LTE, and the Condor only as having "AC
or solar-powered options" with no uplink stated; Flock's FAQ says its
cameras use "a cellular network instead of WiFi", and none of these
documents describes a Wi-Fi, Bluetooth or wired data path [49]. Labels photographed on installed Falcons carry two FCC
IDs: a Sierra Wireless LTE module (N7NRC76B) and a LITE-ON 802.11
a/b/g/n/ac + Bluetooth 4.2 LE combo module (PPQ-WCBN3510A), on a
Qualcomm-based Open-Q 624A board [50]. So the hardware *has* Wi-Fi and
Bluetooth; the vendor documents the uplink as cellular.

What has been reported from the air — all of it community work, none
of it confirmed by Flock, and most of it now stale:

- A management Wi-Fi network named `Flock-` plus part of the MAC
  address, and Bluetooth battery packs advertising as
  `Penguin-NNNNNNNNNN` with a manufacturer ID registered to a module
  maker, XUNTONG, carrying a serial number — reported by Ryan O'Horo in November 2024, who mapped 700+
  Wi-Fi-identified cameras on WiGLE and 18,000+ hits once the
  battery-pack names were searched too [51]. The
  `Penguin-` name was removed in a battery firmware update observed
  on 2025-03-19 [51]; the `Flock-XXXXXX` network is reported
  deactivated around December 2025, with a different name and 5 GHz
  operation reported in May 2026 [52].
- Flock's own IEEE address block is B4:1E:52 [53]. Community detector
  lists add dozens of other prefixes, and one project's own data shows
  that for one of them, F4:6A:DD, 71 % of records matched non-Flock
  hardware [53]. Its companion WiGLE search reported, when read, 5,100 SSID-correlated
  sightings against 85,999 prefix-only "suspected, unverified" ones —
  and its README calls even the correlated ones suspected [54].
- In July 2026 a local group drove a popular ESP32 "Flock detector"
  past at least four visually confirmed cameras and it found none; they
  put it down to LTE backhaul, Bluetooth beacons now off on many units
  (a 2025 firmware update had already stripped the battery-pack names)
  and their own board running an older detection mode, call it a
  single-board, single-day test, and recommend visual confirmation [55].
- In May 2026 one write-up recorded a camera's Wi-Fi radio sending
  twelve probe requests in fifty seconds for a hidden network, timed
  with its infrared strobe [56]. The same post reads the burst as the camera "asking for its uplink";
  that is the author's inference — the post itself elsewhere calls the
  fleet "cellular-uplinked cameras" — and it conflicts with the
  vendor's LTE documentation, so this page does not repeat it.

**Does a Flock camera listen to *your* phone?** No vendor document,
FCC filing, firmware analysis or primary reporting found for this page
shows that Flock's plate-reader cameras capture or log passers-by's
Wi-Fi or Bluetooth. The widely circulated sentence about "a high-gain
multi-band Wi-Fi/Bluetooth antenna and receiver, ensuring detection of
suspect devices inside and outside vehicles" traces, as far as this page could follow it, to a parody comment of
2026-08-09 written in the persona of a Flock representative in a meme
thread about Flock's pricing — alongside "64 GB of DDR6 RAM" and an
RTX 5090 — and it is not in the ESC Region 13 Flock pricing sheet [58].
O'Horo's label-and-radio analysis describes the Wi-Fi as a setup web
interface for the installer and the Bluetooth as the external battery
reporting "health and safety data back to the camera", adding that
Wi-Fi "does not appear to be used in the field for normal operations"
[51].

That said, the *product category* exists. Leonardo (the ELSAG
plate-reader vendor) markets **SignalTrace** to public-safety agencies as
passively detecting "Bluetooth®, Wi-Fi, RFID, and other supported
wireless signals", deployable alongside plate readers or standalone,
and 404 Media describes it as linking devices that regularly travel
together and correlating them to licence plates [59]. That is the
Bluetooth-plus-plate correlation this page warns about, as a
catalogue item.

### The sensors that have been counting your radios for fifteen years

- **Bluetooth travel-time sensors.** TrafficCast's BlueTOAD "detects
  anonymous Bluetooth signals broadcast from mobile devices to
  determine accurate travel times and speeds", reports MAC-address
  detection counts and origin/destination in its web interface, and
  runs on cellular and solar [60]; Iteris's deployments time-stamp the
  MAC addresses of passing Bluetooth devices and match them centrally
  [60]. A 2010 traffic-engineering paper found 7.4 % of passing
  vehicles had a discoverable Bluetooth address and that "the same
  matching algorithms used in traditional license plate studies" apply
  [61]. These boxes have been on arterial roads since around 2010.
- **Retail footfall.** Cisco Meraki's location analytics counts a "passerby" as any probing
  device that did not stay long enough to be a "visitor", a "visitor"
  as a device whose probes kept arriving above a signal threshold for
  five minutes within a twenty-minute window, and measures dwell from
  presence time-stamps, "irrespective of its WiFi association state";
  MACs are hashed, salted and truncated; the older Scanning API v2 left
  randomised addresses out, and v3 includes them in its location output
  [62].
- **Smart meters** talk in the 902–928 MHz band at under a watt, with a
  2.4 GHz ZigBee radio for in-home displays on some models [63] —
  sub-GHz and ZigBee, so not Wi-Fi and not visible to sloth.

**Where sloth fits:** `SURV_CLOUD_SNI` has a `flocksafety.com` row,
and the alert text says plainly that a hit means a host on *your*
network is using the Flock portal, not that a camera is on your street
([[alerts]]). sloth ships no Flock radio fingerprint for the same
reason it ships no Axon one; the community prefixes above, with their
measured false-positive rates, are exactly the kind of row the
research-corpus rule keeps out until a source exists.

## 6. The Bluetooth around you

Bluetooth LE devices advertise on three channels with a payload of up
to 31 bytes, structured as small typed records: flags, service UUIDs,
a local name, transmit power, an "appearance", and manufacturer-
specific data [64]. Since Bluetooth 4.0 the advertised address can be
a random one that changes on a timer the manufacturer sets; 15 minutes
is the value vendor stacks quote as the specification's recommendation
and ship as their default [65].

The same lesson as Wi-Fi applies: the address rotates, the payload
often does not. Becker, Li and Starobinski (2019) showed an
"address-carryover" attack that follows a device across its address
changes whenever an identifying payload token changes at a different
moment than the address; Windows 10 addresses lived about 16 minutes and Apple ones about 20 on
average, but the carry-over attack followed Apple devices for up to 53
minutes and a Windows 10 device for over 11 hours with no upper bound;
the Android phones they tested were immune simply because they did not
continuously advertise any identifying payload [57].

What specific things say:

- **Apple earbuds and phones.** Active Apple audio devices constantly
  transmit "Proximity Pairing" messages describing model, colour,
  whether they are in the ear or the case, battery level and lid-open
  count; Apple devices continuously send "Nearby Info" status
  messages [66].
- **Find My.** An iPhone or Mac that has lost connectivity emits one
  Find My advertisement every two seconds with a rotating public key,
  rotating every 15 minutes; the paper that measured this predates
  AirTag, so it says nothing about the tag itself [67].
- **Samsung SmartTag** advertises under service UUID 0xFD5A
  (registered) or 0xFD59 (unregistered) with a tag state, ageing
  counter and privacy ID [68]. **Tile** advertisements are
  recognisable by its registered UUIDs 0xFEED, 0xFEEC and 0xFD84 [69].
- **Fitness trackers.** A 2016 study found "the majority of the fitness
  trackers use unchanged BLE address while advertising, making it
  feasible to track them", and that their traffic correlates with the
  wearer's activity intensity [70].
- **Retail beacons.** iBeacon carries a UUID/major/minor and a
  1-metre calibrated power for "immediate / near / far" zoning [71];
  Eddystone uses service UUID 0xFEAA [71]. Google Fast Pair advertises
  under 0xFE2C at up to 10 Hz and salts its payload per address
  rotation precisely to avoid tracking [72]. Exposure Notification
  (2020) used 0xFD6F with a rolling identifier and an address rotation
  of 10–20 minutes [73].
- **Medical devices.** Community code for Dexcom glucose transmitters
  expects a device name of `Dexcom` plus the last two characters of the
  serial number [74].

**Where sloth fits today:** `src/ble_snoop.c` (#144, landed
2026-10-19) decodes HCI LE advertising reports and the common record
types — flags, 16-bit UUIDs, name, TX power, appearance, manufacturer
data — proved against 23 hand-built byte-array tests. It is a decoder
only: no sensor registration, no device table, no view, no alert, and
no Service Data record yet, so Eddystone, Exposure Notification, Fast
Pair and SmartTag frames are not classifiable today [75]. The design
for the rest, including the explicit ban on active scanning, is
[[non-ip-sensors]].

## 7. From signals to inferences

This is the section that turns "I heard a radio" into something a
person would care about. Each step below is real, published, and
weaker than it sounds.

- **Here, passing, or staying.** A listener that records a radio's
  signal strength over a short window can separate a trajectory that
  rose, peaked and fell away from one that rose and stayed. sloth's
  Presence column does exactly this: both rise and fall must reach 8 dB
  for `passing`, `visitor` needs at least two minutes, `resident` at
  least fifteen, anything with too few samples is `?`, and all of it
  is a statement about a signal shape, not about who carried the
  device (`src/presence.c`, `docs/views/probe.md`).
- **How far away.** Turning signal strength into distance is
  unreliable indoors — a survey of the field calls it "very
  inaccurate, particularly in indoor environments" — because of the
  randomness of the received signal power [76]. sloth's Probe, Beacons
  and Seqnum views print raw signal strength (dBm, a logarithmic power
  unit) only. One place does not: the dashboard's "Roaming clients"
  panel prints a `dist` column in metres from a log-distance model with
  fixed defaults (`src/views/dashboard_grid.c`), whose own comment calls
  it "a rough order-of-magnitude hint, not a metric measurement" —
  treat it as exactly that.
- **Where it went.** Several monitors spread along a road, each
  reporting when they heard a phone, can be combined into a
  trajectory; this was demonstrated on unmodified 2012 smartphones,
  which did not randomise addresses [77]. sloth can merge observations
  from more than one sensor but has no trilateration or position code
  (`src/wifi_merge.h`).
- **Who knows whom.** Devices that keep turning up at the same events,
  or that ask for similar sets of networks, can be linked statistically
  as probably belonging to acquaintances: 11 million probes from
  160,000 devices at public events yielded a social graph in 2013 [78];
  the 2012 Sydney study did it from SSID similarity [15]. Both predate
  randomisation, infer links with false positives, and identify no
  person.
- **Where a crowd came from.** A 2016 study of 11 million probes at two
  Italian political rallies inferred the attendees' home towns from
  the networks they asked for and found it matched the official voting
  results of the two parties "surprisingly well" [79]. That is a result
  about a crowd, requires an external wardriving database that sloth
  does not query, and is far weaker on modern phones that name few
  networks.
- **Through the wall.** Wi-Fi reflections can reveal how many people
  are in a closed room and simple gestures, "without carrying any
  transmitting device" — shown in 2013 on software radios, and by 2015
  activity recognisers on commodity cards reported over 96 % accuracy
  in test environments, with a 2019 survey warning that such systems
  degrade badly in new rooms and on new people and that "the victim
  user may be unaware" [80]. This needs Channel State Information from
  specific receiver hardware; sloth reads per-frame signal strength
  only and has none of it. Wi-Fi sensing is now a standard — IEEE
  802.11bf-2025, approved 28 May 2025 — and a shipping consumer
  feature: Comcast's opt-in "WiFi Motion" senses movement from signal
  changes between your gateway and your own stationary devices, and
  Comcast states it may have to disclose that data "in response to a
  valid subpoena, court order, search warrant or other lawful legal
  process" [81]. Neither is a third party listening from outside; both
  are what your own equipment can be asked to do.

What sloth does **not** do, verified by reading the tree: no
trilateration (the dashboard's metres column is a single-receiver
path-loss guess, not a position), no pairing of two radios as
companions, no schedule inference, no Wi-Fi sensing. A radio appears, with a signal,
a name list if it offered one, a presence shape, and — if you enable
it — a scored hypothesis that two addresses were one chipset.

## Limits: what a listener cannot honestly say

Every section above ends in the same place, so here it is once:

1. **A MAC is a radio, not a person.** Correlating two addresses says
   "consistent with one chipset", with a false-pair rate sloth prints
   on every test run; it does not say who held it. sloth's charter
   ([[mac-randomisation]], [[alerts]] "Records are not conclusions
   about people") forbids using these records alone for personnel
   action, physical identification, or automated containment.
2. **A domain is a browser or a device.** A TLS server name on your
   network tells you a host there spoke to a vendor; it does not tell
   you which host type.
3. **An address prefix is a chipset vendor, not a product.** The
   Flock F4:6A:DD figure — 71 % of matches were not Flock — is the
   general case for any consumer radio module.
4. **Community fingerprints age.** Every Flock signal reported in 2024
   was gone or changed by 2026. A detector built on them says
   "nothing here" with the same confidence either way.
5. **Hashing does not anonymise a trail.** A stable pseudonym followed
   over time is tracking under another name — this is sloth's own
   reasoning, not a regulator's quotation, and the Enschede case below
   turned on exactly that point.

## Law, briefly and by jurisdiction

This is orientation, not advice.

- **UK.** ICO guidance of 16 February 2016 (pre-GDPR) said that if an
  individual is identifiable from the MAC or other information the
  operator holds, the operator is processing personal data "even if
  the name of the individual is unknown", and called for signage at
  the entrance to collection areas, a privacy impact assessment,
  limited retention and anonymisation where individuals need not be
  identified [82].
- **EU.** The Article 29 Working Party said in 2011 that the MAC
  address of a Wi-Fi access point combined with its calculated location
  is personal data; separately, for anonymous location history collected
  to improve a positioning service, it said even a randomly assigned
  device identifier should be kept for at most 24 hours [83]. In 2021 the Dutch regulator announced a €600,000 fine
  on the municipality of Enschede for Wi-Fi counting sensors that gave
  each phone a unique code, because the data *could* have been used to
  follow individuals and that potential was unnecessary for counting
  a crowd; no actual tracking was found and the municipality appealed
  [84].
- **US.** In 2015 the FTC settled its first case against a retail
  tracking company, Nomi Technologies, for *deception* — its policy
  promised an in-store opt-out that did not exist — not for the
  passive collection itself [85]. In *Joffe v. Google* the Ninth
  Circuit held that payload data on an unencrypted Wi-Fi network is
  not a "radio communication" exempt from the Wiretap Act; the case
  was about captured e-mail and web traffic, not management frames or
  addresses, and binds only that circuit [86].
- **sloth's own rule** is policy, not law: it never crafts and sends a
  frame onto a network it monitors (`MISSION.md` §2 rule 1, the one
  absolute), never puts an interface into monitor mode itself, and
  announces every network-using service — and its records are
  evidence about radios, never identifications of people.

## What you can do about your own emissions

Everything here except the Wi-Fi Direct bullet is a setting the vendor
documents above describe.

- Turn the car's hotspot off when you are not using it, if your car
  lets you (GM, Ford and VW document a switch; Verizon's support article
  documents Toyota's) [27, 30, 31].
- Leave your phone's private/random Wi-Fi address on (it is the
  default on current iOS and Android) and forget networks you no
  longer use — a forgotten network cannot be probed for [18, 19].
- Finish setting up new gadgets promptly; a camera or extender in
  setup mode is an access point announcing its make — and, for the
  Netgear extender, an open one [11, 12].
- Turn off Wi-Fi Direct on printers and TVs you do not use it with —
  the setting's name varies by maker; the spec only says what the
  network is called when it is on [9].
- Point sloth at your own house once: Beacons `[b]` shows what your
  equipment says about itself, Probe `[7]` shows what your devices ask
  for, and the result is usually a short list of things to switch off.

## Try it yourself

With a monitor-mode radio ([[monitor-mode]]) and `--hop`:

| What you want to see | sloth view | Doc |
|---|---|---|
| Every network in range, its vendor strings, hidden-name reveals | Beacons `[b]` | `docs/views/beacons.md` |
| Per-channel occupancy | Channel `[m]` | `docs/views/channel.md` |
| Client radios, what they ask for, passing / staying | Probe `[7]` | `docs/views/probe.md` |
| Remembered-network lists per radio | PNL `[k]` | `docs/views/pnl.md` |
| Scored same-chipset hypotheses across random addresses | Seqnum `[j]` | `docs/views/seqnum.md`, [[mac-randomisation]] |
| Setup-mode gadgets, camera setup networks, vendor cloud contacts | Alerts `[v]` | [[alerts]] |

## Sources

Opened and checked on 2026-10-19 unless stated. "Reported" marks
journalism or community work rather than a vendor document, standard
or peer-reviewed paper.

1. CWNP, "802.11 Beacon Intervals" (TU = 1024 µs; 100 TU = 102.4 ms); sloth `src/beacon_snoop.c` beacon-interval parse, `include/sloth.h` TBTT timing citing IEEE 802.11-2020 §11.1.3.
2. Cisco Blogs, A. Dumdei, "AP Discovery Methods for 6GHz Wi-Fi, Part 2", 2023 (FILS Discovery / unsolicited probe responses about every 20 ms; Reduced Neighbor Report).
3. Torrens, "Wi-Fi Geographies", *Annals AAG* 98(1), 2008; the paper itself could not be opened and the two trade-press accounts of it that could give different figures, so no count from it appears above.
4. Oughton, Kusuma, Peyronel, Crowcroft, "Wi-Fi Wardriving Studies Must Account for Important Statistical Issues", arXiv:2101.06301 (preprint).
5. Cisco Meraki, "802.11w Management Frame Protection (MFP)"; sloth `src/assoc_track.c`, `src/deauth_snoop.c`.
6. Wi-Fi Alliance, Derham & Bhandaru, "Wi-Fi CERTIFIED WPA3 December 2020 update…", wi-fi.org/node/37510; BIGTK key indexes in Linux `nl80211.h`.
7. Wi-Fi Simple Configuration attribute IDs per hostap `src/wps/wps_defs.h` (0x1021 Manufacturer, 0x1023 Model Name, 0x1024 Model Number, 0x1042 Serial Number); sloth `src/beacon_snoop.c`.
8. hostap `ieee802_11_defs.h` (`WLAN_EID_BSS_LOAD 11`) and `hostapd.conf`; sloth `src/beacon_snoop.c`.
9. Wi-Fi Alliance, Wi-Fi Peer-to-Peer Technical Specification v1.5 §3.2.1.
10. NIST SP 1800-36 (quoted sentence verbatim); Espressif RainMaker firmware dev tips (`PROV_XXXX`); sloth `research/papers/nist-sp1800-36-onboarding.md`.
11. NETGEAR KB 23517, "Setting up NETGEAR Wi-Fi Range Extenders".
12. Hikvision, "How to Set Wi-Fi Connection of Wi-Fi Camera via Mobile Phone Web Browser"; EZVIZ support FAQ; sloth `research/papers/camera-setup-softap.md`.
13. NETGEAR KB 000064886, "What is backhaul?".
14. Fenske, Brown, Martin, Mayberry, Ryan, Rye, "Three Years Later: A Study of MAC Address Randomization in Mobile Devices and When It Succeeds", PoPETs 2021(3).
15. Cunche, Kaafar, Boreli, "I know who you will meet this evening!", IEEE WoWMoM 2012; journal version *Pervasive and Mobile Computing* 11, 2014.
16. Freudiger, "How talkative is your mobile device?", WiSec 2015 (paywalled; content as summarised in [17]).
17. Ansohn McDougall, Burkert, Demmler, Schwarz, Hubbe, Federrath, "Probing for Passwords – Privacy Implications of SSIDs in Probe Requests", ACNS 2022 workshops (preprint, Universität Hamburg).
18. Apple Support 102509, "Use private Wi-Fi addresses on Apple devices"; iOS 8 scan randomisation per [21] §2.1.1.
19. AOSP, "Implement MAC randomization" and "MAC randomization behavior".
20. Microsoft Support, "How to use random hardware addresses in Windows".
21. Vanhoef, Matte, Cunche, Cardoso, Piessens, "Why MAC Address Randomization is not Enough", ACM AsiaCCS 2016, papers.mathyvanhoef.com/asiaccs2016.pdf.
22. Martin et al., "A Study of MAC Address Randomization in Mobile Devices and When it Fails", PoPETs 2017(4), arXiv:1703.02874.
23. As [14].
24. Bravenec, Torres-Sospedra, Gould, Fryza, "Exploration of User Privacy in 802.11 Probe Requests with MAC Address Randomization Using Temporal Pattern Analysis", arXiv:2206.10927.
25. Rye & Levin, "Surveilling the Masses with Wi-Fi-Based Positioning Systems", IEEE S&P 2024, arXiv:2405.14975; `_nomap` and Starlink per the paper and The Register, 2024-05-23.
26. Sapiezynski, Stopczynski, Gatej, Lehmann, "Tracking Human Mobility Using WiFi Signals", *PLoS ONE* 10(7), 2015.
27. OnStar, "Built-in Wi-Fi Hotspot FAQ", onstar.com/us/en/support/4glte; Chevrolet, in-vehicle Wi-Fi hotspot how-to page.
28. Owner forum thread "How to Turn off the Trucks WiFi?", chevyzr2.com (reported; single model).
29. GMC, "In-Vehicle Wi-Fi Hotspot troubleshooting" (inference from the troubleshooting text, stated as such).
30. Ford, "FordPass Connect with Wi-Fi Hotspot overview"; Ford Canada hotspot help page.
31. Verizon KB 213124 (Toyota hotspot); Volkswagen of America, "Wi-Fi Hotspot"; Verizon KB 228597 (VW Car-Net).
32. Tesla, Model 3 Owner's Manual, "Wi-Fi" (page returns 403 to automated fetch; sentences confirmed via indexed copies of the official URL).
33. Apple, WWDC 2017 session 717, "Developing Wireless CarPlay Systems", slides "Wireless considerations / Hardware Requirements".
34. Google, Android Auto Help, "Get started with Android Auto"; Engadget, "Why does wireless Android Auto use both Bluetooth and Wi-Fi?", 2026-07-16 (reported).
35. Rouf et al., "Security and Privacy Vulnerabilities of In-Car Wireless Networks: A Tire Pressure Monitoring System Case Study", USENIX Security 2010.
36. 47 CFR §15.231(a)(1); Fleming & Makdessian (Maxim), "Steering Through RKE Requirements", *Microwaves & RF*.
37. Herfurt, "Project TEMPA", CanSecWest 2022 (trifinite.org); Rosenblatt, The Parallax, 2019-11-14 (Tesla quotation; reported).
38. Axon Body 3 Camera User Guide EN_US, "Radio waves" and regulatory label; fccid.io X4GS01200 and X4GAB7610.
39. Axon Body 4 Camera User Guide EN_US (LTE band lists); fccid.io X4GS01506 and X4GAB065.
40. Axon Body 3 and Body 4 user guides, "Automatic Wi-Fi Upload" / Admin > Body Camera Wi-Fi Networks; X4GS01200 grant note ("in client mode").
41. Axon Body 3 / Body 4 user guides, "Location in Video"; Body 4 guide, "Watch Me".
42. Axon Fleet 3 User Guide EN_US p.16; fccid.io X4GS01105 (Signal Sidearm) and X4GS01958.
43. Axon Body 4 Camera User Guide EN_US, "Nearby Body Camera Activation".
44. Axon Fleet 3 User Guide EN_US pp.2–3 and FAQ.
45. Full-text search of the documents in 38–44, Axon Body 2 spec sheet, Body Mini specs and the AX1024 EU Declaration of Conformity; the Axon Dock guide and FCC exhibit PDFs were not read.
46. maclookup.app and Wireshark `manuf` (one entry, 00:25:DF Axon Enterprise, Inc.); the IEEE primary listing was not retrievable by script.
47. CSO Online, "Security flaws in police body cameras open the devices to attack" (Josh Mitchell, DEF CON 26, 2018) (reported).
48. sloth `src/vendor_watchlist.c`, `src/alerts/rules_wired.c :: rule_surv_cloud_sni`, `research/papers/surveillance-vendor-endpoints.md`.
49. Flock Safety, "About Flock Safety — FAQ" (as hosted by Town of Bristol RI) and Flock product pages for Falcon Flex and Condor.
50. fccid.io N7NRC76B (Sierra Wireless RC76B) and PPQ-WCBN3510A (LITE-ON combo module); label photographs and the Open-Q 624A board per [51] (reported).
51. O'Horo, "Spotting Flock Safety's Falcon Cameras", 2024-11-11, updated 2025-03-20 (reported).
52. colonelpanichacks/flock-you README ("Some time around December 2025, this AP was deactivated", attributed to DeFlockJoplin) and flock-you issue #43, 2026-05-18 ("Flock Camera net." on 2.4 GHz ch. 1 and 5 GHz ch. 157, locally administered MACs) (reported).
53. IEEE MA-L B4:1E:52 → Flock Safety (api.macvendors.com); colonelpanichacks/flock-you README; simeononsecurity/flock-finder README (F4:6A:DD 8,496 of 11,996 non-Flock) (reported).
54. simeononsecurity/flock-finder README, counts as read on 2026-10-19 (reported; counts change).
55. DeFlockILM, "Field Test: Does the 'Flock Detector' Still Work? Not Reliably", 2026-07-26 (reported).
56. Klavan Security, "The Flock stopped broadcasting. Somebody listened anyway.", 2026-05-01 (reported).
57. Becker, Li, Starobinski, "Tracking Anonymized Bluetooth Devices", PoPETs 2019(3).
58. Origin: lemmy.world comment 25199499 (satirical persona post); absence confirmed by text extraction of the ESC Region 13 "Flock Pricing" PDF.
59. Leonardo US Cyber & Security Solutions, "Beyond License Plates: How SignalTrace Expands Operational Awareness…", 2026-07-29; 404 Media, J. Cox, "This Company Will Add Phone, AirPod, and Smartwatch Trackers to License Plate Readers", 2026-06-08 (reported).
60. TrafficCast, BlueTOAD cutsheet (Cellular/Ethernet, 2012); Iteris press release, 2013-05-13.
61. Brennan et al., "Influence of Vertical Sensor Placement on Data Collection Efficiency from Bluetooth MAC Address Collection Devices", *J. Transp. Eng.* 136(12), 2010 (abstract via indexed copies).
62. Cisco Meraki, "Location Analytics" documentation.
63. Itron / SDG&E, "OpenWay RF FAQ", 2010; Landis+Gyr Network Router product sheet, 2025.
64. Bluetooth Core Specification Vol 6 Part B, Vol 3 Part C §11, Vol 4 Part E §7.7.65.2 (as cited in `src/ble_snoop.h`; layout cross-checked against [67] and [73]).
65. bluetooth.com, "Bluetooth Technology Protecting Your Privacy"; TI BLE5-Stack `GAP_PARAM_PRIVATE_ADDR_INT` (default 15 min); ESP-IDF RPA timeout default 0x0384 (900 s).
66. Celosia & Cunche, "Discontinued Privacy", PoPETs 2020(1).
67. Heinrich, Stute, Kornhuber, Hollick, "Who Can Find My Devices?", PoPETs 2021(3).
68. Yu, Henderson, Tiu, Haines, "Security and Privacy Analysis of Samsung's Crowd-Sourced Bluetooth Location Tracking System", USENIX Security 2024. (Issue #144's 0xFD5B is wrong: the SIG assigns it to V2SOFT.)
69. Weller, Classen, Ullrich, Waßmann, Tews, "Lost and Found", WiSec 2020 (PrivateFind design; no statement about Tile's address behaviour); Bluetooth SIG assigned numbers for the Tile UUIDs.
70. Das, Pathak, Chuah, Mohapatra, "Uncovering Privacy Leakage in BLE Network Traffic of Wearable Fitness Trackers", HotMobile 2016.
71. Apple, "Getting Started with iBeacon" v1.0; Google Eddystone protocol specification.
72. Google Fast Pair Specification, Provider page.
73. Apple/Google, "Exposure Notification — Bluetooth Specification v1.2", April 2020.
74. NightscoutFoundation/xDrip, `Ob1G5CollectionService.java` (reported; community code).
75. sloth at e37e3a3: `src/ble_snoop.{h,c}`, `tests/test_ble_snoop.c` (23 tests), `src/poll.c` (only `sensor_register` call is Wi-Fi), [[non-ip-sensors]].
76. Zanella, "Best Practice in RSS Measurements and Ranging", *IEEE Communications Surveys & Tutorials*, 2016 (abstract).
77. Musa & Eriksson, "Tracking unmodified smartphones using Wi-Fi monitors", ACM SenSys 2012.
78. Barbera, Epasto, Mei, Perta, Stefa, "Signals from the crowd", ACM IMC 2013.
79. Di Luzio, Mei, Stefa, "Mind your probes", IEEE INFOCOM 2016 (abstract).
80. Adib & Katabi, "See Through Walls with Wi-Fi!", SIGCOMM 2013; Wang, Liu, Shahzad, Ling, Lu, "Understanding and Modeling of WiFi Signal Based Human Activity Recognition", MobiCom 2015; Ma, Zhou, Wang, "WiFi Sensing with Channel State Information: A Survey", *ACM Computing Surveys* 52(3), 2019, doi:10.1145/3310194 (the survey naming the Intel 5300 and Atheros CSI tools; full text not open-access, quotations from the fact-check pass).
81. IEEE Std 802.11bf-2025 (approved 28 May 2025, per AFNOR/ANSI store listings); Comcast, Xfinity "WiFi Motion" support pages.
82. ICO Wi-Fi location analytics guidance, 16 Feb 2016, as summarised by Osborne Clarke and Pinsent Masons Out-Law (the ICO PDF is no longer served).
83. Article 29 Working Party, Opinion 13/2011 on geolocation services (via Hunton summary).
84. Autoriteit Persoonsgegevens, Enschede decision, 30 April 2021, as reported by Pinsent Masons Out-Law.
85. FTC press release, "Retail Tracking Firm Settles FTC Charges It Misled Consumers About Opt Out Choices", 23 April 2015.
86. *Joffe v. Google, Inc.*, 729 F.3d 1262 (9th Cir. 2013), amended 746 F.3d 920; cert. denied 2014.

## Related pages

- [[how-wifi-works]] — the protocol reference behind §1 and §2.
- [[wifi-sigint-techniques]] — the same material for an analyst, technique by technique.
- [[wifi-sigint]] — the v1.1 view set (PNL, EAPOL, Seqnum, Assoc).
- [[mac-randomisation]] — the sequence-number primitive and its limits on use.
- [[non-ip-sensors]] — the BLE / sub-GHz roadmap, and why sloth never actively scans.
- [[monitor-mode]] — what the radio has to be able to do.
- [[alerts]] — `OPEN_SETUP_AP`, `CAM_SETUP_SSID`, `SURV_CLOUD_SNI`.
- [[threat-model]] — who the adversaries are from sloth's side of the antenna.
