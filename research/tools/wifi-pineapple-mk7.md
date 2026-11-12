---
source_url: https://documentation.hak5.org/wifi-pineapple/setup/connecting-to-the-wifi-pineapple-over-wifi
retrieved: 2026-11-12
topics: [pineapple, pineap, hak5, setup-ap, attack-hardware, two-radio]
alert_kinds: [ALERT_TYPE_KARMA_AP]
citation: Hak5, "Connecting to the WiFi Pineapple over WiFi", "Settings" and "Radios and Chipsets", WiFi Pineapple Mark VII documentation (documentation.hak5.org, retrieved 2026-11-12)
---
# WiFi Pineapple Mark VII: what the vendor documents about its radios

The source behind the Pineapple setup-AP pairing on `KARMA_AP` (#151
item 2, `src/attack_hw.c :: hw_pineapple_pair()`). Quotations are from
three pages of Hak5's Mark VII documentation, retrieved 2026-11-12.

## The setup access point

From "Connecting to the WiFi Pineapple over WiFi":

- "The WiFi Pineapple serves an Open AP for you to connect to for the
  purposes of completing device setup."
- "The SSID of the AP is `Pineapple_XXXX`, where the 'XXXX' is the last
  4 characters of the devices MAC address."
- "The Pineapple_XXXX network will disappear after setup is complete!"
  and "After setup is complete, the WiFi Pineapple will remove the setup
  networks".

## The radios

From "Settings": "The default recon interface is `wlan1`, the built-in
2.4GHz WiFi radio", and with a compatible USB adapter "the `wlan3`
interface will become available and can be used for scanning 2.4GHz
*and* 5GHz channels". The page names a Management Network and "the Open
and EvilWPA networks" without saying which radio carries either.

From "Radios and Chipsets": "The WiFi Pineapple Mark VII is based on
Mediatek MT7601U and MT7610U chipsets."

## How sloth uses it

A BSSID that has fired `KARMA_AP` plus a *different* live BSSID
beaconing exactly `Pineapple_` and four hex digits is a pairing. It
goes into the alert's detail (`+setup-AP Pineapple_1a2b@<bssid>`) and
into the verdict layer as the `pair` signal. It never raises an alert,
and it moves neither severity nor confidence.

## What it does not say

- **Which MAC "the devices MAC address" is.** The Mark VII has several
  interfaces, and the page does not say whether the suffix is the setup
  AP's own BSSID. sloth records whether the suffix matches either BSSID's
  low 16 bits and does not require it.
- **Anything after setup.** By the vendor's account the setup network is
  gone once setup completes, so the pairing applies only to a device
  being set up in range. A configured Pineapple has a Management Network
  with an operator-chosen SSID, and nothing here identifies that.
- **Adjacent MACs, a shared IE order, channel relations, timing.** #151
  asks about all four for the two-radio pattern. None is documented on
  these pages, so none is required or scored. They need a capture.
- **Whether PineAP and the management AP share a radio.** Not stated for
  the Mark VII. The older Nano/Tetra docs say the PineAP source MAC
  defaults to wlan0, but that is a different device, so it is not cited
  here.
