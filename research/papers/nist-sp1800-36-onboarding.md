---
source_url: https://doi.org/10.6028/NIST.SP.1800-36
retrieved: 2026-09-17
topics: [iot, onboarding, provisioning, softap, wifi-direct, credentials, exposure]
alert_kinds: [ALERT_TYPE_OPEN_SETUP_AP]
citation: NIST SP 1800-36 (NCCoE), "Trusted IoT Device Network-Layer Onboarding and Lifecycle Management", November 2025
---
# NIST SP 1800-36 — open-network IoT onboarding

The NCCoE practice guide on trusted network-layer onboarding. It exists
because the way most headless consumer and IoT devices join a WLAN today
is not trustworthy, and it names the specific mechanism sloth's
`ALERT_TYPE_OPEN_SETUP_AP` looks for.

Volume A, Executive Summary, on the state of the practice:

> Wi-Fi is sometimes used to provide credentials over an open (i.e.,
> unencrypted) network, but this onboarding method risks credential
> disclosure.

and, on why the moment matters:

> It is easy for a network to falsely identify itself, yet many IoT
> devices onboard to networks without verifying the network's identity
> and ensuring that it is their intended target network. Also, many IoT
> devices lack user interfaces, making it cumbersome to input network
> credentials manually.

## What sloth detects from this

A device with no screen and no keypad has to be told the WLAN
passphrase somehow. The common answer is that the device brings up its
own **open** SoftAP, the owner's phone joins it, and the credentials go
across that link. While the device sits in that state it is an
unauthenticated management surface reachable by anyone in RF range —
who can provision it onto a network of their choosing, read or rewrite
its configuration, or stand up the same SSID and collect the passphrase
the owner types in.

`ALERT_TYPE_OPEN_SETUP_AP` fires on the passively observable half of
that: an OPEN `beacon_ap` whose SSID matches a curated onboarding
pattern. It is **WARN**, because what is observed is the exposure, not
an attacker using it.

## No ATT&CK technique, deliberately

`alert_technique()` returns `""` for this kind. ATT&CK describes what an
adversary does; an unconfigured device in its factory onboarding state
is a victim-side posture with no adversary behaviour in evidence. The
techniques that would nearly fit each claim more than sloth saw —
T1557 (Adversary-in-the-Middle) is what an attacker sets up *after*
joining the setup AP, and T1600 (Weaken Encryption) requires crypto to
have been weakened rather than never configured. `ALERT_TYPE_BTM_ABUSE`
settled the same question the same way when it took T1498 over T1557.

This is a different case from `ALERT_TYPE_NO_MONITOR_MODE`, the repo's
other empty technique: that one reports sloth's own rig, this one
reports an observed third-party device. The basis is cited — it is
simply not an ATT&CK ID.

## Why the pattern table is small

The rule matches a short prefix table rather than anything
setup-shaped, behind an allowlist of carrier, ISP and venue hotspot
SSIDs that are open by design. Two of the rows have a normative or
vendor basis rather than a field observation:

- **`DIRECT-`** — the Wi-Fi Alliance *Wi-Fi Peer-to-Peer (P2P)
  Technical Specification* v1.5 §3.2.1 states that "Each SSID shall
  begin with the ASCII characters `DIRECT-`", and requires WPA2-PSK on
  the P2P Group in the same clause. An **open** `DIRECT-` SSID is
  therefore a device operating outside the protection its own
  specification mandates.
  (<https://cse.iitkgp.ac.in/~bivasm/sp_notes/wifi_direct_2.pdf>)
- **`HP-Setup`** — HP printers advertise `HP-Setup>xx-<model>` until
  they are joined to a WLAN, and HP's own support forum shows that
  network listed as unsecured.
  (<https://h30434.www3.hp.com/t5/Printers-Archive-Read-Only/HP-setup-network-doesn-t-appear/td-p/7909443>)

The rest come from devices seen in range on the passive run that
motivated issue #80. That provenance is weaker than a spec clause and
is recorded as such rather than dressed up: the honest claim is "this
name was observed on an open SoftAP", not "this vendor documents it".

## What it does not say

SP 1800-36 gives no detection signature — it is guidance for building
trusted onboarding (Wi-Fi Easy Connect / DPP, BRSKI, Thread
commissioning), not for spotting untrusted onboarding on the air. The
inference from "open onboarding network" to "an onboarding network is
open right now, over there" is sloth's, and the alert claims only what
was observed: an open AP whose name matches a setup pattern. Whether a
given device is mid-setup, abandoned in setup mode, or simply named
that way is the operator's call.
