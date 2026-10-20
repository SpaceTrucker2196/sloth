---
source_url: https://archive.hack.lu/2014/Hacklu2014_offline_bruteforce_attack_on_wps.pdf
retrieved: 2026-10-20
topics: [wps, pixie-dust, offline-bruteforce, prng, e-hash, m3, pixiewps, reaver]
alert_kinds: [ALERT_TYPE_WPS_PIXIE_PROBE, ALERT_TYPE_WPS_PIXIE_LIKELY_SUCCESS]
citation: Dominique Bongard, "Offline bruteforce attack on WiFi Protected Setup", Hack.lu 2014 (slides) — the Pixie-Dust attack
---
# Bongard 2014 — offline brute force of the WPS PIN ("Pixie Dust")

Slides by Dominique Bongard (0xcite), presented at Hack.lu 2014. This
is the primary source for the attack later implemented as `pixiewps`
and wired into `reaver -K` / `bully -d`. Quotations below are from the
retrieved PDF's text.

## The mechanism

In the registration protocol the enrollee — normally the **AP**, since
*"In the most common case, the Registrar is a station outside the WiFi
network and the Enrollee is the AP"* — commits to the two PIN halves in
M3:

    E-Hash1 = HMAC_AuthKey(E-S1 || PSK1 || PKE || PKR)
    E-Hash2 = HMAC_AuthKey(E-S2 || PSK2 || PKE || PKR)

E-S1 and E-S2 are 128-bit secret nonces. *"If we can find E-S1 and
E-S2, we can the brute force PSK1 and PSK2 offline!"* They usually come
from a PRNG, and the slides show implementations where they can be
recovered: a 32-bit-state linear congruential generator seeded with no
external entropy, with *"E-S1 and E-S2 generated right after N1"* (the
enrollee nonce, which M1 carries in the clear); a 32-bit LFSR whose
state is *"Trivial to recover … from the nonce"*; and one where *"E-S1
and E-S2 are never generated / E-S1 = E-S2 = 0x0"*.

The attack, as the slides list it:

> Do the WPS protocol up to message M3 / Get the Nonce from M1 /
> Bruteforce the state of the PRNG / Compute E-S1 and E-S2 from the
> state / Bruteforce PSK1 / PSK2 from E-Hash1 / E-Hash2 / Do the full
> WPS protocol to get the credentials

## Why sloth cites this

Two of those steps are radio traffic; everything between them is
offline. Sloth reads the two radio steps.

`ALERT_TYPE_WPS_PIXIE_PROBE` — *"up to message M3"*, then nothing. The
online attack (CERT VU#723755, `research/cert/vu-723755.md`) has to send
M4, because M4 carries R-Hash1 and R-Hash1 *is* the guess. A registrar
that receives M3 and never sends M4 has collected E-Hash1/E-Hash2 and
had no use for the rest of the run. The rule fires WARN on an attempt
that reached M1 and M3, never M4..M8 or Done, and then stayed silent
for `--tune wps.pixie_silence_s` (60 s default, owner ruling
2026-10-19).

`ALERT_TYPE_WPS_PIXIE_LIKELY_SUCCESS` — *"Do the full WPS protocol to
get the credentials."* A registration at the same AP that reaches M7
(*"E -> R M7 … Ekwk(E-S2 || Credentials)"*: the enrollee has accepted
both PIN halves and sends the network credentials), M8 or Done within
`--tune wps.pixie_success_window_s` (24 h default) after an M3-abandoned
run. CRIT. The silence window does not gate this one: the run with the
PIN can start at once.

## How the dominant tool meets these rules

Checked against reaver's source, not inferred (t6x/reaver-wps-fork-t6x
at `f9b5e15`, 2025-10-31). `src/exchange.c` sends M4 on receipt of M3
whenever M2 was sent, with no Pixie condition; `wps_registrar.c` calls
`pixie_attack()` while processing M3; `src/pixie.c` on success calls
`set_pin()` and replaces `wps->dev_password` with the cracked PIN, so
the same exchange's M4 already carries the right R-Hash1 and the run
goes on to M8. So:

- **`reaver -K` success is one continuous M1..M8 attempt** and neither
  rule fires on it. It looks like an ordinary enrolment.
- `WPS_PIXIE_PROBE` matches reaver when `pixiewps` **fails**
  (`send_wsc_nack(); exit(1)`) or **outlasts the receive timeout**
  (a silent NACK, then `exit(0)` with *"Send pin with -p"*), and any
  offline crack run separately from saved M1/M3. That is, it detects
  failed, timed-out or deferred attempts.
- `WPS_PIXIE_LIKELY_SUCCESS` matches the second half of the deferred
  case: the later run with `-p PIN`.

`bully` and OneShot were not checked and nothing here claims either
way. The signal reaver's success does leave is timing: M4 waits for
`pixiewps`, seconds, where an online run answers M3 within one EAP
round trip. A rule on that gap is a follow-up, not built; it would need
its own threshold and source.

## Misattribution

An online brute force (VU#723755) where the sensor missed a single M4
records that refused guess as an M3 abandon — with about a second of
quiet, so `WPS_PIXIE_PROBE` stays silent — and when the brute force
later succeeds `WPS_PIXIE_LIKELY_SUCCESS` fires. The CRIT is right (the
PSK is gone) but the attack is not Pixie-Dust. The tracker counts
closed attempts that reached M4 without the credentials (`guess_n`),
and when the probing station has any, the detail says it may be an
online brute force rather than Pixie-Dust.

## What it does not let sloth say

Whether a given AP's PRNG is weak. That is decided by the AP's
firmware, which the radio does not reveal, and the slides are explicit
that it cannot be read off the brand: *"Many of the implementations are
the reference code for the chipset / Only the GUI is reskinned /
Therefore many brands are affected / Many vendors use different
chipset"*. So both rules report a **sequence that corroborates** the
attack — never a confirmed compromise (owner standard, #145 ruling 2).
The benign trigger for both is a receiver gap: a channel-hopping radio
that left after M3 of a legitimate enrolment sees the same shape. The
success rule has a second, misattributed trigger, above: a successful
online brute force with one missed M4.

## The weak-RNG chipset watchlist is struck

Issue #82 proposed shipping a watchlist of chipsets with weak WPS
nonces, conditional on this source counting as primary for it (owner
ruling 2026-10-19, under #145 ruling 2: no watchlist row without a
primary source). It does not. The slides show the flawed generators
as code and name chipset vendors only in passing — a quoted press line
that *"Broadcom chips are affected"*, and Marvell, Realtek, Intel and
Qualcomm listed under *"It's complicated"* — and give no identifier
sloth can observe on the air (OUI, WPS Manufacturer / Model attributes,
firmware version) mapped to any generator. The same slide says brands reskin reference code and mix
chipsets, which is the reason such a mapping cannot be inferred either.
The `pixiewps` tool's internal mode table is an implementation, not a
publication of which products are affected. With no primary source for
any row, the watchlist ships empty — which is to say it does not ship.

## Related

- `research/cert/vu-723755.md` — the online PIN brute force this
  attack makes unnecessary
- `research/mitre/T1110.md` — T1110.002 Password Cracking, the
  technique both rules map to
