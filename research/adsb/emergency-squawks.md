---
source_url: https://github.com/wiedehopf/readsb/blob/dev/README-json.md
retrieved: 2026-11-08
topics: [adsb, mode-s, squawk, emergency, 7500, 7600, 7700, do-260b, spoofing, false-alarm, flag-only, exemption]
alert_kinds: [ALERT_TYPE_ADSB_EMERGENCY]
citation: readsb README-json.md (DO-260B 2.2.3.2.7.8.1.1); EU 923/2012 SERA.13005; Costin & Francillon, Black Hat USA 2012; Schafer, Lenders & Martinovic, ACNS 2013
---
# ADS-B emergency squawks and status — what they mean, and why sloth only flags them

The basis for `ALERT_TYPE_ADSB_EMERGENCY` (`src/alerts/rules_adsb.c`,
#186). Read first-hand on 2026-11-08 unless a line says otherwise.

**Verdict.** The three codes and the emergency/priority status are
defined, unambiguous declarations by an aircraft's crew, which makes
them worth surfacing. They are also unauthenticated broadcasts that a
software-defined radio can forge — the literature
names this exact message as a "false alarm" attack — and a single
receiver has no second opinion. So the finding is a flag: sloth reports
what the decoder heard and takes no action, and never rates it CRIT.
There is no honest ATT&CK technique: the alert reports a third party's
declared state, not an adversary's step against the operator's network
(second exemption form, agents/AGENTS.md).

## The codes: SERA.13005 (the ICAO procedure in EU law)

Commission Implementing Regulation (EU) No 923/2012, SERA.13005 "SSR
transponder Mode A code setting", as published in the UK CAA's
regulatory library
(https://regulatorylibrary.caa.co.uk/923-2012/Content/Regs/03000_SERA13005_SSR_transponder_Mode_A_code_setting.htm):

- (a)(1): the pilot shall "select Code 7700 to indicate a state of
  emergency unless ATC has previously directed the pilot to operate the
  transponder on a specified code. In the latter case, a pilot may
  nevertheless select Code 7700 whenever there is a specific reason to
  believe that this would be the best course of action;"
- (a)(2): "select Code 7600 to indicate a state of radio-communication
  failure;"
- (a)(3): "attempt to select Code 7500 to indicate a state of unlawful
  interference. If circumstances so warrant, Code 7700 should be used
  instead."

SERA transposes the ICAO procedure; ICAO Doc 8168 (PANS-OPS) and Doc
4444 (PANS-ATM) are the international source but are not freely
published and were **not read** for this document. The FAA's AIM 4-1-20
carries the same three codes; its page returned 403 to the fetch and was
**not read** first-hand either.

What follows for the rule: exactly three codes, `7500`, `7600`, `7700`.
`7000` (a European VFR conspicuity code) and `7777` are not emergency
codes and must not fire; nor must a squawk merely beginning with 7.

## The status field: readsb's README-json.md (DO-260B)

readsb's `README-json.md` (wiedehopf/readsb, branch `dev`, read
2026-11-08), which states "Section references (2.2.xyz) refer to
DO-260B":

- "squawk: Mode A code (Squawk), encoded as 4 octal digits"
- "emergency: ADS-B emergency/priority status, a superset of the 7x00
  squawks (2.2.3.2.7.8.1.1)" with the values "(none, general, lifeguard,
  minfuel, nordo, unlawful, downed, reserved)"
- "Keys will be omitted if data is not available."
- "aircraft will only be in the aircraft json if a messages has been
  received in the last 60 seconds"

RTCA DO-260B itself is a paid standard and was **not read**; the clause
number is readsb's. What the rule takes from it: `none` and an absent
key are no condition; every other word is one, `lifeguard` (a medical
priority flight) and `minfuel` included, because they are the aircraft
declaring a priority state. "A superset of the 7x00 squawks" means the
code and the status describe one declaration, so the rule keys on the
code when there is one and on the status word otherwise, and a status
that follows its code a document later is the same incident.

That same relationship is why the rule escalates on **persistence, not
corroboration**: a status agreeing with its code is the decoder
reporting one declaration two ways, not two independent observations.

## Why it is only a flag: ADS-B has no authentication

A. Costin and A. Francillon, "Ghost in the Air(Traffic): On insecurity
of ADS-B protocol and practical attacks on ADS-B devices", Black Hat USA
2012 (EURECOM; https://s3.eurecom.fr/docs/bh12us_costin.pdf, read
2026-11-08):

- Abstract: "we demonstrate that attacks are both easy and practically
  feasible, for a moderately sophisticated attacker. Attacks range from
  passive attacks (eavesdropping) to active attacks (message jamming,
  replaying of injection)."
- §III: the main problem is "the lack security mechanisms,
  specifically: lack of entity authentication to protect against message
  injection from unauthorized entities", and "lack of message signatures
  or authentication codes to protect against tampering of messages or
  impersonating aircrafts."
- §IV: replay and impersonation were implemented with a USRP and tested
  against a commercial radio-enthusiast receiver — the class of
  receiver sloth reads.

M. Schafer, V. Lenders and I. Martinovic, "Experimental Analysis of
Attacks on Next Generation Air Traffic Communication", ACNS 2013, LNCS
7954, pp. 253-271, doi:10.1007/978-3-642-38980-1_16
(https://disco.cs.rptu.de/downloads/publicationfiles/SLM13.pdf, read
2026-11-08):

- §3.2, "False Alarm Attack": "the attacker deletes and re-injects or
  modifies messages of a real aircraft in order to indicate a fake
  alarm. Like Mode S, ADS-B provides mechanisms to indicate emergencies
  or unlawful interferences such as aircraft hijacking. Such an attack
  results in confusion and focuses the attention of responsible persons
  on the target aircraft." and "The detection of this deception on
  higher levels than the physical layer is hard, since e.g. voice radio
  must be considered to be untrustworthy in case of a hijacked
  aircraft."
- Abstract: "attacks on ADS-B can be inexpensive and highly successful
  ... any safety-critical air traffic decision process should not rely
  exclusively on the ADS-B system."

What follows for the rule: sloth sees the physical layer only through a
decoder's JSON — no signal timing, no angle of arrival, no second
receiver — so it has none of the checks the literature proposes. It
cannot tell a real 7500 from an injected one, and must say so in the
detail.

## Transients

A single receiver can also report a code nobody set. The rule's design
answer is persistence measured in the aircraft's own message time: LOW
on first sight, WARN only once the condition has held for
`adsb.emerg_hold_s` (10 s) of messages. **No source read here gives a
number** for how long a decode error or a code dialled through in
passing lasts; 10 s is a judgement — ten of readsb's one-second
documents, and long enough that one corrupted reply cannot reach WARN.
It is a knob for that reason.

## ATT&CK

No technique. The alert reports an aircraft declaring an emergency, a
third party's state that has nothing to do with the operator's network;
the adversarial reading (a forged alarm) is one sloth cannot
distinguish, and claiming it would put intent into every genuine
emergency. Listed in `tests/test_research_corpus.c ::
test_uncitable_kinds_with_a_real_basis_are_still_cited`.
