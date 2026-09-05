# FragAttacks

Mathy Vanhoef, *Fragment and Forge: Breaking Wi-Fi Through Frame
Aggregation and Fragmentation*, USENIX Security 2021.
[Paper](https://papers.mathyvanhoef.com/usenix2021.pdf) ·
[Project site](https://www.fragattacks.com/) ·
[Advisory index](https://github.com/vanhoefm/fragattacks/blob/master/ADVISORIES.md)

Twelve CVEs. Three are design flaws in 802.11 itself and affect every
device shipped since 1997; the other nine are implementation bugs. They
share one outcome: an adversary in radio range can get frames of their
choosing accepted into an encrypted WPA/WPA2/WPA3 session **without
holding the key**.

Sloth implements five of them. This page explains which, why the other
seven are harder or impossible to observe passively, and — the part
worth reading before you trust the alert — what each detector's gate
actually proves.

## The twelve

| CVE | what the receiver does wrong | passively observable? |
|---|---|---|
| 2020-24586 | does not clear the fragment cache on (re)connect | **yes — shipped, slice 2** |
| 2020-24587 | reassembles fragments encrypted under different keys | needs PTK-rotation visibility — **slice 4** |
| 2020-24588 | accepts non-SPP A-MSDU frames | **yes, sideways — shipped.** Not as usually described; see below |
| 2020-26139 | forwards EAPOL from an unauthenticated sender | yes, needs handshake state — slice 4 |
| 2020-26140 | accepts plaintext data frames in a protected network | **yes — shipped** |
| 2020-26141 | does not verify the TKIP MIC of fragmented frames | no (MIC is under the key) |
| 2020-26142 | processes fragmented frames as full frames | no (a receiver-side decision) |
| 2020-26143 | accepts fragmented plaintext data frames | **yes — shipped** |
| 2020-26144 | accepts plaintext A-MSDU starting with an EAPOL RFC1042 header | **yes, plaintext only — shipped, slice 4** |
| 2020-26145 | accepts plaintext broadcast fragments as full frames | **yes — shipped** |
| 2020-26146 | reassembles encrypted fragments with non-consecutive PNs | **not as slice 2 was originally described** — see below |
| 2020-26147 | reassembles mixed encrypted/plaintext fragments | **yes — shipped, slice 2** |

Several of these are only ever visible as the *attacker's* frames on the
air. Nothing sloth can see tells it whether the victim's driver actually
accepted them — that is a decision inside another machine. The alerts
below therefore say "this was transmitted", not "this worked".

## What sloth detects

### `FRAG_PLAINTEXT` — CVE-2020-26140 / -26143

A data frame with the Protected bit clear, carrying something other than
EAPOL, on a session where the sender's key install has already been
witnessed.

### `FRAG_BCAST` — CVE-2020-26145

A **fragmented** group-addressed data frame with Protected clear. In an
RSN, broadcast frames are never fragmented — reassembling one is the bug
— so the fragment is already a violation before anything reassembles
it. Sloth fires on the fragment rather than waiting for a completion
that only the victim can perform.

### `FRAG_CACHE` — CVE-2020-24586

The fragment cache is supposed to be cleared on every (re)association.
Sloth tracks reassembly sessions keyed on `(BSSID, SA, DA, TID)`: a
fragment with the More Fragments bit set and fragment number 0 opens a
session, and any later fragment for the same key is its continuation.

If a continuation **completes** a session that started **before** a
(re)association response sloth witnessed for either endpoint, the
completion straddles a boundary at which the buffer should have been
empty. There is no benign reading of that — it is the CVE's own failure
mode, not a threshold being crossed.

This one is deliberately **not** gated on the RSN-witnessed state
`FRAG_PLAINTEXT` and `FRAG_BCAST` use. The fragment cache exists before
decryption — an implementation's failure to clear it does not care
whether the fragments in it are plaintext or ciphertext — so the
detector fires on either.

Association timing uses a **strict** "after": a session that opens the
same second an association lands is not reported, because sloth's
one-second clock resolution cannot show which came first.

### `FRAG_MIXED` — CVE-2020-26147

The same session table catches a second, unrelated bug: a reassembly
whose fragments do not agree on the Protected bit. An all-encrypted
sequence is normal. An all-plaintext one is normal on an open network.
A sequence that starts encrypted and completes plaintext, or the
reverse, is neither — each fragment is individually unremarkable, and
the violation only exists once they are combined into one MSDU.

### Why CVE-2020-26146 is not here despite slice 1 saying "slice 2"

The CCMP packet number is transmitted in the clear (it has to be — the
receiver needs it to reconstruct the nonce), so reading it was never the
obstacle this page's earlier draft implied. The obstacle is what the PN
*is*: one counter shared by every frame sent under one key on one TID,
not a per-reassembly sequence. Two fragments of one MSDU only get
consecutive PNs if literally nothing else was transmitted on that TID
between them — which the spec expects but does not enforce — and a
retried fragment (a retry gets a fresh PN even though its fragment
number and sequence number are unchanged) opens a gap on its own. A
same-session "PN must be N+1" check built against that reality would be
noisy on exactly the ordinary multi-station traffic this detector family
is supposed to be quiet against. Left for a slice that can test the
retry case honestly, rather than shipped and found unusable in the
field.

## The gate, and why it is not the beacon

The obvious implementation is "if the beacon for this BSSID advertises
RSN, any unprotected data frame is a finding." Sloth does not do that.
The gate is per `(BSSID, station)`, and it is **ordered**: sloth must
have seen *that station* transmit a Protected frame *before* the
plaintext one.

Three reasons, and the third is the real one.

**It survives a hopping radio.** `--hop` means most BSSes are heard for
a fraction of a second at a time and the beacon may never land in the
window. A detector that needs the beacon first is silent exactly when
the radio is doing its job.

**It is per-station, so one client cannot indict another.** Association
and the 4-way handshake happen in the clear. On a busy BSS there is
almost always some station mid-association, and a per-BSS flag would
turn its perfectly normal traffic into a CRIT against the whole network.

**It is what the CVE says.** These are "accepting plaintext *after key
install*" bugs. The beacon tells you what the AP *offers*; it says
nothing about whether this station completed a handshake. A station's
own encrypted traffic is direct evidence that it did. Using the weaker
signal would produce an alert that is right about the network and wrong
about the frame.

The ordering requirement follows from the same argument and is tested
directly: plaintext seen *before* the key install is a client that had
not finished associating yet, and counting it retroactively would make
every normal association look like an attack.

## What is exempt, and why each exemption is load-bearing

| exempt | because |
|---|---|
| EAPOL (EtherType 0x888E) | rekeying is legitimately unprotected. Without this, every rekey on the network is a CRIT |
| Null / QoS-Null subtypes | no frame body at all; they are how a station signals power-save state, and they are always unprotected. Without this, every idle client fires |
| continuation fragments (FN > 0) | carry no LLC header, so an EAPOL continuation cannot be told from a data one. Counting them anyway is a guess dressed as a detection |
| non-SNAP LLC | an EtherType read out of bare LLC is invented, and an invented one that is not 0x888E makes every IPX frame a CRIT |
| four-address (WDS) frames | cross two BSSes and carry no single BSSID. Attributing them to a guess is worse than not seeing them |

The unicast rule needs the EtherType and therefore only counts frames
that say what they carry. The broadcast rule does not: fragmentation
itself is the violation and broadcast EAPOL does not exist, so it needs
no exemption at all.

### `FRAG_AMSDU` — CVE-2020-24588, detected sideways

The most cited of the family, and the detector usually proposed for it
**cannot work passively**.

The attack flips the A-MSDU Present bit on an encrypted MPDU so the
receiver reparses the payload as aggregated subframes with
attacker-chosen destinations. The natural signals — the first subframe's
DA against Address 3, the subframe length against the MPDU, the
subframe's LLC prefix — are all **inside the ciphertext**. The QoS
Control field carrying the bit is in the plaintext MAC header, so the
*bit* is visible; the body is not, and sloth does not crack
(`MISSION.md` §2).

What is left is the bit alone, which fires on any hardware that
aggregates — most of it.

**So sloth detects the replay instead.** The attacker does not forge a
frame; they capture one the victim already sent and retransmit it with
one bit changed. That makes the observable a *duplicate MPDU whose
A-MSDU bit differs*.

#### Why the packet number, not the sequence number

The #75 triage proposed keying this on the sequence number. The CCMP
packet number is strictly better and it is what shipped.

| | sequence number | CCMP PN |
|---|---|---|
| width | 12 bits | 48 bits |
| wraps | every 4096 frames — under a second at any real rate | never under one key |
| reuse | routine | a protocol violation (§12.5.3.4.4) |

A seqnum-keyed detector needs a comparison window short enough to be
evaded and long enough to false-positive. The PN has no such tension: a
repeat is *already* an anomaly before the flipped bit is considered, so
the rule is "same transmitter, same PN, different A-MSDU bit" with
nothing else propping it up.

It also has no meaning on unprotected frames, which is exactly right —
-24588 is an attack on encrypted MPDUs, and a plaintext A-MSDU is
CVE-2020-26144, a different row in the table above.

#### What it excludes, and how

- **A plain retransmission** carries the same PN *and* the same bit.
  Excluded by construction, not by a threshold — which matters, because
  retries are constant on a congested link.
- **Two radios using the same PN** is normal: they have different keys.
  The key includes the transmitter.
- **A rekey** legitimately restarts PNs from zero, so the comparison
  window is 10 seconds. The attacker replays promptly — the victim's
  replay window and fragment cache are what the attack rides, and both
  are short-lived.

This is the only FragAttacks rule here with **no key-install gate**. It
does not need one: the PN is itself proof the frame is protected.

#### Reading the PN

It is transmitted in the clear immediately after the MAC header, and the
byte order traps people:

```
PN0  PN1  rsvd  KeyID  PN2  PN3  PN4  PN5
```

Low octet first, then the *high four* after the KeyID octet. Reading
those eight bytes as a big-endian integer produces a plausible number
that is wrong, and nothing downstream would notice. Bit 5 of the KeyID
octet is the Extended IV bit; without it the frame is WEP or original
TKIP, which have no 48-bit PN at all, so the same eight bytes mean
something else entirely and `dot11_ccmp_pn()` returns -1 rather than
inventing evidence.

### `FRAG_AMSDU_EAPOL` — CVE-2020-26144, the plaintext half

`FRAG_AMSDU` above detects the *encrypted* half of the aggregation
design flaw by replay, because the subframe headers a direct check
would need are inside the ciphertext. CVE-2020-26144 is the same flaw's
other half, and it needs no such workaround: the frame is **plaintext**,
so the A-MSDU subframe header — DA(6), SA(6), Length(2), then an
ordinary LLC/SNAP — sits in the clear right where any other subframe's
would.

The check is one fact: real EAPOL is never aggregated. It is always its
own MPDU, never a subframe of one. So a plaintext A-MSDU whose first
subframe's LLC/SNAP claims EtherType `0x888E` (EAPOL) is not "unusual
aggregation" — it is a receiver being handed a subframe dressed as an
authenticator message, which is the confusion this CVE describes. There
is no threshold and no rate to tune: the claim itself is the finding.

**Same key-install gate as `FRAG_PLAINTEXT`.** This is plaintext
traffic being judged, so the same false-positive story applies for the
same reason: without evidence this station's key was already installed,
an unprotected A-MSDU is an open network or a station mid-association,
not a finding. The gate is per `(BSSID, station)` and ordered, exactly
as above.

**Only the first subframe is read.** A-MSDU subframes are each preceded
by a Length field, but trusting that field to walk to the second
subframe means trusting the exact value this attack manipulates
elsewhere in the family — reading past the first would be leaning on
the evidence to validate itself. The first subframe is also the one a
spoofed EAPOL claim would occupy, so nothing downstream of it matters
for this check.

**What is not reused from `FRAG_PLAINTEXT`'s EtherType reader.** That
function (`first_frag_ethertype()`) explicitly declines any A-MSDU
frame — an aggregated body has no single LLC header, only a run of
subframes, so treating it as one would misread the first subframe's
length or DA/SA as if they were payload. This detector's reader
(`first_amsdu_subframe_ethertype()`) is the A-MSDU-aware sibling that
function's own comment points to.

## Addressing

Every detector in this family needs to know which address field is the
BSSID, and it moves with the DS bits (§9.3.2.1, Table 9-26):

| ToDS | FromDS | addr1 | addr2 | addr3 | addr4 | |
|---|---|---|---|---|---|---|
| 0 | 0 | DA | SA | BSSID | — | IBSS |
| 0 | 1 | DA | **BSSID** | SA | — | AP → STA |
| 1 | 0 | **BSSID** | SA | DA | — | STA → AP |
| 1 | 1 | RA | TA | DA | SA | WDS / mesh |

Reading addr3 as the BSSID unconditionally is the shape that looks right
because it holds for a beacon. On a downlink frame it attributes the
traffic to the *sending station* instead of its AP, which silently
merges every station on the network into one bogus BSS. `dot11_data_addrs()`
in `src/dot11_data.c` owns this table and is tested against all four rows.

## Testing

Hand-built `uint8_t` frames per IEEE 802.11-2020 §9.2, no captures — see
`agents/AGENTS.md` § Discipline. The cases that decide whether this is
usable in the field are the *negative* ones: an open network, a client
mid-association, a rekey, an idle client sending Null frames, a QoS
frame whose LLC sits two bytes further along. A capture from a lab rig
running `fragattacks.py` would exercise none of them.

That gap is real and worth stating: these tests prove the detector
against the specification, not against what the tool actually puts on
the air. The `needs-pcap-fixture` label on #75 means exactly that —
wanted as follow-up validation, not blocking.

## See also

- [[captive-portal]] — the other detector whose false-positive story is the whole design
- `docs/views/alerts.md` — the rule table rows
- Issue #75 for the slicing and the premises that needed correcting
