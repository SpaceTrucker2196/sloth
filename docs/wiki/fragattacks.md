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

Sloth implements two of them. This page explains which, why the other
ten are harder or impossible to observe passively, and — the part worth
reading before you trust the alert — what the detector's gate actually
proves.

## The twelve

| CVE | what the receiver does wrong | passively observable? |
|---|---|---|
| 2020-24586 | does not clear the fragment cache on (re)connect | yes, needs a fragment-session table — **slice 2** |
| 2020-24587 | reassembles fragments encrypted under different keys | needs PTK-rotation visibility — **slice 4** |
| 2020-24588 | accepts non-SPP A-MSDU frames | **not as usually described** — see below |
| 2020-26139 | forwards EAPOL from an unauthenticated sender | yes, needs handshake state — slice 4 |
| 2020-26140 | accepts plaintext data frames in a protected network | **yes — shipped** |
| 2020-26141 | does not verify the TKIP MIC of fragmented frames | no (MIC is under the key) |
| 2020-26142 | processes fragmented frames as full frames | no (a receiver-side decision) |
| 2020-26143 | accepts fragmented plaintext data frames | **yes — shipped** |
| 2020-26144 | accepts plaintext A-MSDU starting with an EAPOL RFC1042 header | yes, plaintext only — not yet built |
| 2020-26145 | accepts plaintext broadcast fragments as full frames | **yes — shipped** |
| 2020-26146 | reassembles encrypted fragments with non-consecutive PNs | yes — the CCMP PN is in the clear — slice 2 |
| 2020-26147 | reassembles mixed encrypted/plaintext fragments | yes, slice 2 |

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

## Why the A-MSDU detector is not here

CVE-2020-24588 is the most cited of the family, and the detector usually
proposed for it cannot work passively.

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

The signal worth building instead: the attack replays a frame the victim
already sent, with the bit flipped. **The same sequence number appearing
twice with a differing A-MSDU bit** is specific in a way the bit alone
is not, and `src/seqnum_track.c` already tracks sequence numbers. That
is slice 3.

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
