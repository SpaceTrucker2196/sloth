# Sloth — Mission

This file is the standing charter for the agent (human or LLM) operating
this repo. Read it before you write a line of code. It tells you
*why* sloth exists, *what it must never become*, and *where to go next*.

This repo is run as a **dark factory** — Level 5 agent autonomy: the
agent writes the code, writes the tests, runs the review. The human is
the customer and the final acceptance reviewer, not the engineer.
Everything an agent needs to continue building sloth from a cold start
is in-tree. See [`agents/dark-factory.md`](agents/dark-factory.md) for the
pattern and how to apply it elsewhere.

Operating rules live in [`CLAUDE.md`](CLAUDE.md). Architecture and
per-view depth live in [`docs/views/`](docs/views/) and
[`docs/wiki/`](docs/wiki/). This file is the mission, not the manual.

---

## 1. Mission

Sloth is an open intelligence tool for RF signals intelligence:
**Citizen Signals Intelligence (Citizen SIGINT)**. It is a
receive-only tool that lets a private citizen see and understand the
radio spectrum around them: Wi-Fi, Bluetooth and Bluetooth Low Energy,
ADS-B, APRS, GNSS, wideband SDR sweeps, and the host network the
sensor is attached to.

"Open" describes the method. Every alert rule, the sources it rests on
and a written assessment of what it can and cannot show are in this
repository, so an operator can check a finding instead of trusting it.
The code is source-available under the
[Sloth Source-Available License](LICENSE), which is not an open-source
licence.

Sloth has three aims:

1. **Identify and characterise emitters.** Say what is transmitting
   near the sensor, what kind of device it is, how it behaves on the
   air, and where it is or how it moves relative to the sensor.
2. **Detect hostile or anomalous activity aimed at the operator's own
   networks.** Evil twins, deauthentication and association floods,
   KARMA lures, rogue DHCP, ARP spoofing, GNSS jamming and spoofing,
   attack-tool fingerprints, and other departures from what the site
   normally hears.
3. **Report in a disciplined intelligence style.** A finding is an
   assessment, not a verdict. Each alert rule has a written assessment
   with cited sources, a severity and a false-positive judgement. Each
   finding carries its own quality: whether the evidence is complete,
   how late it is, how many radios corroborate it, and the state of its
   source. The Wi-Fi impersonation rules carry a confidence separate
   from severity. Reports say what the sensor could not see as well as
   what it saw.

The means are <!-- count:views -->37<!-- /count --> live views, <!-- count:rules -->101<!-- /count --> alert rules, a JSONL stream,
local SQLite stores and written reports (§3). The goal is not to *do*
things to the spectrum or the network. The goal is to *see* what is
there, surface what is hostile or anomalous, and hand the operator
enough context to decide what to do next — out-of-band, through other
tools, under their own authority.

If a single sentence has to survive: **sloth is the eyes, not the
hands.**

*(Mission rewritten 2026-11-26 under the operator's explicit
authorisation of that date — the charter is never the agent's to change
on its own (agents/dark-factory.md §4.3). It replaces the "passive
SIGINT console for IP, 802.11 and Bluetooth" mission. Rules 1–5 of §2 are
unchanged; rule 6 and "Lawful and ethical use" are added.)*

---

## 2. Rules of engagement (non-negotiable)

These rules define what sloth is allowed to do. They are not preferences
and they are not negotiable per feature. If a proposed change violates
any of them, the change does not land — find another way or close the
issue.

1. **No injection.** Sloth never crafts and sends a frame onto a network
   it is monitoring. No injected packets, no probe requests, no
   deauthentication, no beacons, no ARP poisoning. This is the whole of
   the rule, and it is absolute: there is no flag, no build option and no
   deployment mode that turns it off, and no observation is worth
   acquiring by transmitting onto the segment under observation.

   It is also the *only* absolute here, which is a change from how this
   section used to read. Sloth previously claimed never to scan, never to
   resolve a host it had not already seen, and never to modify network or
   host state. Those were not kept: `--hop` retunes sloth's own receiver,
   `--allow-active` sends a reverse-DNS query and asks the kernel to
   scan, a routable `--data-socket` publishes an mDNS service file, and
   **opening a capture handle sets promiscuous mode on whatever interface
   libpcap opened** — that last one behind no flag at all. Each of the
   first three arrived as a separate "narrow exception"; the fourth was
   never noticed in this document. Four is the point at which the
   exceptions have become the rule.

   So the line is drawn where it can actually be held. **Optional
   services may use the network.** A resolver, a scan trigger, a
   telemetry socket, an mDNS advertisement, a local web interface — these
   transmit from the host, over paths the operator configured, and none
   of them puts a frame on the monitored segment. What sloth *observes*,
   it observes passively; what sloth *offers*, it may offer over the
   network like any other daemon.

   Two properties still hold, and they are what "passive" is now worth:

   - **Sloth never puts an interface into monitor mode.** The operator
     does that. Sloth only tunes a receiver already in it, and only its
     own.
   - **Every network-using service is opt-in and announced.** None is on
     by default; `--allow-active` prints on stderr exactly what it
     enabled; `--strict` locks the active behaviours off for the run and
     refuses a routable `--data-socket`. A passive tool that quietly
     becomes active is the failure this section exists to prevent, and
     that failure is about silence, not about capability.

   Promiscuous mode is the one write that is neither opt-in nor
   announced, because it is inherent to capturing at all: libpcap sets it
   when the handle opens. It changes what sloth's own NIC accepts, never
   what the segment carries. Stated here so the list is complete rather
   than comfortable.

   **Bluetooth is held to the same rule.** On Bluetooth Classic and Low
   Energy a receiver is used only to receive: no inquiry, no active
   scanning (no SCAN_REQ), no connection, pairing or GATT read, no
   advertising, and no Ubertooth transmit, interference or jamming mode.
   A host controller is listened to through a passive scan the operator
   started, or a capture stream; an Ubertooth is driven only in its
   receive and follow modes. *(Scope widened to Bluetooth and BLE, with
   Ubertooth support, on 2026-10-21 under the operator's explicit
   instruction; see #144.)*

   *(Rule rewritten 2026-10-14. Drafted by the agent on #84 and applied
   under the operator's explicit authorisation of that date — the charter
   is never the agent's to change on its own (agents/dark-factory.md
   §4.3). Consolidates the carve-outs of 2026-07-04 (#22), 2026-07-05
   (#29) and the `--allow-active` behaviour of #84.)*

   *(A longer dwell that follows a finding is inside this rule, not a new
   exception: `--cue` lets six fixed 802.11 findings hold the `--hop`
   scheduler on the channel they were heard on, which retunes only
   sloth's own receiver, as the #22 carve-out does, and puts nothing on
   the segment. Off by default, announced, refused under `--strict`.
   Recorded under the operator's explicit authorisation of 2026-11-23,
   #248.)*

2. **No active key recovery.** Sloth never runs a passphrase against a
   captured handshake. It never calls `hashcat`, `aircrack-ng`, John,
   or any cracking library. It never decrypts a frame it captured. It
   captures EAPOL/PMKID material and exports it in
   hashcat-22000 format *so the operator can run a crack themselves,
   offline, on hardware they own, against a target they are authorised
   to test*. That step is the operator's responsibility, on the
   operator's clock, with the operator's legal cover — not sloth's.

3. **Vulnerabilities are flagged, not exploited.** Sloth detects WEP,
   WPA-TKIP, MFP-off, weak TLS, attack-tool user-agents, evil twins,
   rogue DHCP, DGA-style DNS, deauth floods, KARMA/Pineapple
   behaviour, dnscat/iodine tunnels, ARP spoofing, and similar. The
   detection emits an alert and (optionally) a per-flow pcap snippet.
   It never follows up with an active step — no MITM, no session
   hijack, no replay, no credential harvesting.

4. **White hat only.** Sloth is built for: defenders monitoring their
   own networks, blue teams running authorised SIGINT in a SOC,
   incident responders triaging a compromised host, researchers in a
   lab they own, CTF and training environments, and security-aware
   travellers who want to know what the café Wi-Fi is doing. It is not
   built for surveillance of third parties, harassment, stalking, or
   any operation against a network the operator does not have explicit
   written authority to observe.

5. **Operator owns the consequences.** Sloth surfaces information.
   What the operator does with that information — file an incident,
   reconfigure an AP, brief a client, walk away — is outside sloth's
   scope. The tool is honest about what it sees and silent about what
   to do.

6. **Radios, not people.** Sloth reports that a device is present, how
   it behaves technically, and where it is or how it moves relative to
   the sensor. It never infers who uses a device, or that person's
   activity, purpose or routine. A correlation across MAC rotations is a
   hypothesis about a radio, never an identification of a person (#94);
   a presence verdict says a device stayed or passed, not who carried
   it. A feature whose output is a statement about a person is out of
   scope, however it is phrased.

   *(Principle set by the operator on 2026-11-25; recorded here under
   the operator's explicit authorisation of 2026-11-26
   (agents/dark-factory.md §4.3).)*

If you are tempted to add an "active" feature because it would be
useful — port scanning the LAN, sending a deauth to test detection,
auto-cracking the captured handshake — stop. That feature belongs in a
different tool. Sloth's value is being trusted to be passive: an
operator can run sloth on a sensitive segment without changing the
segment. Lose that and the tool is just another aircrack fork.

### Lawful and ethical use

The rules above are how sloth is built. These are the terms it is
built to be used on:

- **Receive only.** The sensor transmits nothing onto what it watches
  (rule 1). The one sloth-family program that transmits, `sloth-va`,
  connects only to the operator's own listed Victron devices, is off
  by default, and is kept out of the sensor
  ([ADR 0011](docs/wiki/adr/0011-sloth-va-transmits.md)).
- **No decryption and no content interception.** Sloth never decrypts
  a frame it captured and never breaks the encryption of anyone's
  traffic (rule 2). On the traffic the sensor host carries, its
  decoders keep the protocol metadata a detection needs (names,
  versions, fingerprints, HTTP request lines), not the messages
  themselves; a credential seen in clear text is recorded as an
  exposure with its user name and never its password. `sloth-va`
  decrypts only the operator's own devices' readings, with the
  operator's own keys.
- **No key recovery.** Sloth runs no passphrase against anything
  (rule 2). Exporting handshake material is opt-in and is for networks
  the operator is authorised to test.
- **Only what is broadcast in the clear.** Over the air, sloth reads
  what transmitters send unencrypted: beacons, probes, advertisements,
  aircraft and APRS position reports, satellite signals, spectrum
  power. On the wire it reads what the sensor host itself carries.
- **Minimise third-party identifiers in shared output.** Before a
  report, a capture or a screenshot leaves the operator's hands,
  remove the MAC addresses, network names and call signs of devices
  that are not the operator's. Sloth's own sharing paths already hold
  some back (ADR 0006, ADR 0009); the rest is the operator's job.
- **The law where you are is your responsibility.** Receiving,
  recording and sharing radio signals is regulated. In the U.S. that
  includes, for example, FCC rules and the Electronic Communications
  Privacy Act (ECPA); other countries have their own. This charter is
  not legal advice.

---

## 3. Where the project is right now

As of v1.8.7 (`SLOTH_VERSION` in `include/sloth.h` is the source of
truth for this number; if the two disagree, the `#define` is right).
Everything below ships; anything only planned is in §4.

**The sensor is two daemons from one tree** (ADR 0010), plus helpers.
Every unit is in `packaging/systemd/`; `make install-service` installs
them and enables none.

| Program | Unit | What it receives |
|---|---|---|
| `sloth-wifi` (`sloth` is a symlink to it) | `sloth-sensor.service` | the 802.11 monitor radio (with `--hop`), the host's IP traffic through libpcap, `/proc`, netlink and nl80211, BLE advertisements through the HCI monitor channel or an Ubertooth capture, and a GNSS receiver for the sensor's own position. Owns the terminal views. |
| `sloth-rf` | `sloth-rf.service` | headless; reads what decoders the operator already runs write: ADS-B from readsb (`aircraft.json`, SBS or Beast), APRS from Dire Wolf's packet log, rtl_433's event log, Victron readings from `sloth-va`, and GNSS through gpsd or a serial receiver. Opens no capture and no radio. |
| `sloth-ble-scan` | `sloth-ble-scan.service` | holds a passive LE scan (no SCAN_REQ) so `sloth-wifi` can hear advertisements. |
| `sloth-sdrsweep` | `sloth-sdrsweep.service`, `.path`, `-auto.timer` | a receive-only power sweep of a SoapySDR device (about a minute), for slothweb's Spectrum tab. Built only where SoapySDR is installed. |
| `sloth-va` | `sloth-va.service` | the operator's own Victron devices. **It transmits** (LE connections and pairing with the listed devices only) and is kept out of the sensor (ADR 0011). |

**Three repositories** (ADR 0001):

- **sloth** (this one, public): both daemons and the helpers, the alert
  rules, the research corpus (`research/`, `research.db`) and the alert
  assessments, the JSONL stream, `sloth.db` and `sloth-rf.db`, and the
  contract (`make contract`) the other two build against.
- **sloth-mesh** (private): `slothweb`, the browser dashboard over both
  daemons, its `slothweb.db` (triage, incidents, baselines, fleet), and
  `slothweb-mcp`. Described here in
  [`docs/wiki/slothweb.md`](docs/wiki/slothweb.md).
- **sloth-comint** (private): the intelligence packs (OUI names,
  attacker-tool OUIs, camera vendors, surveillance endpoints, tool
  signatures, the BLE watchlist, vendor research) and `sloth-comintd`.
  This tree builds from a pinned snapshot in `intel/`.

**Detection and views:**

- **<!-- count:views -->37<!-- /count --> views** (`VIEW_COUNT`, `sloth-wifi`'s; `sloth-rf` is headless), keyed
  `[1]…[0]`, `[a]…[z]`, `[?]` (help), `[*]` (BLE) and `[#]` (GNSS), indexed in
  [`docs/wiki/views-catalog.md`](docs/wiki/views-catalog.md).
- **<!-- count:rules -->101<!-- /count --> alert rules** in `src/alerts/` — one per `ALERT_TYPE_*`;
  `sloth-wifi` raises <!-- count:rules-wifi -->96<!-- /count --> of the kinds and `sloth-rf`
  <!-- count:rules-rf -->6<!-- /count --> (the GNSS rules, `ADSB_EMERGENCY` and its own
  `SENSOR_SOURCE_DOWN`). Each has a row in
  [`docs/views/alerts.md`](docs/views/alerts.md), a cited basis in
  `research/` (enforced by `tests/test_research_corpus.c`) and a written
  assessment in
  [`docs/wiki/alert-assessments/`](docs/wiki/alert-assessments/README.md).
- **Wi-Fi SIGINT**: PNL aggregation, RSN/AKM/MFP inventory, EAPOL /
  PMKID capture with opt-in hashcat-22000 export, hidden-SSID reveal,
  scored sequence-number correlation across MAC rotations (a hypothesis
  about a radio, never an identification of a person — #94), KARMA /
  evil-twin / Pineapple detection, per-AP fingerprinting, presence
  (passing versus staying), and passive cueing of the hop scheduler.
- **Finding quality and coverage**: each rule's observable / partly /
  blind status for the present configuration, and on each finding its
  completeness, latency, corroboration and source state
  ([`docs/wiki/coverage-assessment.md`](docs/wiki/coverage-assessment.md)).
- **Threat intel** matcher in `src/threat_intel.c` against an embedded
  IOC list that is **synthetic demo data, not a feed** — so
  `THREAT_DOMAIN` / `THREAT_IP` detect nothing until an operator
  replaces it. Sloth ships no feed and cannot fetch one (§2).

**Stores and outputs:** `sloth.db` and `sloth-rf.db` (SQLite, bounded,
tiered retention), the JSONL stream (`-o`, and the read-only data
socket each daemon serves; additive only), per-alert pcaps with
evidence manifests, an optional hash chain over the `-o` file
(`--jsonl-chain`, checked by `--verify`), and written
products: the posture report (`--report`, `--report-json`) with its
collection-coverage and exposure sections, `--preflight`, the site
handoff packet (`--handoff`) and the interference report.

**Testing:** `make test` is green and `make gate` runs the whole build
matrix, the sanitizers, fuzzing and the contract checks. Quote an
assertion count only when measured (agents/AGENTS.md).

Platforms: primary target is Linux (rtnetlink, nl80211, INET_DIAG,
`/proc`). Darwin builds the binary and the test suite cleanly via the
BSD platform stub — it is the dev/CI host, not a deployment target.
Windows and the generic POSIX stub exist as build-only placeholders.

---

## 4. Direction

In rough priority order — not a sprint plan, a sense of where the
gravity is. Items are planned, not shipped; [`ROADMAP.md`](ROADMAP.md)
and the open issues track them.

1. **Detection breadth, not detection depth.** Add new alert rules and
   new passive observables before you tune the existing ones, in every
   signal domain, not only Wi-Fi. Coverage beats precision until
   coverage exists. Every new rule needs a row in
   `docs/views/alerts.md`, a seeded-state test in `tests/test_alerts.c`
   and a written assessment.

2. **Intelligence discipline.** Make the collection method explicit
   (#241, after FM 2-0 Chapter 1): site questions tied to the rules that
   answer them (#244), a finding lifecycle with a preliminary state,
   confirm or withdraw, and a value time limit (#245), and a
   time-limited sweep of a room or site that reports each emitter
   against the baseline (#249). Coverage assessment, passive cueing,
   finding quality and the exposure report have shipped from the same
   programme.

3. **Operator ergonomics.** The dashboard exists to answer "is anything
   on fire?" in two seconds. Anything that helps that — better colour
   gradients on heat, sparkline density, alert-hot IP override across
   panels — is in scope. Anything that requires the operator to read a
   manual to use is not.

4. **Forensic export.** JSONL is the contract sloth has with whatever
   pipeline consumes it (Splunk, Loki, a homemade SIEM, a notebook).
   Keep the schema stable; add fields, don't rename them; document the
   shape in `docs/wiki/jsonl-schema.md`.

5. **RF depth.** Wi-Fi is still where most of the unique value lives:
   keep pushing on beacon-IE parsing, vendor fingerprints, association
   tracking, 6 GHz / Wi-Fi 7 coverage and protocol-level anomaly
   detection. Beyond it: a passive Dire Wolf receive input for APRS
   (#254), site epochs for a sensor that moves (#256), and pairing a
   device's BLE and Wi-Fi identities (#156) or grouping its rotating
   MACs (#229) — each a statement about a radio, under rule 6.

6. **Validation.** Prove the passive contract over the air and at the
   host's egress (#147), and fill the fingerprint tables that need real
   captures (#151, #201).

7. **Test discipline.** No commit goes in red. Hand-craft protocol
   tests from RFC bytes — never a parser feeding its own output back.
   Bug fixes ship with a test that would have caught the bug.

What is **out of scope**, regardless of how interesting:

- Active reconnaissance (port scan, host sweep, OS fingerprint via
  probes).
- Frame injection of any kind.
- Online cracking, dictionary attacks, password-spray, credential
  validation.
- Decrypting anyone else's traffic.
- Identifying, profiling or following a person (§2 rule 6).
- Network configuration (DHCP server, DNS resolver, firewall rules).
- Any "honeypot" mode that responds to inbound traffic.
- **Remote-control** surfaces of any kind. No command channel, no
  "do X" RPC, no inbound-configuration endpoint, no plugin loader, no
  shell-out. Sloth refuses to act on instructions it receives over the
  network — the operator drives sloth from the local TTY or not at all.

A **read-only local data socket** (UNIX domain or `127.0.0.1`) that
streams the same content as the JSONL log is in scope. It is a
`tail -f` for in-process consumers, not an API: no verbs, no auth
surface that could be brute-forced, no remote bind by default. If a
SOC needs to aggregate across hosts, a local consumer reads the socket
(or the JSONL file) and ships upstream — that consumer is not part of
sloth. Any feature that adds a *control* surface, even if dressed up as
"configuration", lands as a rejected change.

---

## 5. How to operate the repo (cold start)

The expectation is that you can resume from zero: a fresh clone, no
memory of prior conversations, no tribal knowledge. If something is
needed and not in-tree, that's a defect — fix it as part of your work.

1. Read [`CLAUDE.md`](CLAUDE.md) — operating manual: build discipline,
   conventions, "how to add a view", "how to add an alert rule", hard
   don'ts.
2. Read [`agents/dark-factory.md`](agents/dark-factory.md) once, so you
   know the autonomy contract you're operating under (when you decide,
   when you stop and ask).
3. Run `make && make test`. Both must be green before you change a
   line. If either is red on `main`, fix that first — never build on a
   broken base.
4. Read [`docs/views/README.md`](docs/views/README.md) for the per-view
   template, then skim the views relevant to whatever you're touching.
5. Look at recent commits (`git log --oneline -30`) to see cadence and
   the *kind* of change that lands here.
6. Pick the next thing from §4 or from open issues. Land it as one
   commit per logical change, imperative subject line, body explaining
   *why*, `Co-Authored-By` trailer.

When you are unsure whether a feature is in scope, apply the test from
§2: **does this change require sloth to write to the network, decrypt
something, say something about a person rather than a radio, or do
something the operator hasn't asked for?** If yes, it's out. If no,
it's worth considering on the merits.

When you are unsure whether to decide or escalate, apply the autonomy
rules in [`agents/dark-factory.md`](agents/dark-factory.md): code-level
decisions are yours; anything that rewrites §2 of this file, breaks an
API consumed downstream, or touches the human's machine outside the
repo is a stop-and-ask.

---

## 6. The one-line summary you can quote

> Sloth is an open, receive-only Citizen SIGINT tool: it watches the
> spectrum, it flags what is hostile, it reports radios, not people,
> and it never attacks.

Anything you build on top of this codebase must still be describable
by that sentence. If it isn't, you've built a different tool — fork it
and give it a different name.
