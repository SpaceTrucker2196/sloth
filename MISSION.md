# Sloth — Mission

This file is the standing charter for the agent (human or LLM) operating
this repo. Read it before you write a line of code. It tells you
*why* sloth exists, *what it must never become*, and *where to go next*.

This repo is run as a **dark factory** — Level 5 agent autonomy: the
agent writes the code, writes the tests, runs the review. The human is
the customer and the final acceptance reviewer, not the engineer.
Everything an agent needs to continue building sloth from a cold start
is in-tree. See [`docs/dark-factory.md`](docs/dark-factory.md) for the
pattern and how to apply it elsewhere.

Operating rules live in [`CLAUDE.md`](CLAUDE.md). Architecture and
per-view depth live in [`docs/views/`](docs/views/) and
[`docs/wiki/`](docs/wiki/). This file is the mission, not the manual.

---

## 1. Mission

Sloth is a terminal-based **passive signals-intelligence (SIGINT)
console** for IP and 802.11 networks. It turns what a host already
sees — `/proc`, `/sys`, netlink, and a libpcap stream — into a live
operator view: 27 panels, six alert rules, embedded threat-intel, a
WiFi-SIGINT toolkit, and an optional JSONL forensic log.

The goal is not to *do* things on the network. The goal is to *see*
what is happening on the network, surface what is anomalous, and hand
the operator enough context to decide what to do next — out-of-band,
through other tools, under their own authority.

If a single sentence has to survive: **sloth is the eyes, not the
hands.**

---

## 2. Rules of engagement (non-negotiable)

These rules define what sloth is allowed to do. They are not preferences
and they are not negotiable per feature. If a proposed change violates
any of them, the change does not land — find another way or close the
issue.

1. **Passive only.** Sloth never injects packets, never sends probes,
   never deauthenticates, never beacons, never ARP-poisons, never
   port-scans, never resolves hosts it didn't already see. It never
   writes to the wire, and it never modifies network or host state:
   no `ip link set`, no `iptables`, no monitor-mode toggling, no
   configuration of interfaces it did not create.

   **One narrow, opt-in exception:** with passive channel-hopping
   enabled (`--hop`, off by default), sloth may retune the *channel* of
   its **own monitor-mode capture interface** — the receiver the
   operator explicitly dedicated to sloth. This changes only what sloth
   *hears*, never what the network *does*: no frame is transmitted, no
   other interface is touched, and the monitored segment is unaffected.
   Retuning a receiver is not writing to the wire. With `--hop` off
   (the default) sloth modifies no kernel state at all, preserving the
   guarantee that it can run on a sensitive segment without changing it.
   Everything else in this rule stands — no injection, no deauth, no
   probing, and sloth still never puts an interface *into* monitor mode
   (the operator does that; sloth only tunes what's already there).
   *(This carve-out was authorised by the operator on 2026-07-04 to
   enable issue #22; see PROGRESS.md.)*

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

If you are tempted to add an "active" feature because it would be
useful — port scanning the LAN, sending a deauth to test detection,
auto-cracking the captured handshake — stop. That feature belongs in a
different tool. Sloth's value is being trusted to be passive: an
operator can run sloth on a sensitive segment without changing the
segment. Lose that and the tool is just another aircrack fork.

---

## 3. Where the project is right now

As of v1.1 ("WiFi SIGINT"):

- **27 views**, keyed `[1]…[0]`, `[a]…[w]`, indexed in the README.
- **Six alert rules** in `src/alerts.c` (port scan, beacon flood,
  ARP spoof, evil twin, rogue DHCP, DGA/DNS-tunnel, weak TLS,
  attack-path HTTP, deauth flood, probe flood) — each with a row in
  [`docs/views/alerts.md`](docs/views/alerts.md).
- **WiFi SIGINT layer**: PNL aggregation, RSN/AKM/MFP inventory,
  EAPOL / PMKID / 4-way handshake capture with hashcat-22000 export,
  hidden-SSID reveal, sequence-number MAC-randomisation
  deanonymisation, KARMA / evil-twin / Pineapple detection,
  per-AP fingerprinting (PHY tier, vendor IEs, WPS state, 802.11k
  neighbour reports, RNR for 6 GHz).
- **Threat intel** matcher in `src/threat_intel.c` against an embedded
  IOC list.
- **Forensic log** (`-o file.jsonl`) and per-alert pcap export
  (`--pcap-dir DIR`).
- **~1950 test assertions**, `make test` green; `make` warning-clean.

Platforms: primary target is Linux (rtnetlink, nl80211, INET_DIAG,
`/proc`). Darwin builds the binary and the test suite cleanly via the
BSD platform stub — it is the dev/CI host, not a deployment target.
Windows and the generic POSIX stub exist as build-only placeholders.

---

## 4. Direction

In rough priority order — not a sprint plan, a sense of where the
gravity is:

1. **Detection breadth, not detection depth.** Add new alert rules and
   new passive observables before you tune the existing ones. Coverage
   beats precision until coverage exists. Every new rule needs a row
   in `docs/views/alerts.md` and a seeded-state test in
   `tests/test_alerts.c`.

2. **Operator ergonomics.** The dashboard exists to answer "is anything
   on fire?" in two seconds. Anything that helps that — better colour
   gradients on heat, sparkline density, alert-hot IP override across
   panels — is in scope. Anything that requires the operator to read a
   manual to use is not.

3. **Forensic export.** JSONL is the contract sloth has with whatever
   pipeline consumes it (Splunk, Loki, a homemade SIEM, a notebook).
   Keep the schema stable; add fields, don't rename them; document the
   shape in `docs/wiki/log.md`.

4. **WiFi SIGINT depth.** 802.11 is where most of the unique value
   lives — every commodity tool can show you TCP connections. Keep
   pushing on beacon-IE parsing, vendor fingerprints, association
   tracking, 6 GHz / Wi-Fi 7 coverage, and protocol-level anomaly
   detection that classic IDSes don't do.

5. **Test discipline.** No commit goes in red. Hand-craft protocol
   tests from RFC bytes — never a parser feeding its own output back.
   Bug fixes ship with a test that would have caught the bug.

What is **out of scope**, regardless of how interesting:

- Active reconnaissance (port scan, host sweep, OS fingerprint via
  probes).
- Frame injection of any kind.
- Online cracking, dictionary attacks, password-spray, credential
  validation.
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
2. Read [`docs/dark-factory.md`](docs/dark-factory.md) once, so you
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
something, or do something the operator hasn't asked for?** If yes,
it's out. If no, it's worth considering on the merits.

When you are unsure whether to decide or escalate, apply the autonomy
rules in [`docs/dark-factory.md`](docs/dark-factory.md): code-level
decisions are yours; anything that rewrites §2 of this file, breaks an
API consumed downstream, or touches the human's machine outside the
repo is a stop-and-ask.

---

## 6. The one-line summary you can quote

> Sloth is a passive, white-hat SIGINT console: it watches, it flags,
> it never attacks.

Anything you build on top of this codebase must still be describable
by that sentence. If it isn't, you've built a different tool — fork it
and give it a different name.
