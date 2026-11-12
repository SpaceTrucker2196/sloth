# sloth — agent instructions

Canonical agent instructions live in `agents/AGENTS.md`.

That folder is plaintext and public. It was git-crypt encrypted until
2026-07-28; the encryption was removed because it protected the wrong
thing. `agents/` holds operating procedure — how to converge an issue,
how the risk gate scores a diff, what the autonomy boundary is — not
secrets, and `agents/dark-factory.md` is explicitly written as a
teaching artifact for anyone adopting the pattern.

The original rationale was preventing prompt-injection contamination of
the files that steer agent behavior. Encryption did not really deliver
that: it stopped third parties *reading* the instructions, but an agent
working this repo also reads issue text, PR bodies, code comments and
README prose, all of which are wide open and are a far larger injection
surface. Hiding one small surface while leaving the large one exposed
bought little and cost every reader — including a fresh agent on a
machine without the key — the ability to see the rules it is being held
to.

The real defence is the one already in place: agent-instruction changes
are a reviewed, high-signal event. `agents/risk_score.sh` weights any
diff touching `agents/` at +40 precisely so such a change cannot arrive
quietly inside a feature commit.

## Fleet sharing: monitor data only (owner hard rule, 2026-11-12)

- Share what sloth heard in monitor mode. Never share what it learned
  through the joined network or the wire.
- Monitor radio, BLE, GNSS, ADS-B: everything they heard travels, the
  joined network's APs and stations as heard over the air included
  (owner: "anything that is thru monitor mode is game").
- ARP, DHCP, mDNS, DNS, flows, IPs, host names, the managed card's scan,
  station dump and MAC: never. A row known only that way never travels.
- Fail closed; every export names its host; the importer refuses what
  the rule forbids.
- Only the owner relaxes this. Enforcement points and the tests that
  hold it: agents/AGENTS.md, same heading;
  [ADR 0009](docs/wiki/adr/0009-fleet-monitor-only.md).

@agents/AGENTS.md
