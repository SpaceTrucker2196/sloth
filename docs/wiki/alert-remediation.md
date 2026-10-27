# Alert remediation

**Summary**: how to investigate and fix every alert type sloth raises,
one section per `ALERT_TYPE_*`, each step grounded in a source the
research corpus already cites for that type. slothweb's alert detail
page shows the section for the alert being read (built into the binary
by `web/tools/alertkb.c`, never copied by hand).

**Sources**: `include/sloth_alerts.def` (the types), `research/` (every
step's basis; each section names its own), `docs/wiki/alerts.md` and
`docs/views/alerts.md` (what each rule fires on).

**Last updated**: 2026-10-26 (the last two unconditioned "locate and
remove" steps made conditional on the premises, as the rest are;
review: WEAK_TLS aimed at the client
that offered the old version; every on-device step conditional on the
device being the operator's; ROGUE_DHCP and ROGUE_RA ask first whether
the network is meant to have more than one; TPC's legacy step replaced
by the source's residual causes; steps that read a withheld detail say
where it is shown; BLE_ADV_FLOOD's vendor line held to its source.
Earlier the same day the first version, all 90 types)

## How to read a section

Each section has the same four parts:

- **Investigate**: what to check before acting, starting with the benign
  causes the cited source names. sloth is a passive receiver; nothing
  here asks it to send anything, and every step is something the
  operator does on their own equipment. A step that acts on a device is
  conditional on that device being the operator's: one that is not
  (a neighbour's access point, a camera on someone else's premises) is
  reported to whoever controls it, and never joined, probed or
  configured from here.
- **Fix**: what removes the exposure or stops the behaviour, where the
  source says so.
- **Vendor fix**: whether a patch exists. Where the source names none,
  the line says "none" and what mitigates instead; it never invents an
  advisory.
- **Sources**: the corpus documents the steps rest on, by path. Each one
  lists the type in its `alert_kinds` frontmatter, and
  `web/tests/test_alertkb.c` fails the build's tests if a section cites
  a document that does not, or a type has no section. The two
  own-operational-state types (`NO_MONITOR_MODE`, `BT_OWN_TRANSMIT`)
  have no corpus document by design (`agents/AGENTS.md`, *Detectors cite
  their sources*) and cite sloth's own pages instead.

A step that says "the source does not say" is the honest answer; the
operator's own logs are usually where the rest of the answer lives.

slothweb withholds the detail of every type whose detail can carry a
credential or a remote's free text (`web/src/web_alertfmt.h`). A step
that reads the detail of such a type points at the TUI's Alerts view,
which shows it, or at the fields the alert's page does show.

## `PORT_SCAN`

**Investigate**

1. Look at the scanning address: a source on the public internet scanning
   an exposed host is background traffic, not a finding; one inside the
   network, or one aimed at the operator's own hosts specifically, is.
2. Check whether the source is the operator's own vulnerability scanner
   or monitoring, and whether the scan coincides with a scheduled job.
3. Read the other alerts on the same address (`ATTACK_PATH`,
   `ATTACK_TOOL_UA`, brute-force rules) for what followed the scan.

**Fix**

1. The source names no fix: scanning is reconnaissance, early rather
   than urgent. Act on what followed it.
2. If the scanner is inside the network and not the operator's, isolate
   the host and find out what is running on it.

**Vendor fix:** none; scanning is a behaviour, not a vulnerability.
Mitigate by acting on the follow-on alerts.

Sources: `research/mitre/T1595.md`

## `DEAUTH_FLOOD`

**Investigate**

1. Note the victim and BSSID in the detail: the transmitter address in a
   deauthentication frame is whatever the sender claims, so it does not
   name the attacker.
2. Check whether the targeted clients actually dropped off (the AP's own
   logs); a client using management-frame protection ignores
   unprotected deauthentication frames.
3. Look for the shapes that replace deauth once MFP is on:
   `SA_QUERY_FLOOD` and `BTM_ABUSE` on the same BSSID.

**Fix**

1. Turn on management-frame protection (802.11w / PMF) and make it
   required where every client supports it; the source states MFP
   defeats spoofed deauthentication.

**Vendor fix:** none for the protocol behaviour; mitigate by requiring
management-frame protection.

Sources: `research/mitre/T1498.md`

## `NXDOMAIN_BURST`

**Investigate**

1. Identify the querying host and the names that failed: a burst of
   non-existent names is what a DGA or a DNS tunnel produces
   incidentally, but also what a misconfigured search domain produces.
2. Read `DGA_DOMAIN`, `DNS_TUNNEL` and `BEACONING` on the same host;
   the burst alone is a shape, not an intent.

**Fix**

1. If the names are generated, treat the host as possibly infected:
   isolate it and examine it.
2. If they are a configuration error, fix the resolver or search-domain
   setting that produces them.

**Vendor fix:** none; mitigate on the host that queries.

Sources: `research/mitre/T1071-004.md`

## `THREAT_DOMAIN`

**Investigate**

1. Confirm the host that looked the name up and whether a connection to
   the answer followed.
2. Remember the shipped IOC list is synthetic demo data; on a real
   deployment, check how current the list is. The source warns that
   indicators go stale in both directions: a sinkholed domain becomes a
   good thing to see resolved.

**Fix**

1. If the indicator is current, isolate the host and investigate what
   made the lookup.
2. Block the name at the resolver if it is confirmed hostile.

**Vendor fix:** none; this is an indicator match.

Sources: `research/mitre/T1071-004.md`

## `THREAT_IP`

**Investigate**

1. Identify the local host and the remote address and port.
2. Check how current the indicator is: addresses are re-allocated, and a
   match says the address was on a list, not that it is hostile now.
3. Read `BEACONING` on the same pair: a periodic connection to a listed
   address is stronger than either alone.

**Fix**

1. If the indicator is current, isolate the host and investigate.
2. Block the address at the perimeter.

**Vendor fix:** none; this is an indicator match.

Sources: `research/mitre/T1071-004.md`

## `BEACONING`

**Investigate**

1. Identify the destination: update checkers, telemetry and NTP-like
   services beacon by design, so the destination matters more than the
   rhythm.
2. Read the alert beside `THREAT_IP` and `THREAT_DOMAIN` for the same
   destination, as the source recommends.
3. Find the process on the local host that holds the connection.

**Fix**

1. If the destination is not a known service, isolate the host and
   examine the process.
2. If it is a known service, note it so the next occurrence is read
   against it.

**Vendor fix:** none; periodicity is a behaviour.

Sources: `research/mitre/T1071-004.md`

## `DGA_DOMAIN`

**Investigate**

1. Look at the name and the host that queried it. A DGA score is not a
   verdict: short random-looking names are also a naming fashion, and
   some real DGAs use wordlists that score well.
2. Check whether the host also produced `NXDOMAIN_BURST`: generated
   names mostly do not exist.

**Fix**

1. If several generated names come from one host, isolate it and examine
   it for malware.
2. Block confirmed names at the resolver.

**Vendor fix:** none; mitigate on the host.

Sources: `research/mitre/T1071-004.md`

## `ARP_SPOOF`

**Investigate**

1. Rule out the benign causes the source names: a DHCP lease reassigned
   to another machine, VRRP / HSRP / keepalived failover moving an
   address on purpose, a laptop switching between wired and wireless.
2. Check whether the address claimed is the gateway's: that is the case
   where the segment's traffic is redirected.
3. Find the port the new MAC is on (switch tables) and the device behind
   it.

**Fix**

1. Enable dynamic ARP inspection on the switch; the source names it as
   the fix most networks do not deploy.
2. Pin the gateway's ARP entry statically on hosts that matter; a static
   entry is unaffected by poisoning.
3. Remove the device that answered falsely.

**Vendor fix:** none for ARP itself, which has no authentication;
mitigate with dynamic ARP inspection.

Sources: `research/mitre/T1557-002.md`

## `ROGUE_DHCP`

**Investigate**

1. Check whether the network is meant to have more than one DHCP server:
   the rule fires on any two, with no baseline, so a failover pair or a
   split scope (two servers by design) raises it too.
2. List the DHCP servers in the detail and identify the ones the network
   is meant to have.
3. Find any other server's port and device: a home router plugged in
   backwards is the ordinary case, a host handing out a rogue gateway or
   resolver is the adversary-in-the-middle case.

**Fix**

1. If a server is not one the network is meant to have, and the device
   is the operator's, disconnect or reconfigure it; if it is not the
   operator's, report it to whoever runs the network segment. Leave a
   designed failover pair as it is.

**Vendor fix:** none; the source names no network-side control.
Mitigate by removing the unintended server.

Sources: `research/mitre/T1557.md`

## `ROGUE_RA`

**Investigate**

1. Check whether the network is meant to have more than one IPv6 router:
   the rule fires on any two, with no baseline, so redundant routers (a
   first-hop redundancy pair, two uplinks) raise it too.
2. List the IPv6 routers in the detail and identify the ones the network
   is meant to have.
3. Find any other device sending advertisements and what prefix and
   resolver it announces.

**Fix**

1. If a router is not one the network is meant to have, and the device
   is the operator's, disconnect or reconfigure it; if it is not the
   operator's, report it to whoever runs the network segment. Leave
   designed redundant routers as they are.

**Vendor fix:** none; the source names no network-side control.
Mitigate by removing the unintended router.

Sources: `research/mitre/T1557.md`

## `SMB1_USE`

**Investigate**

1. Identify the client and the server that negotiated SMBv1: the source
   says it is almost always a legacy device doing its job, not an
   exploit in progress.
2. Check whether the server is patched for MS17-010. A patched host still
   triggers the alert, because the protocol is still on.

**Fix**

1. Disable SMBv1 on the server and the client; Microsoft has deprecated
   it and removed it from default installs.
2. Replace or isolate the legacy device that needs it.
3. Apply MS17-010 to any Windows host still serving SMBv1.

**Vendor fix:** MS17-010 (March 2017) fixes CVE-2017-0144; removing
SMBv1 removes the class.

Sources: `research/cve/2017-0144.md`

## `KERB_PREAUTH_BURST`

**Investigate**

1. Identify the source and how many principals the failures span: many
   accounts from one source is spraying, chosen to stay under per-account
   lockout.
2. Rule out the benign cause the source names: a job with a stale
   password fails the same way, indefinitely.
3. Read the domain controller's logs for the accounts tried and whether
   any succeeded; sloth sees failures, not success.

**Fix**

1. If it is spraying, block the source and reset any account that
   authenticated from it.
2. If it is a stale credential, update the job that uses it.

**Vendor fix:** none; mitigate on the directory.

Sources: `research/mitre/T1110.md`

## `LDAP_SEARCH_FLOOD`

**Investigate**

1. Identify the source and the account doing the searching: the source
   says identity-sync connectors, monitoring agents, backup software,
   address books and scanners all read the directory in bulk.
2. Compare with the directory's own logs; intent is a fact about the
   account, not about the wire.

**Fix**

1. If the reader is not a known bulk reader, disable the account and
   investigate the host.
2. Record the known bulk readers so the next alert is read against them.

**Vendor fix:** none; enumeration uses the directory as designed.

Sources: `research/mitre/T1087-002.md`

## `BGP_NOTIFICATION_BURST`

**Investigate**

1. Identify the two peers and check the link between them: a flapping
   peer with a real link problem produces this honestly.
2. Read the routers' logs for the NOTIFICATION error codes.

**Fix**

1. Repair the link or the configuration that resets the session.
2. If a third party is sending the NOTIFICATIONs, block it; the source
   names no protocol fix.

**Vendor fix:** none named by the source.

Sources: `research/mitre/T1499.md`

## `SSH_BRUTE_FORCE`

**Investigate**

1. Identify the source and the server; the rule is a rate of failed
   sessions, and a misconfigured job with a stale credential produces
   the same signature.
2. Read the server's authentication log for the accounts tried and any
   success; sloth sees failures only.

**Fix**

1. Block the source if it is not the operator's.
2. Reset any account that logged in from the source.
3. If it is a stale credential, update the job that uses it.

**Vendor fix:** none; the source names no protocol fix.

Sources: `research/mitre/T1110.md`

## `RDP_BRUTE_FORCE`

**Investigate**

1. Identify the source and the server; repeated connection attempts to
   3389 are the signature, and a stale credential is the common benign
   cause.
2. Read the server's security log for the accounts tried and any
   success.

**Fix**

1. Block the source and reset any account that logged in from it.
2. If it is a stale credential, update the client that uses it.

**Vendor fix:** none; the source names no protocol fix.

Sources: `research/mitre/T1110.md`

## `SNMP_COMMUNITY_BRUTE`

**Investigate**

1. Identify the source and the agent; varying community strings against
   one agent is the signature.
2. Check whether the source is the operator's own monitoring with a wrong
   configuration.

**Fix**

1. Block the source if it is not the operator's, or correct the
   monitoring configuration if it is.
2. Change the community if the guessing may have found it.

**Vendor fix:** none; the source names no protocol fix.

Sources: `research/mitre/T1110.md`

## `MQTT_BROKER_BRUTE`

**Investigate**

1. Identify the client and the broker; a CONNACK with a non-zero return
   code is one failure, and a device with a stale credential produces
   them indefinitely.
2. Read the broker's log for the accounts tried and any success.

**Fix**

1. Update or remove the device with the stale credential, or block the
   source if it is not the operator's.

**Vendor fix:** none; the source names no protocol fix.

Sources: `research/mitre/T1110.md`

## `EVIL_TWIN`

**Investigate**

1. Compare the two BSSIDs the detail names (in the TUI's Alerts view;
   slothweb withholds this type's detail, since it carries the SSID a
   remote chose): roaming, mesh and multi-band deployments produce
   same-SSID pairs constantly, which is why the rule needs a mismatch in
   cipher, vendor or RSN posture.
2. Check whether the weaker BSSID is the operator's own equipment (a
   cross-vendor range extender was this rule's documented false
   positive).
3. Check which clients associated to the weaker one.

**Fix**

1. If the weaker BSSID is the operator's, bring its posture up to the
   others' so the mismatch goes away.
2. If it is not, and it is on premises the operator controls, locate it
   and take it off the network; if it is not, report it to whoever runs
   the site. Do not join or probe it.

**Vendor fix:** none for the design gap CVE-2023-52424 names (the
4-way handshake does not bind the network's name); mitigate by removing
the rogue.

Sources: `research/cve/2023-52424.md`, `research/mitre/T1557.md`

## `EVIL_TWIN_PROXIMITY`

**Investigate**

1. Read the RSSI swing in the detail and the BSSID: a large change in a
   short window means a transmitter moved close or a second one appeared
   under the same name.
2. Check for an `EVIL_TWIN` on the same SSID.

**Fix**

1. If a second transmitter is confirmed and it is the operator's, take
   it off the air; if it is not, and it is on premises the operator
   controls, locate it and remove it; otherwise report it to whoever
   runs the site.

**Vendor fix:** none; this is an observation about a transmitter.

Sources: `research/mitre/T1557.md`

## `KARMA_AP`

**Investigate**

1. Look at the SSIDs the BSSID has answered for: one radio answering to
   many names is the KARMA shape, possible because no network name is
   bound to anything.
2. Check which clients associated to it.

**Fix**

1. If the transmitter is on premises the operator controls, locate it
   and remove it; if not, report it to whoever runs the site. Do not
   join it.
2. Check the operator's clients that associated to it for what they
   sent.

**Vendor fix:** none for the design gap CVE-2023-52424 names; mitigate
by removing the rogue.

Sources: `research/cve/2023-52424.md`, `research/mitre/T1557.md`

## `DNS_TUNNEL`

**Investigate**

1. Look at the parent domain and the host querying it. The source warns
   that long, high-entropy names are also how several content-delivery
   and anti-abuse systems work normally.
2. Check volume over time for that parent domain; a tunnel has to move
   bytes.

**Fix**

1. If the domain is not a known service, isolate the host and examine
   it.
2. Block the parent domain at the resolver once confirmed.

**Vendor fix:** none; mitigate on the host and the resolver.

Sources: `research/mitre/T1071-004.md`

## `PROBE_FLOOD`

**Investigate**

1. Look at the transmitter address and rate. The address is as claimed
   and often randomised.
2. A stuck client produces the same burst; check whether the address
   persists over time.

**Fix**

1. None needed for a one-off. Repeated floods near the operator's network
   are reconnaissance: correlate with `MY_NETWORK_RECON` and
   `RECURRING_TRANSIT`.

**Vendor fix:** none; probing is what clients do.

Sources: `research/mitre/T1595.md`

## `ATTACK_TOOL_UA`

**Investigate**

1. Identify the source and the target host. The source calls this high
   confidence and trivially evaded: it catches tools that did not change
   their default.
2. Check what the target answered (its access log); the request is not a
   compromise.

**Fix**

1. Block the source if it is not the operator's own testing.
2. Check the targeted service: the source says the target, not the
   volume, is the measure of risk.

**Vendor fix:** none; the alert is about a client.

Sources: `research/mitre/T1190.md`, `research/mitre/T1595.md`

## `ATTACK_PATH`

**Investigate**

1. Identify the source, the target host and the path requested: a path
   that exists only in exploit lists, asked of a host that does not run
   that software, is a scan.
2. Check the target's access log for the response; sloth does not read
   response bodies.

**Fix**

1. Check that the targeted service does not run what the path asks
   for, or that its owner has it patched.
2. Block the source if the scanning persists.

**Vendor fix:** depends on the software targeted; the alert names the
attempt, not a vulnerable product.

Sources: `research/mitre/T1190.md`, `research/mitre/T1595.md`

## `WEAK_TLS`

**Investigate**

1. Identify the client: the alert's address is the host that sent the
   ClientHello. sloth reads only the highest version that ClientHello
   offers (`supported_versions`, else `legacy_version`); it does not see
   what the server chose and checks no cipher suite. The server it was
   talking to is in the detail, in the TUI's Alerts view (slothweb
   withholds this type's detail, which carries the name the client
   asked for).
2. Find the software on that client that offers nothing newer than TLS
   1.1. The source names embedded devices (building management, medical,
   industrial) as the common trigger.

**Fix**

1. Update or replace the client's TLS stack so it offers TLS 1.2 or
   later; RFC 8996 makes negotiating 1.0 and 1.1 a MUST NOT.
2. Where the client cannot be updated, segment it so its weak sessions
   do not cross untrusted links.
3. On the server side, confirm only that the server refuses anything
   below TLS 1.2. That does not fix the client: a client that can offer
   nothing newer then fails to connect, so fix or isolate the client
   first.

**Vendor fix:** a firmware or software update for the client where the
vendor offers one; RFC 8996 (BCP 195) is the standard to hold it to.

Sources: `research/rfc/8996.md`

## `NO_MONITOR_MODE`

**Investigate**

1. This is sloth's own sensor: interfaces were seen but none is in
   monitor mode, so the 802.11 views and rules have no input.
2. Check whether a monitor interface was meant to be configured and
   whether the adapter supports monitor mode.

**Fix**

1. Put a capable adapter in monitor mode and start sloth with it, as
   `docs/wiki/deployment.md` describes.

**Vendor fix:** not applicable; this is configuration.

Sources: `docs/wiki/alerts.md`, `docs/wiki/deployment.md`

## `CLEARTEXT_CRED`

**Investigate**

1. Identify the protocol and the two endpoints. The source says the
   common trigger is a legacy protocol on a management VLAN, and that
   the credential was exposed whether or not anyone was listening.
2. Treat the credential as compromised: anything that can see the
   segment could read it. slothweb never shows the username; the
   detail is withheld for this type.

**Fix**

1. Change the exposed credential.
2. Plan the service's migration off the cleartext protocol; the source
   says the answer to this finding is a migration plan.

**Vendor fix:** none; the protocol carries the credential in the clear
by design. Mitigate by migrating off it.

Sources: `research/mitre/T1040.md`

## `BEACON_FLOOD`

**Investigate**

1. Note the count of new BSSIDs: hundreds of fabricated networks fill
   every client's scan list.
2. Check for a dense real deployment (a conference) before concluding.

**Fix**

1. Locate the transmitter if the flood persists; nothing on the network
   side stops a radio from beaconing.

**Vendor fix:** none; mitigate by locating the source.

Sources: `research/mitre/T1498.md`

## `AUTH_FLOOD`

**Investigate**

1. Note the BSSID and rate: authentication requests filling an AP's
   association table, a resource of a few hundred entries.
2. Check the AP's logs for clients refused during the window.

**Fix**

1. Locate the transmitter.
2. Check whether the AP firmware limits pending authentications; the
   source does not name a vendor fix.

**Vendor fix:** none named by the source.

Sources: `research/mitre/T1499.md`

## `SSID_CONFUSION`

**Investigate**

1. Compare the weak and strong BSSIDs the detail names (in the TUI's
   Alerts view; slothweb withholds this type's detail, which carries the
   SSID): the same SSID on a second BSSID with a weaker RSN posture than
   the strongest seen for that name.
2. Check whether the weaker one is the operator's (a migration window, a
   misconfigured AP).

**Fix**

1. If it is the operator's, raise its posture to match the others.
2. If it is not, and it is on premises the operator controls, locate it
   and remove it; otherwise report it to whoever runs the site.
3. Configure the operator's clients so they do not accept the weaker
   posture for a saved network.

**Vendor fix:** CVE-2023-52424 is a design gap in 802.11 (the SSID is
not bound into key derivation); mitigate by posture and client
configuration.

Sources: `research/cve/2023-52424.md`

## `MGMT_FUZZ`

**Investigate**

1. Note the BSSID and the malformed-IE counts. The source names a
   misbehaving driver as a common benign cause.
2. Check whether nearby devices crashed or dropped at the time.

**Fix**

1. Locate the transmitter if the frames persist; the target is the
   parser of whatever receives them, and the source names no fix.

**Vendor fix:** none named by the source.

Sources: `research/mitre/T1499.md`

## `ROGUE_RADIUS`

**Investigate**

1. Note the BSSID and the EAP methods offered: weak methods (MD5, GTC)
   and outer identities sent in the clear are the lure's shape.
2. Check whether the BSSID is the operator's enterprise network.
3. Treat any client that associated as having exposed its outer
   identity; it is readable by anyone in range. slothweb withholds the
   detail of this type.

**Fix**

1. Set `ca_cert` and `domain_suffix_match` on every 802.1X client, so it
   only completes the exchange against the operator's server.
2. If a BSSID is not the operator's and it is on premises the operator controls, locate it and remove it;
   otherwise report it to whoever runs the site. Do not join or probe it.

**Vendor fix:** the supplicant fix for CVE-2023-52160 is upstream; a
handset that has not taken it stays exposed.

Sources: `research/cve/2023-52160.md`

## `ICMP_TUNNEL`

**Investigate**

1. Identify the two hosts and the payload sizes. The source names path-MTU
   discovery, `ping -s` diagnostics and some vendor keepalives as
   legitimate causes of large payloads.
2. Check how long the exchange has run; an interactive tunnel is slow and
   steady.

**Fix**

1. If it is not a known diagnostic, isolate the host and examine it.

**Vendor fix:** none; this is a covert channel, not a bug.

Sources: `research/mitre/T1095.md`

## `MY_NETWORK_RECON`

**Investigate**

1. Note the client and the designated network it probed for. The rule's
   own text lists the benign causes: a returning device, an unobserved
   association.
2. Check whether the client is rostered (`--known-mac`).

**Fix**

1. None for a single sighting. Repeated sightings with
   `RECURRING_TRANSIT` are a pattern worth recording against the
   operator's own context.

**Vendor fix:** none; probing is ordinary client behaviour.

Sources: `research/mitre/T1595.md`

## `RECURRING_TRANSIT`

**Investigate**

1. Note the device and the passes. The source warns that a device seen on
   several days is a neighbour, a delivery driver or a colleague far more
   often than surveillance.
2. Remember MAC randomisation: the pattern is only as good as the
   correlation behind it.

**Fix**

1. None from sloth's side; the operator supplies the context.

**Vendor fix:** not applicable.

Sources: `research/mitre/T1595.md`

## `UNKNOWN_DEVICE`

**Investigate**

1. Note the MAC and network: the source says an unrostered MAC is far
   more often a guest's randomised handset than an implant.
2. Check the roster: absence from it is not absence of authorisation.
3. Find where the device is attached (switch port, AP association).

**Fix**

1. Add the device to the roster if it belongs.
2. If it does not, disconnect it and examine it.

**Vendor fix:** not applicable; the defence is inventory.

Sources: `research/mitre/T1200.md`

## `RF_DEGRADED`

**Investigate**

1. Note the channel and the retry and bad-FCS ratios. The source states
   this is the observable a flood produces and also the one a microwave
   oven produces.
2. Look for flood alerts on the same channel and window.

**Fix**

1. Move the network off the channel or remove the interference source.

**Vendor fix:** not applicable.

Sources: `research/mitre/T1498.md`

## `ASSOC_FLOOD`

**Investigate**

1. Note the BSSID, the rate and how many station addresses were used; the
   rule fires at a rate no roaming policy produces.
2. Check the AP's logs for clients refused.

**Fix**

1. Locate the transmitter.

**Vendor fix:** none named by the source.

Sources: `research/mitre/T1498.md`

## `BTM_ABUSE`

**Investigate**

1. Note the sender, the client and the candidate list. A BSS Transition
   Request with Disassociation Imminent moves a client with no deauth
   frame and no RSSI proximity constraint.
2. Check whether the candidate BSSID is the operator's, and whether
   the sender ever beaconed.

**Fix**

1. If the sender is not the operator's AP and it is on premises the
   operator controls, locate it and remove it; otherwise report it to
   whoever runs the site.

**Vendor fix:** none named by the source; the mechanism works as
802.11-2020 §9.6.14 defines it.

Sources: `research/ieee/802.11-2020-9.6.14.md`

## `WPA_DOWNGRADE`

**Investigate**

1. Read the posture the detail names (in the TUI's Alerts view; slothweb
   withholds this type's detail, which carries the SSID): MFP
   capable-but-not-required on an SAE BSS, or WPA2/WPA3 transition mode.
   The TUI's WiFi view shows the same posture for the BSSID.
2. Check whether a migration window is still justified; the source says
   transition mode is legitimate during migration and is also the state
   an attacker needs.

**Fix**

1. On the operator's own BSS, when every client supports it, switch it
   to SAE only with MFP required; the source says WPA3 mandates MFP. A
   BSS that is not the operator's is its owner's to change.
2. Until then, keep the transition window short and documented.

**Vendor fix:** not applicable; the downgrade the source describes is a
configuration posture, not a bug.

Sources: `research/cert/vu-871675.md`

## `PEAP_NO_SERVER_CERT`

**Investigate**

1. Note the client and BSSID and whether the detail says "no
   ServerHello" (unambiguous) or "no Certificate observed" (probably
   certless; possibly a chain split across fragments).
2. Treat that client's credentials as exposed if the BSSID is not the
   operator's.

**Fix**

1. Configure the client with `ca_cert` and `domain_suffix_match`; the
   source states that without a CA pin there is nothing to verify the
   server against.
2. Update `wpa_supplicant` on affected clients.

**Vendor fix:** the CVE-2023-52160 fix is upstream in wpa_supplicant;
handsets need the update.

Sources: `research/cve/2023-52160.md`, `research/cert/vu-871675.md`, `research/mitre/T1557.md`

## `CSA_ABUSE`

**Investigate**

1. Note the BSSID, the announced channel and whether the transmitter
   address was forged.
2. Check whether the target channel hosts a known twin.

**Fix**

1. If the transmitter is not the operator's AP and it is on premises the operator controls, locate it and remove it;
   otherwise report it to whoever runs the site. Do not join or probe it.
2. Check the clients that followed the switch.

**Vendor fix:** none named by the source.

Sources: `research/mitre/T1557.md`

## `RRM_SURVEY_ABUSE`

**Investigate**

1. Note the asker and the client: an 802.11k Beacon Request makes
   someone else's client survey the air and report back.
2. Check whether the asker is the operator's AP and ever beaconed the
   SSID it asked about.

**Fix**

1. Remove the asker if it is not the operator's.

**Vendor fix:** none named by the source.

Sources: `research/mitre/T1595.md`

## `RTS_FLOOD`

**Investigate**

1. Note the transmitter, the rate and the maximum NAV. The source notes an
   RTS flood silences a channel without transmitting anything a
   frame-rate detector watches for; a NAV above the legal maximum is
   the strong signal.
2. Check `RF_DEGRADED` on the same channel.

**Fix**

1. Locate the transmitter; there is no network-side control for another
   radio's RTS.

**Vendor fix:** none.

Sources: `research/mitre/T1498.md`

## `CAPTIVE_PORTAL`

**Investigate**

1. Note the host whose connectivity check was intercepted and the client.
   The rogue answers the check to open a browser on the victim.
2. Check whether the AP is a known evil twin, and whether the network
   legitimately has a captive portal.

**Fix**

1. Disconnect the client from the network and check what it entered on
   the portal page.
2. If the rogue AP is not the operator's and it is on premises the operator controls, locate it and remove it;
   otherwise report it to whoever runs the site. Do not join or probe it.

**Vendor fix:** none; this is an interception.

Sources: `research/mitre/T1557.md`

## `BLOCKACK_ATTACK`

**Investigate**

1. Note the transmitter, receiver and TID. The symptom the source names is
   a client that stopped working with a clean deauth table.
2. Check whether the channel was retrying hard at the time.

**Fix**

1. Locate the transmitter; the source names no fix.

**Vendor fix:** none named by the source.

Sources: `research/papers/bl0ck-2302.05899.md`, `research/mitre/T1499.md`

## `FRAG_PLAINTEXT`

**Investigate**

1. Note the BSSID and the station pair: unprotected data frames after key
   install are the on-air artefact of CVE-2020-26140 / -26143.
2. Whether the receiver accepted them is a decision inside its driver;
   the source says this varies by vendor.

**Fix**

1. Update the firmware of the AP and the clients on that BSS to versions
   that carry the FragAttacks fixes.

**Vendor fix:** the per-vendor FragAttacks advisories (index linked from
the source).

Sources: `research/papers/fragattacks-usenix2021.md`

## `FRAG_BCAST`

**Investigate**

1. Note the BSSID: plaintext broadcast fragments on a protected BSS are
   CVE-2020-26145's artefact.

**Fix**

1. Update AP and client firmware to versions with the FragAttacks fixes.

**Vendor fix:** the per-vendor FragAttacks advisories.

Sources: `research/papers/fragattacks-usenix2021.md`

## `FRAG_CACHE`

**Investigate**

1. Note the BSSID and the station pair: a reassembly completed after a
   (re)association is CVE-2020-24586, a design flaw in the standard.

**Fix**

1. Update AP and client firmware to versions that clear the fragment
   cache on (re)connect.

**Vendor fix:** the per-vendor FragAttacks advisories.

Sources: `research/papers/fragattacks-usenix2021.md`

## `FRAG_MIXED`

**Investigate**

1. Note the BSSID and the station pair: a reassembly that mixed an
   encrypted fragment with a plaintext one (CVE-2020-26147).

**Fix**

1. Update AP and client firmware to versions with the FragAttacks fixes.

**Vendor fix:** the per-vendor FragAttacks advisories.

Sources: `research/papers/fragattacks-usenix2021.md`

## `SAE_PSK_SPLIT`

**Investigate**

1. Note the SSID and the two BSSIDs: one SAE-only, one PSK-only under the
   same name. Check whether both are the operator's.
2. Check whether a client associated using PSK.

**Fix**

1. If the PSK-only BSSID is the operator's, move it to SAE.
2. If it is not, and it is on premises the operator controls, locate it
   and remove it; otherwise report it to whoever runs the site.

**Vendor fix:** VU#871675 covers the mechanism; the split itself is
configuration or a rogue.

Sources: `research/cert/vu-871675.md`

## `SAE_PSK_REGRESSION`

**Investigate**

1. Note the BSSID and how long it was SAE-only. The source says the
   protection is lost whether an attacker or an administrator caused it.
2. Check the AP's configuration history.

**Fix**

1. Restore SAE on the BSSID.

**Vendor fix:** not applicable; this is posture.

Sources: `research/cert/vu-871675.md`

## `FRAG_AMSDU`

**Investigate**

1. Note the BSSID and the station pair: the same protected MPDU replayed
   with the A-MSDU bit flipped (CVE-2020-24588).

**Fix**

1. Update AP and client firmware to versions with the FragAttacks fixes,
   and negotiate SPP A-MSDU where both ends support it; the source says
   the bit is otherwise authenticated in none of WPA, WPA2 or WPA3.

**Vendor fix:** the per-vendor FragAttacks advisories.

Sources: `research/papers/fragattacks-usenix2021.md`

## `FRAG_AMSDU_EAPOL`

**Investigate**

1. Note the BSSID and the station pair: a plaintext A-MSDU whose first
   subframe claims EAPOL (CVE-2020-26144). EAPOL is never a subframe of an
   aggregated frame.

**Fix**

1. Update AP and client firmware to versions with the FragAttacks fixes.

**Vendor fix:** the per-vendor FragAttacks advisories.

Sources: `research/papers/fragattacks-usenix2021.md`

## `FRAG_MIXKEY`

**Investigate**

1. Note the BSSID and the station pair: a reassembly spanning a key
   rotation (CVE-2020-24587, a design flaw).

**Fix**

1. Update AP and client firmware to versions with the FragAttacks fixes.

**Vendor fix:** the per-vendor FragAttacks advisories.

Sources: `research/papers/fragattacks-usenix2021.md`

## `FRAG_PN_GAP`

**Investigate**

1. Note the BSSID and the station pair. The source explains why packet
   number gaps alone are weak: the counter is shared by every frame on a
   key and TID, so ordinary interleaving and retries open gaps too.

**Fix**

1. Update AP and client firmware to versions with the FragAttacks fixes.

**Vendor fix:** the per-vendor FragAttacks advisories.

Sources: `research/papers/fragattacks-usenix2021.md`

## `FRAG_EAPOL_RELAY`

**Investigate**

1. Note the BSSID and the two stations: EAPOL forwarded between stations,
   neither of which is the AP (CVE-2020-26139).

**Fix**

1. Update the AP firmware to a version with the FragAttacks fixes.

**Vendor fix:** the per-vendor FragAttacks advisories.

Sources: `research/papers/fragattacks-usenix2021.md`

## `SA_QUERY_FLOOD`

**Investigate**

1. Note the BSSID and station. The source reads a storm of SA Query
   frames as a network successfully defending itself against spoofed
   disassociations.
2. Read the AP's logs; they may be the only other record of the attempt.

**Fix**

1. Keep MFP required and the AP firmware current (hostapd before 2.10
   did not consistently validate certain management frames).
2. Locate the transmitter of the spoofed frames.

**Vendor fix:** hostapd 2.10 and later for CVE-2019-16275.

Sources: `research/cve/2019-16275.md`, `research/mitre/T1499.md`

## `MFP_UNPROTECTED`

**Investigate**

1. Note the BSSID and the action-frame category: an individually
   addressed robust action frame with the Protected bit clear, on a BSS
   that advertises MFP required.
2. Sloth cannot tell a non-conforming stack from an injected frame;
   check the transmitter.

**Fix**

1. Update the AP: hostapd before 2.10 accepted such frames
   (CVE-2019-16275).
2. Update or replace the client stack sending them if it is a
   non-conforming implementation.

**Vendor fix:** hostapd 2.10 and later.

Sources: `research/cve/2019-16275.md`

## `OPEN_SETUP_AP`

**Investigate**

1. Note the SSID and BSSID: an open SoftAP whose name matches an
   onboarding pattern is an unauthenticated management surface.
2. Find the device and whether it is mid-setup, abandoned in setup mode,
   or only named that way.

**Fix**

1. If the device is the operator's: finish setting it up so it leaves
   the open SoftAP, or power it off.
2. If it is not: tell whoever controls it that it is sitting in open
   setup mode; do not join its SoftAP or configure it.
3. For the operator's own devices, prefer onboarding that verifies the
   network (Wi-Fi Easy Connect / DPP, as NIST SP 1800-36 describes) over
   open-network provisioning.

**Vendor fix:** none; mitigate by completing or replacing the
onboarding.

Sources: `research/papers/nist-sp1800-36-onboarding.md`

## `WPS_PIN_BRUTE`

**Investigate**

1. Note the station and BSSID and the attempt count; each M1-M3-NACK cycle
   is one refused PIN guess.
2. Check whether the AP has WPS enabled and whether it locks out.

**Fix**

1. On the operator's AP, turn off WPS external registrar (PIN); it is
   the only workaround CERT offers. An AP that is not the operator's is
   its owner's to change: tell them.
2. If the attack on the operator's AP may have succeeded, change the
   network passphrase.

**Vendor fix:** none universal; CERT's workaround is to disable the
external registrar.

Sources: `research/cert/vu-723755.md`, `research/mitre/T1110.md`

## `WPS_LOCKOUT_CYCLING`

**Investigate**

1. Note the BSSID and the cycle count: the AP repeatedly locking and
   releasing WPS is a brute force seen from the victim's side, even when
   sloth heard no attempt.

**Fix**

1. On the operator's AP, turn off WPS PIN; an AP that is not the
   operator's is its owner's to change: tell them.
2. Change the operator's passphrase if the attack may have reached the
   full PIN.

**Vendor fix:** none universal; disable the external registrar.

Sources: `research/cert/vu-723755.md`, `research/mitre/T1110.md`

## `WPS_PBC_RACE`

**Investigate**

1. Note the BSSID and the number of concurrent enrollees inside the 120 s
   walk time. Two household members pressing WPS together is the
   ordinary case the threshold keeps quiet.
2. Check which devices actually joined during the window.

**Fix**

1. On the operator's network, remove any device that enrolled and is not
   the operator's.
2. Prefer not to use push-button configuration where unknown devices are
   in range; the window authenticates by proximity alone.

**Vendor fix:** none; session overlap is a protocol condition the
registrar must abort on.

Sources: `research/papers/wps-pbc-session-overlap.md`, `research/mitre/T1557.md`

## `MLE_INVALID_LINK_ID`

**Investigate**

1. Note the MLD address. A Per-STA Profile with link_id 15, or one link
   named twice, has no benign explanation in a conformant MLD.
2. Check whether any Wi-Fi 7 AP on the segment runs hostapd older than
   2.12.

**Fix**

1. Update hostapd to 2.12 or later on Wi-Fi 7 APs.
2. Locate the transmitter.

**Vendor fix:** hostapd 2.12 (CVE-2026-58374, w1.fi 2026-1).

Sources: `research/cve/2026-58374.md`

## `MLE_COMMON_INFO_LEN_BAD`

**Investigate**

1. Note the MLD address and the Common Info Length; a length under 7 or
   past the element is the input class w1.fi 2026-1 hardens against.

**Fix**

1. Update hostapd and wpa_supplicant to versions carrying the w1.fi
   2026-1 fixes.
2. Locate the transmitter.

**Vendor fix:** the w1.fi 2026-1 mitigation commits (hostapd 2.12).

Sources: `research/cve/2026-58374.md`

## `MLE_SUBELEM_OVERRUN`

**Investigate**

1. Note the MLD address and the overrun: a Link Info subelement chain
   that reaches past its element is a buffer read overflow in the family
   the advisory describes.

**Fix**

1. Update hostapd and wpa_supplicant to versions carrying the w1.fi
   2026-1 fixes.
2. Locate the transmitter.

**Vendor fix:** the w1.fi 2026-1 hardening (hostapd 2.12); the source
notes no listed commit is specific to this shape.

Sources: `research/cve/2026-58374.md`

## `MLD_MAC_COLLISION`

**Investigate**

1. Note the MLD address and the link_id: two different radios claimed
   one Multi-Link identity. The source says neither reading is benign.
2. Use roster membership, signal and timing to tell which device is
   genuine.

**Fix**

1. For the device that is not the operator's: if it is on premises the
   operator controls, locate it and remove it; otherwise report it to
   whoever runs the site. Do not join or probe it.

**Vendor fix:** none; this is an identity claim, not a bug.

Sources: `research/ieee/802.11be-9.4.2.312-mld-identity.md`

## `MLE_CROSS_LINK_CIPHER_DOWNGRADE`

**Investigate**

1. Note the MLD address and the weaker link: one link of an MLD advertised
   with a weaker cipher or MFP not required is the lane an
   adversary-in-the-middle wants used.
2. Check the AP's per-link configuration.

**Fix**

1. Configure every link of the MLD with the same posture.

**Vendor fix:** not applicable; this is posture.

Sources: `research/ieee/802.11be-9.4.2.312-mld-identity.md`

## `CAM_WS_DISCOVERY`

**Investigate**

1. Note the camera's address: it told the segment it exists, over a
   protocol with no access control. Most such cameras are supposed to be
   there.
2. Check it against the operator's own inventory.

**Fix**

1. Remove a camera that does not belong.

**Vendor fix:** none; WS-Discovery has no authentication by design.

Sources: `research/papers/ws-discovery-onvif.md`

## `PM_FORGE`

**Investigate**

1. Note the station and BSSID: two frames claiming one address in
   incompatible power-save states inside one beacon interval. Sloth does
   not say which frame was forged.
2. Check for a `QUEUE_EVICT` on the same station within seconds.

**Fix**

1. Update AP firmware where the vendor has an advisory for
   CVE-2022-47522 (D-Link, HPE Aruba Networking, Cisco and Lenovo issued
   them).
2. The source says the root cause is in the 802.11 standard, so an
   unpatched AP stays exposed.

**Vendor fix:** per-vendor advisories; not every vendor is patched and
the standard itself is unchanged.

Sources: `research/cve/2022-47522.md`

## `SURV_CLOUD_SNI`

**Investigate**

1. Note the local host and the vendor domain. The source states the
   observation cannot tell a device uploading from a browser with the
   vendor's portal open, and that `axon.com` is also a marketing site.
2. Find out what the local host is.

**Fix**

1. None if the traffic is expected. If not, identify and remove the
   device or application.

**Vendor fix:** not applicable; this is an exposure note.

Sources: `research/papers/surveillance-vendor-endpoints.md`

## `TPC_ABSENT_HIGH_BAND`

**Investigate**

1. Note the BSSID (designated as the operator's) and channel: no Power
   Constraint and no TPC Report on 5 GHz.
2. A legacy 802.11a AP, never required to send them, is already left out
   (the rule skips `phy` legacy), so the residual benign causes are the
   two the source names: a channel-hopping receiver that missed the
   beacons that carried them (the rule waits a floor of observation
   before reading silence, and one beacon carrying either element
   settles it for the session), and a BSS that is really 6 GHz, where the
   limit travels in the Transmit Power Envelope instead (the rule is
   confined to 5 GHz for that reason).

**Fix**

1. Turn on 802.11d and 802.11h on the AP (hostapd `ieee80211d=1`,
   `ieee80211h=1` with a `country_code`); the source names those
   switched off as the common cause.

**Vendor fix:** not applicable; this is configuration.

Sources: `research/ieee/802.11-2020-11.8-spectrum-management.md`

## `CAM_SETUP_SSID`

**Investigate**

1. Note the SSID prefix and BSSID: a camera advertising its documented
   setup SSID is still in provisioning, and its first-boot password change
   has not happened.
2. Check whether the camera is the operator's.

**Fix**

1. If it is the operator's: finish provisioning it and change its
   account password (the setup key is printed on the camera; for
   Hikvision, the last 8 characters of the serial), or power it off if
   it is not being installed.
2. If it is not: tell whoever controls it that it is still in setup
   mode; do not join its setup network or configure it.

**Vendor fix:** none; this is the vendor's onboarding as documented.

Sources: `research/papers/camera-setup-softap.md`

## `QUEUE_EVICT`

**Investigate**

1. Note the station and BSSID, and whether the alert is corroborated: a
   `PM_FORGE` on the same station within ten seconds (the alert's page
   lists the device's other alerts; the TUI's detail says corroborated
   or uncorroborated, and slothweb withholds this type's detail).
   Ordinary roaming produces the uncorroborated shape.

**Fix**

1. As for `PM_FORGE`: AP firmware from a vendor that issued a
   CVE-2022-47522 advisory.

**Vendor fix:** per-vendor advisories for CVE-2022-47522.

Sources: `research/cve/2022-47522.md`

## `MLE_RECONFIG_NO_MLO`

**Investigate**

1. Note the BSSID: it announced a Reconfiguration Multi-Link element and
   never claimed AP MLD membership. Clients act on the announcement.
2. Check whether the BSSID is the operator's Wi-Fi 7 AP.

**Fix**

1. If the transmitter is not the operator's and it is on premises the
   operator controls, locate it and remove it; otherwise report it to
   whoever runs the site.

**Vendor fix:** none named by the source.

Sources: `research/ieee/802.11be-2024-9.4.2.322-bss-mle-consistency.md`

## `MLE_PR_BEACON_DIFF`

**Investigate**

1. Note the BSSID: its Probe Response named a different MLD identity than
   its Beacon. Sloth does not say which transmitter is genuine.

**Fix**

1. If the BSSID is the operator's and a second transmitter is using it,
   locate that transmitter; remove it if it is on premises the operator
   controls, otherwise report it to whoever runs the site.

**Vendor fix:** none named by the source.

Sources: `research/ieee/802.11be-2024-9.4.2.322-bss-mle-consistency.md`

## `SURV_DNS`

**Investigate**

1. Note the local host and the vendor domain it looked up. The source says
   a lookup is weaker than a TLS session: link previews, prefetching
   browsers and filtering resolvers resolve names nothing connects to.
2. If the asker is a resolver on the segment, find the client behind it.

**Fix**

1. None if expected; otherwise identify the device or application.

**Vendor fix:** not applicable; this is an exposure note.

Sources: `research/papers/surveillance-vendor-endpoints.md`

## `WPS_PIXIE_PROBE`

**Investigate**

1. Note the station and BSSID: a WPS run that stopped after M3 and stayed
   silent is the Pixie-Dust offline-PIN shape. The benign cause is a
   receiver that left mid-enrolment.

**Fix**

1. On the operator's AP, turn off WPS PIN; whether its PRNG is weak
   cannot be read off the brand. An AP that is not the operator's is its
   owner's to change: tell them.

**Vendor fix:** none that the source can name per product; disable WPS
PIN.

Sources: `research/papers/bongard-pixie-dust-2014.md`, `research/mitre/T1110.md`

## `WPS_PIXIE_LIKELY_SUCCESS`

**Investigate**

1. Note the stations and BSSID: a registration reached the credentials
   after an M3-abandoned run. The rule's own text says to treat the PSK
   as exposed.

**Fix**

1. If the AP is the operator's: change the network passphrase, turn off
   WPS PIN, and review the devices that joined after the event.
2. If it is not: tell its owner; do not join it.

**Vendor fix:** none per product; disable WPS PIN.

Sources: `research/papers/bongard-pixie-dust-2014.md`, `research/mitre/T1110.md`

## `COUNTRY_ABSENT`

**Investigate**

1. Note the BSSID and channel: a 5 GHz AP with no Country element. The
   source says no advisory exists; it is a heuristic for a stripped
   build.
2. Check whether the AP is pre-802.11d equipment, or whether it is
   designated as the operator's.

**Fix**

1. On the operator's AP, set a country code and enable 802.11d.
2. A BSSID carrying the operator's SSID from equipment that is not the
   operator's: locate it, and report it to whoever controls it; do not
   join or configure it.

**Vendor fix:** not applicable; this is configuration.

Sources: `research/ieee/802.11d-country-element.md`

## `DFS_MASKING`

**Investigate**

1. Note the BSSID and DFS channel: first heard there after the RF baseline,
   with no channel switch leading there. The source says a legitimate AP
   rebooting onto a DFS channel looks the same.
2. Check whether it carries the operator's SSID or is half of an
   evil-twin pair.

**Fix**

1. For a BSSID that is not the operator's: locate it, and report it to
   whoever controls it; do not join or configure it.

**Vendor fix:** not applicable; no public advisory names this pattern.

Sources: `research/regulatory/dfs-15.407-en301893.md`

## `CAM_MDNS_SERVICE`

**Investigate**

1. Note the instance and address: a camera service type in DNS-SD
   corroborates a camera and does not confirm one (the `rtsp` type names
   a protocol, not a device).
2. Check it against the operator's inventory.

**Fix**

1. Remove a device that does not belong.

**Vendor fix:** none; this is the device's own announcement.

Sources: `research/papers/camera-vendor-identity.md`

## `CAM_SSDP_DEVICE`

**Investigate**

1. Note the address and the device type: DigitalSecurityCamera:1 is the
   device naming itself a camera; Basic:1 with a camera-vendor SERVER
   token is the device's own claim, not a registry check.
2. Check it against the operator's inventory.

**Fix**

1. Remove a device that does not belong.

**Vendor fix:** none; this is the device's own announcement.

Sources: `research/papers/camera-vendor-identity.md`

## `CAM_SETUP_OUI`

**Investigate**

1. Note the BSSID and OUI: a camera-vendor block names the maker, never
   the box; a mixed-vendor block (TP-Link, Ubiquiti, Wyze) fires only
   beside a camera setup SSID.
2. Check it against the operator's inventory.

**Fix**

1. Finish provisioning a camera of the operator's. One that is not the
   operator's: if it is on premises the operator controls, remove it;
   otherwise tell whoever controls it. Do not join or configure it.

**Vendor fix:** none; the registry assignment is not a vulnerability.

Sources: `research/papers/camera-vendor-identity.md`, `research/papers/camera-router-role.md`

## `CAM_RTSP_UNAUTH`

**Investigate**

1. Note the RTSP server and the paths: a stream description was handed to
   a client that presented no credential and was not challenged. The
   source lists why this corroborates and does not confirm (a server may
   challenge SETUP or PLAY instead, or admit by source address).
2. Find which client asked; it is often the operator's own VMS.

**Fix**

1. Require authentication on the RTSP server, so DESCRIBE is answered
   with the 401 challenge the RFC defines.

**Vendor fix:** none named by the source; this is server configuration.

Sources: `research/rfc/2326-7826-rtsp.md`

## `BT_OWN_TRANSMIT`

**Investigate**

1. This is sloth's own sensor host: its Bluetooth controller was told by
   the host stack to transmit (scan, inquiry, advertising, connect). sloth
   sent nothing itself.
2. Find the process on the sensor host that issued the command.

**Fix**

1. Stop the host service that makes the controller transmit, so the
   sensor host stays passive.

**Vendor fix:** not applicable; this is the sensor's own configuration.

Sources: `docs/wiki/alerts.md`, `docs/wiki/ble.md`

## `BLE_ADV_FLOOD`

**Investigate**

1. Note the payload family and the count of fresh addresses: genuine
   devices send the same keys, so the count and rate are the evidence.
2. Check whether nearby phones showed pairing pop-ups at the time.

**Fix**

1. On affected handsets, turn off the notification the flood abuses (the
   source names "Show notification" in Nearby Share on Android 14 and
   "Show notifications to connect using Swift Pair" on Windows).
2. Update iOS devices to 17.2 or later.

**Vendor fix:** iOS 17.2 or later (the BLE Spam tool's own source marks
the crash fixed in 17.2; Apple's HT214035 does not name it); otherwise
none, mitigate by the notification settings.

Sources: `research/bluetooth/ble-spam-flood.md`

## `BLE_HID_UNEXPECTED`

**Investigate**

1. Note the address and OUI table: a keyboard-class advertiser on
   attacker-helper silicon, or HID appearances on several new random
   addresses. No pairing was observed.
2. Check whether a legitimate keyboard or remote is nearby.

**Fix**

1. Update hosts to the CVE-2023-45866 fixes (BlueZ, Android 2023-12-05
   patches, macOS 14.2, iOS 17.2).

**Vendor fix:** BlueZ, Android, Apple (HT214035) fixes for CVE-2023-45866.

Sources: `research/cve/2023-45866.md`

## `BLE_WATCHLIST`

**Investigate**

1. Note the category and the address count: a category, never an
   identity. Finder tags rotate addresses, and a tag rides in its owner's
   own bag too.

**Fix**

1. None from sloth's side; the operator decides whether the presence
   matters.

**Vendor fix:** not applicable.

Sources: `research/bluetooth/ble-watchlist-categories.md`

## Related pages

- [[alerts]] — the engine and the rules
- [[research-corpus]] — the sources every section cites
- [[slothweb]] — the alert detail page that shows these sections
