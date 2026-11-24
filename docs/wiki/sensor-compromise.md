---
name: sensor-compromise
description: Runbook for a lost or stolen sloth sensor - what it holds on disk and what a finder reads, the steps to take, how to hold less, and the --preflight check for evidence kept on an unencrypted disk
type: reference
---

# A lost or stolen sensor

**Summary**: A sensor holds on its disk everything it has heard and been told: `sloth.db`, the JSONL file, alert and evidence pcaps, crackable handshake material, reports, the site's configuration (designated networks, the device roster) and the tailnet node key. Whoever holds the disk reads all of it unless the disk is encrypted; sloth's file modes stop other accounts on a running host, not a finder with the card in another machine. When a sensor is lost: take it off the tailnet, remove it from every peer's allow-list, record the time after which nothing from it is trusted, and change what it knew that can be changed. To hold less: shorter retention and full-disk encryption. `--preflight` warns when `--pcap-dir` or `--eapol-dir` keeps captures longer than 7 days on a disk with no dm-crypt under it.

**Sources**: issue #251 part 2 (from #241 item 19); FM 6-02.43 (2009) 2-42 (compromise procedures belong where every unit can read them, not only in one unit's own procedures); [[deployment]] (paths, the unit's `StateDirectory=`), [[fleet]] § The transport (tailnet, `--web-allow`, `--peer`), [[retention]], [[pcap-export]], [[record-integrity]]; `src/preflight.c` (`check_at_rest()`), `src/preflight_gather.c` (`pf_block_crypt()`), `src/preflight.h` (`PF_PLAIN_RETAIN_DAYS`); `tests/test_preflight.c`; Linux `Documentation/ABI/testing/sysfs-block-dm` (`dm/uuid`, `dm/name`) and `sysfs-block` (`slaves/`); cryptsetup sets a dm-crypt mapping's uuid to `CRYPT-<type>-…`.

**Last updated**: 2026-11-24 (#251 review: step 3 no longer counts a handoff packet as holding the chain head, which it does not), 2026-11-24 (#251: the page, and the `--preflight` at-rest check).

---

## 1. What a sensor holds, and what a finder reads

Paths are the packaged layout ([[deployment]]); a hand-run sensor holds
the same things wherever its flags point.

| What | Where (packaged) | What it tells a finder |
|---|---|---|
| `sloth.db` | `/var/lib/sloth/sloth.db` (sloth-rf: `/var/lib/sloth-rf/`) | every device, AP, probe and finding kept for `db.retain_days` (30 by default; findings 12 times longer, [[retention]]), including what the managed interface learnt on the joined network: host names, DHCP and DNS, and the columns sloth-mesh withholds from its pages (a clear-text credential's user name, an RDP cookie, an MQTT user name, an EAP identity) |
| JSONL `-o` file | where `-o` points | the same records as a stream, kept until removed: sloth never sweeps it |
| Alert pcaps | `--pcap-dir`, `/var/lib/sloth/pcap` | the first 64 bytes of each matching packet, `pcap.retain_days` (14) |
| Evidence and handshake pcaps, `eapol.22000` | `--eapol-dir` (opt-in, `--collect-handshakes`) | **crackable material**: a WPA handshake or PMKID is an offline guess at the network's passphrase. `handshake.retention_days` (7) |
| Reports and snapshots | `--report`, `--report-json`, `--snapshot-out`, the handoff packet | the site's posture, findings and AP list |
| Configuration | `/etc/default/sloth`, `/etc/default/sloth-rf`, `/etc/default/slothweb`, `--inventory`, `--known-macs` | the designated SSIDs and BSSIDs, the roster of the site's own devices, the approved-AP inventory, the sensor's fixed `--location`, the peers it talks to |
| slothweb's database | sloth-mesh's, under `/var/lib/slothweb` | triage state and fleet imports from the peers |
| Keys | the tailnet daemon's state (Tailscale: `/var/lib/tailscale`) | the node key that makes this host a member of the operator's tailnet ([[fleet]] § The transport). **sloth itself holds no key**: no TLS, no signing key, nothing to revoke inside sloth (#251 builds no signing, [[record-integrity]] § 5) |

Files are `0600` and directories `0700`, owned by the `sloth` account
(`src/secure_file.h`), which keeps other accounts on a running host out.
A finder does not run the host: they read the card or disk in another
machine, as root. Without disk encryption, everything above is readable.

## 2. Steps when a sensor is lost

In this order, the first two as soon as the loss is known:

1. **Take it off the tailnet.** In the tailnet's admin console remove
   the node, which revokes its node key; its `100.x` address then
   authenticates nothing. This is the one key a sensor holds today.
2. **Remove it from every peer's allow-list.** On each other sensor,
   delete its `--web-allow 100.A.B.C/32` and its `--peer NAME=…` from
   `/etc/default/slothweb`, and restart slothweb there. A new node that
   is later handed the same address must not inherit the old one's
   admission.
3. **Record the time.** Write down the last moment the sensor was known
   to be in hand. Records from it after that time are not trusted:
   fleet imports from it, its JSONL, its reports. Records before it
   stay trusted only as far as something kept off the sensor ties
   them: a printed or copied report's chain head ([[record-integrity]]
   § 4), checked against the segment heads `sloth --verify` lists. A
   handoff packet does not carry the chain head today, so it ties
   nothing. A sensor that comes back is rebuilt, not
   resumed: its files may have been changed while it was away.
4. **Change what it knew.** The passphrases of networks whose handshakes
   were under `--eapol-dir` (the material is offline-crackable, and the
   finder has time), any credential `sloth.db` recorded in clear text,
   and anything in its configuration files that is a secret.
5. **sloth-mesh and sloth-comint keys** (#184 Stage 6, per-installation
   keys): not built yet. When they exist, revoking the sensor's key in
   both belongs in step 1. This page is to be updated then.

## 3. Holding less

- **Retention.** Shorter windows hold less: `--tune pcap.retain_days=N`,
  `--handshake-retention N` (or no `--collect-handshakes` at all),
  `--tune db.retain_days=N`, `--tune report.retain_days=N` ([[retention]],
  [[cli-reference]]). The JSONL file has no sweep; rotate it with the
  host's log rotation, or do not keep one on the sensor (the data socket
  and sloth-mesh need no file).
- **Full-disk encryption on the host.** A host setting, outside sloth:
  LUKS (dm-crypt) on the root or on the volume `/var/lib/sloth` sits on,
  set up when the host is installed. It protects a sensor that is off
  or locked; a sensor taken while running with the key in memory is not
  protected by it. An unattended sensor needs the key at boot (a TPM or
  a network unlock), which is the operator's trade-off.

## 4. The `--preflight` check

`--preflight` adds one line per evidence directory, `pcap-dir-at-rest`
and `eapol-dir-at-rest` in the `storage` check ([[preflight]]):

| Line | When |
|---|---|
| `ok` | the directory's filesystem sits on dm-crypt; or no dm-crypt is under it and captures are kept `PF_PLAIN_RETAIN_DAYS` (7) days or fewer |
| `warn` | no dm-crypt under it and captures kept more than 7 days, or forever (`0`). The line names the device and the knob |
| `not checked` | the filesystem's device is not a block device `/sys` traces |

7 days is `handshake.retention_days`' default, the shortest window
sloth ships for anything it keeps. The defaults themselves therefore
warn for `--pcap-dir` (14 days) on an unencrypted disk, which is the
point: two weeks of captures on a card anyone can read.

**How it is detected, and how far that goes.** Without root, from
`/sys` only, through the same guarded readers the rest of the preflight
uses (so the fake platform serves them in tests): the directory's
`st_dev` gives `/sys/dev/block/MAJ:MIN`; a device-mapper node there has
`dm/uuid`, which cryptsetup sets to `CRYPT-…` for dm-crypt (LUKS and
plain), and its `slaves/` are walked down, so LVM on LUKS (an `LVM-…`
node over a `CRYPT-…` one) is found too. That is reliable for what it
reads: a `CRYPT-` node in the stack is dm-crypt. What it does **not**
see, and the warning says so:

- **fscrypt** (per-directory encryption in ext4 and f2fs) and a
  **self-encrypting drive** (OPAL): the stack has no dm-crypt node, so
  the line warns though the data is encrypted;
- **btrfs, ZFS (and its native encryption), overlayfs, tmpfs and NFS**
  report a device number that is not a block device in `/sys`: the line
  is `not checked`, never a guess.

A warning is an advisory (exit `1`, not `2`): the operator decides. The
check reads nothing else and opens nothing.

`tests/test_preflight.c` holds the detection against a fake `/sys`
(dm-crypt under LVM, a plain partition, no entry) and the levels at the
edge (7 days `ok`, 8 `warn`, `0` `warn`), each seen red under a mutation.

## Related pages

- [[record-integrity]] — what is hashed, and why no signing key yet.
- [[retention]] — what sloth deletes and when.
- [[preflight]] — the other checks.
- [[fleet]] — the tailnet and the allow-lists.
- [[deployment]] — where the files are.
- [[threat-model]]
