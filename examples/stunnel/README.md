# stunnel templates for the sloth data socket

TLS transport for `--data-socket` **without linking crypto into
sloth**. sloth keeps binding loopback; stunnel owns the certificates,
the handshake and the encryption.

Use this when the consumer is an appliance or a SIEM that takes a raw
TCP stream and cannot be wrapped in SSH. If SSH is available, prefer
`ssh -L` — it is one command and there is nothing to expire. See
[`docs/wiki/data-socket-exposure.md`](../../docs/wiki/data-socket-exposure.md).

| File | Runs on | `accept` | `connect` |
|---|---|---|---|
| [`sensor.conf`](sensor.conf) | the host running sloth | routable:8766 (TLS in) | `127.0.0.1:8765` (sloth) |
| [`reader.conf`](reader.conf) | the management host | `127.0.0.1:8765` (local) | sensor:8766 (TLS out) |

Both are templates. Every path, hostname and address is a placeholder.

---

## The mistake to avoid

`accept` and `connect` are mirror images between the two files, and
swapping them is the one error that fails *open*:

- On the **sensor**, `accept` is the TLS side (routable) and `connect`
  is the plaintext side (must be `127.0.0.1`).
- On the **reader**, `accept` is the plaintext side (must be
  `127.0.0.1`) and `connect` is the TLS side (the sensor).

Put a routable address on either `accept = 127.0.0.1:8765` line and you
have published the cleartext stream — the exact exposure the tunnel was
built to prevent, now one hop further from the guard that would have
caught it.

Check before you leave the host:

```sh
# On each host: the plaintext port must be bound to 127.0.0.1 only.
ss -ltnp | grep -E '8765|8766'
```

`127.0.0.1:8765` is correct. `0.0.0.0:8765` or `*:8765` is not.

---

## Deploy

**1. Certificates.** Mutual TLS, so both ends need a keypair. For a
two-host setup, self-signed certs that each side pins are simpler than
running a CA:

```sh
# On the sensor
openssl req -x509 -newkey rsa:4096 -days 825 -nodes \
    -keyout sensor-key.pem -out sensor-cert.pem \
    -subj "/CN=sloth-sensor-01"

# On the reader
openssl req -x509 -newkey rsa:4096 -days 825 -nodes \
    -keyout reader-key.pem -out reader-cert.pem \
    -subj "/CN=sloth-reader-01"
```

Then swap the **certificates only** (never the keys):

- copy `reader-cert.pem` to the sensor as `reader-ca.pem`
- copy `sensor-cert.pem` to the reader as `sensor-ca.pem`

```sh
sudo install -d -m 0700 -o stunnel4 -g stunnel4 /etc/stunnel/certs
sudo install -m 0600 -o stunnel4 -g stunnel4 *-key.pem  /etc/stunnel/certs/
sudo install -m 0644 -o stunnel4 -g stunnel4 *-cert.pem /etc/stunnel/certs/
sudo install -m 0644 -o stunnel4 -g stunnel4 *-ca.pem   /etc/stunnel/certs/
```

Keys are `0600`. A key that is group- or world-readable makes the rest
of this pointless.

**2. Edit the config.** In `sensor.conf` set `accept` to the sensor's
real address. In `reader.conf` set `connect` to the sensor's hostname
and `checkHost` to the sensor cert's CN.

**3. Start sloth on loopback** — no opt-in flag, by design:

```sh
sloth --headless --data-socket          # tcp:127.0.0.1:8765
```

**4. Run stunnel** on each host:

```sh
sudo install -d -m 0755 -o stunnel4 -g stunnel4 /run/stunnel /var/log/stunnel
sudo stunnel /etc/stunnel/sensor.conf    # sensor
sudo stunnel /etc/stunnel/reader.conf    # reader
```

**5. Verify** from the reader:

```sh
nc 127.0.0.1 8765 | head -3
```

JSONL records means the path works end to end. Nothing, with
`Connection refused` in the reader's stunnel log, usually means the
sensor rejected the client certificate — check `verify`/`CAfile` on
the sensor side first.

---

## Notes

- **`verify = 2` on both sides is not optional here.** One-sided TLS
  gives you privacy from a passive listener and nothing against an
  active one: any host that reaches port 8766 completes the handshake
  and reads the whole stream. The data includes bystander PNLs,
  hostnames and captured credential material, so authenticating the
  peer is the baseline, not an enhancement.
- **Certificates expire.** `-days 825` is about 27 months. This is the
  lifecycle cost that keeping crypto out of sloth pushes onto the
  deployment — real, but owned by a component built for it. Put the
  expiry in whatever reminds you about expiries.
- **Prefer the UNIX socket where you can.** If the consumer is on the
  sensor itself, `--data-socket unix:/run/sloth.sock` needs none of
  this: 0600 plus the kernel's peer check is stronger than any of it,
  with nothing to rotate.
- **Not a sloth component.** These files are templates for an external
  tool. sloth neither reads nor validates them, and nothing here
  changes sloth's own behaviour — it is still bound to loopback.

## See also

- [`docs/wiki/data-socket-exposure.md`](../../docs/wiki/data-socket-exposure.md)
  — the trust boundary and all three supported remote paths.
- [`../forwarder/`](../forwarder/) — push to a SIEM instead of exposing
  a port at all. Usually the better answer.
- [`../consumer/`](../consumer/) — reference reader for the stream.
