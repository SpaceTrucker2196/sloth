#ifndef SLOTH_DISCOVERY_H
#define SLOTH_DISCOVERY_H

#include <stddef.h>

/* Optional LAN service advertisement for the read-only data socket
 * (issue #29). When the operator has bound `--data-socket` to a
 * *routable* TCP address, sloth can drop an Avahi service file so the
 * host's mDNS responder advertises `_sloth._tcp` — letting the sloth-ios
 * client discover it by name instead of typing host:port.
 *
 * It is one of the opt-in network-using services MISSION §2 rule 1
 * permits (alongside --allow-active's PTR query), and is disabled with
 * `--no-discovery`. sloth itself transmits nothing: it writes a config
 * file that a separate daemon (avahi-daemon) may use to announce. For
 * loopback / unix data sockets — or no data socket — nothing is
 * published and sloth stays fully silent. */

/* Render the Avahi service-group XML for instance `instance` on `port`
 * into `buf`. Returns the number of bytes written (excluding the NUL),
 * or -1 on truncation / bad args. Pure and side-effect free — the
 * testable core. */
int discovery_service_xml(char *buf, size_t sz, const char *instance, int port);

/* If `data_socket_spec` is a TCP bind reachable from off-host, return
 * its port (> 0); otherwise (unix socket, anywhere in 127.0.0.0/8, or
 * malformed) return -1. "Routable" is exactly data_socket_spec_is_remote()
 * == 1 — the 0.0.0.0 wildcard included — and the port is the binder's
 * strict full-string parse, so what is advertised is what was bound.
 * sloth doesn't announce a socket only reachable from the same host. */
int discovery_routable_tcp_port(const char *data_socket_spec);

/* Publish a service file for `data_socket_spec` at `path` (NULL =
 * the default /etc/avahi/services/sloth.service). No-op returning -1
 * when the spec isn't a routable TCP bind, or when --strict is locked.
 * Returns 0 on a successful write.
 *
 * The write is symlink-safe (#134): the directory is pinned with
 * sfile_system_dir() — it must be root- or euid-owned and not
 * group/other-writable, so a 1777 /tmp is refused — the content goes
 * into an O_EXCL temp inside it and takes the final name by rename,
 * which replaces a planted link rather than following it. The file is
 * 0644 on purpose: avahi-daemon runs as `avahi` and must read it. The
 * directory descriptor is held until discovery_unpublish(). */
int discovery_publish(const char *data_socket_spec, const char *path);

/* Remove the service file previously written by discovery_publish(),
 * through the directory descriptor held since then. Safe to call when
 * nothing was published. */
void discovery_unpublish(void);

#endif /* SLOTH_DISCOVERY_H */
