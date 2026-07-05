#ifndef SLOTH_DISCOVERY_H
#define SLOTH_DISCOVERY_H

#include <stddef.h>

/* Optional LAN service advertisement for the read-only data socket
 * (issue #29). When the operator has bound `--data-socket` to a
 * *routable* TCP address, sloth can drop an Avahi service file so the
 * host's mDNS responder advertises `_sloth._tcp` — letting the sloth-ios
 * client discover it by name instead of typing host:port.
 *
 * This is the ONE place sloth's presence touches the network, so it is
 * gated behind MISSION §2's second opt-in carve-out and disabled with
 * `--no-discovery`. sloth itself transmits nothing: it writes a config
 * file that a separate daemon (avahi-daemon) may use to announce. For
 * loopback / unix data sockets — or no data socket — nothing is
 * published and sloth stays fully silent. */

/* Render the Avahi service-group XML for instance `instance` on `port`
 * into `buf`. Returns the number of bytes written (excluding the NUL),
 * or -1 on truncation / bad args. Pure and side-effect free — the
 * testable core. */
int discovery_service_xml(char *buf, size_t sz, const char *instance, int port);

/* If `data_socket_spec` is a TCP bind on a non-loopback host, return its
 * port (> 0); otherwise (unix socket, loopback, or malformed) return -1.
 * "Routable" here just means not 127.0.0.1 / ::1 / localhost — sloth
 * doesn't announce a socket only reachable from the same host. */
int discovery_routable_tcp_port(const char *data_socket_spec);

/* Publish a service file for `data_socket_spec` at `path` (NULL =
 * the default /etc/avahi/services/sloth.service). No-op returning -1
 * when the spec isn't a routable TCP bind. Returns 0 on a successful
 * write. Records the path so discovery_unpublish() can remove it. */
int discovery_publish(const char *data_socket_spec, const char *path);

/* Remove the service file previously written by discovery_publish().
 * Safe to call when nothing was published. */
void discovery_unpublish(void);

#endif /* SLOTH_DISCOVERY_H */
