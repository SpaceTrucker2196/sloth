/* The kernel's IPv6 neighbour cache (RFC 4861 §7.3.2), read over
 * rtnetlink RTM_GETNEIGH, into the same arp_entry_t rows /proc/net/arp
 * fills for IPv4 (#176). The two are the same thing - what this host
 * currently believes about address-to-MAC bindings on its interfaces -
 * and /proc has no file for the IPv6 half, so it is a netlink dump.
 *
 * linux_neigh_parse() is the pure half: it walks one recv()'s worth of
 * netlink messages and appends a row per RTM_NEWNEIGH that carries a
 * destination and a link-layer address and is in a resolved state, the
 * same filter the /proc reader applies when it skips all-zero MACs.
 * The interface name comes through `ifname`, so the parser needs no
 * kernel to run against hand-built messages. linux_neigh6_fill() is
 * the socket half. */
#ifndef SLOTH_LINUX_NEIGH_H
#define SLOTH_LINUX_NEIGH_H

#include <stddef.h>
#include "sloth.h"

/* Append the resolved AF_INET6 neighbours in `buf` (len bytes of
 * netlink messages) to out[n..max). Returns the new n. *done is set
 * when NLMSG_DONE or NLMSG_ERROR ends the dump. `ifname` writes the
 * name of a kernel interface index, returning 0 on success; a NULL or
 * failing one leaves the row's iface empty. */
typedef int (*linux_ifname_fn)(int ifindex, char *out, size_t outsz);
int linux_neigh_parse(const void *buf, size_t len, arp_entry_t *out, int max,
                      int n, int *done, linux_ifname_fn ifname);

/* Dump the kernel's IPv6 neighbour cache into out[n..max). Returns the
 * new n; n unchanged when netlink is unavailable. */
int linux_neigh6_fill(arp_entry_t *out, int max, int n);

#endif
