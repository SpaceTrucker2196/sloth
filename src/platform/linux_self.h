/* The host's own link-layer addresses, for the self roster (#183).
 *
 * get_ifaces() already gives the self roster one address per row of
 * /proc/net/dev, capped at MAX_IFACES. That misses three kinds of
 * address the host really does own:
 *
 *   - the permanent (burned-in) address of an interface that is
 *     currently using a different one: NetworkManager's per-connection
 *     MAC randomisation and cloned addresses swap the netdev address,
 *     and the card goes back to its own the next time the setting
 *     changes. IFLA_PERM_ADDRESS (rtnetlink, Linux 5.5+) names it.
 *   - addresses a Wi-Fi phy will hand to an interface that does not
 *     exist yet: /sys/class/ieee80211/<phy>/macaddress and the
 *     `addresses` pool a new vif (a monitor vif, a second station, an
 *     AP) is given an address from.
 *   - wireless devices with no netdev at all: wpa_supplicant's P2P
 *     device (`p2p-dev-wlan0`), whose locally administered address
 *     sends P2P discovery probes, and NAN. Only nl80211's
 *     NL80211_CMD_GET_INTERFACE dump names them (linux_wifi.c, behind
 *     WITH_WIFI like every other nl80211 request).
 *
 * Every source is a read: an rtnetlink dump, an nl80211 dump, and
 * regular sysfs files. Nothing is configured (MISSION §2).
 *
 * The parsers are pure, so tests feed them hand-built netlink messages
 * and a fake sysfs (tests/fake_platform.c) with no kernel to run on;
 * linux_get_self_macs() is the socket half. */
#ifndef SLOTH_LINUX_SELF_H
#define SLOTH_LINUX_SELF_H

#include <stddef.h>
#include <stdint.h>

/* Append mac to out[0..n) unless it is all-zero, has the group bit set,
 * or is already there. Returns the new n (unchanged at max). */
int linux_self_append(uint8_t (*out)[6], int max, int n, const uint8_t mac[6]);

/* Parse one "aa:bb:cc:dd:ee:ff" token at the start of s. 0 on success. */
int linux_self_parse_mac(const char *s, uint8_t mac[6]);

/* Append the IFLA_ADDRESS and IFLA_PERM_ADDRESS of every RTM_NEWLINK
 * in buf (len bytes of netlink messages from one recv()) that is six
 * bytes long; tunnel and InfiniBand addresses are other lengths and
 * are not 802 addresses. *done is set on NLMSG_DONE or NLMSG_ERROR.
 * Returns the new n. */
int linux_self_parse_links(const void *buf, size_t len, uint8_t (*out)[6],
                           int max, int n, int *done);

/* Every Wi-Fi phy's macaddress and addresses pool, read through the
 * given sysfs reader and lister (the shape of g_platform.sys_read /
 * sys_list). Either NULL reads nothing. Returns the new n. */
typedef int (*linux_self_read_fn)(const char *path, char *buf, int cap);
typedef int (*linux_self_list_fn)(const char *dir, char *names, int name_sz,
                                  int max);
int linux_self_phy_macs(linux_self_read_fn rd, linux_self_list_fn ls,
                        uint8_t (*out)[6], int max, int n);

/* The host's own addresses from all three sources into out[0..max).
 * Returns how many; 0 when no source answers. */
int linux_get_self_macs(uint8_t (*out)[6], int max);

#endif
