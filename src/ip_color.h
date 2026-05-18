#ifndef IP_COLOR_H
#define IP_COLOR_H

#include <stdint.h>
#include "sloth.h"

/* Per-row packet category. Drives the row background grey shade and the
 * matching background for the DNS / ICMP log panels. */
typedef enum {
    PKT_CAT_OTHER = 0,
    PKT_CAT_TCP   = 1,
    PKT_CAT_UDP   = 2,
    PKT_CAT_DNS   = 3,
    PKT_CAT_ICMP  = 4,
    PKT_CAT_COUNT
} pkt_category_t;

/* Classify a packet by IP proto and ports. UDP/53 + TCP/53 -> DNS;
 * everything else falls back to TCP / UDP / ICMP / OTHER. */
pkt_category_t pkt_categorize(int proto, uint16_t sport, uint16_t dport);

/* Source bits set when an IP appears in a particular dashboard data
 * source. An IP whose source mask has >1 bit set is considered cross-
 * panel and gets rendered bold. */
#define IP_SRC_CONN   (1 << 0)
#define IP_SRC_PKT    (1 << 1)
#define IP_SRC_ARP    (1 << 2)
#define IP_SRC_DNS    (1 << 3)
#define IP_SRC_ICMP   (1 << 4)
#define IP_SRC_ALERT  (1 << 5)
#define IP_SRC_DEV    (1 << 6)

#define IP_NUM_COLORS 8

/* Hash-derived 0..IP_NUM_COLORS-1 index — same input always yields the
 * same colour. */
int  ip_color_index(const char *ip);

/* Per-frame index: clear it at the top of a draw, add the IPs from each
 * source, then ask is_cross_panel during row rendering. */
void ip_index_clear(void);
void ip_index_add  (const char *ip, int src_bit);
int  ip_index_is_cross_panel(const char *ip);

/* Convenience: rebuild the entire index from the current sloth state. */
void ip_index_build(const sloth_state_t *s);

#endif /* IP_COLOR_H */
