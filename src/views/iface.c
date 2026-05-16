#include <stdio.h>
#include "ntop.h"
#include "tui.h"
#include "util.h"
#include "views/iface.h"

void view_iface_draw(const ntop_state_t *s) {
    char bar[32], r[16], t[16], rb[16], tb[16];

    TPRINT("  %-12s  %-12s  %-12s  %-10s  %-10s\n",
           "Interface", "RX Rate", "TX Rate", "Total RX", "Total TX");
    TPRINT("  %-12s  %-12s  %-12s  %-10s  %-10s\n",
           "------------", "------------", "------------",
           "----------", "----------");

    for (int i = 0; i < s->iface_count; i++) {
        const iface_stat_t *f = &s->ifaces[i];

        TPRINT("  %-12s  %-12s  %-12s  %-10s  %-10s\n",
               f->name,
               fmt_rate(f->rx_rate, r, (int)sizeof(r)),
               fmt_rate(f->tx_rate, t, (int)sizeof(t)),
               fmt_bytes(f->rx_bytes, rb, (int)sizeof(rb)),
               fmt_bytes(f->tx_bytes, tb, (int)sizeof(tb)));

        tui_bar(f->rx_rate, 100e6, 24, bar);
        TPRINT("  RX [%-24s]\n", bar);
        tui_bar(f->tx_rate, 100e6, 24, bar);
        TPRINT("  TX [%-24s]\n\n", bar);
    }

    if (s->iface_count == 0)
        TPRINT("  (no interfaces found)\n");
}
