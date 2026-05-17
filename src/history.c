#include <string.h>
#include "sloth.h"
#include "history.h"

iface_hist_t *history_find(sloth_state_t *s, const char *name) {
    iface_hist_t *empty = NULL;
    for (int i = 0; i < MAX_IFACES; i++) {
        if (strncmp(s->iface_hist[i].name, name, 16) == 0)
            return &s->iface_hist[i];
        if (!empty && s->iface_hist[i].name[0] == '\0')
            empty = &s->iface_hist[i];
    }
    if (empty) {
        size_t nl = strlen(name);
        if (nl >= 16) nl = 15;
        memcpy(empty->name, name, nl);
        empty->name[nl] = '\0';
    }
    return empty;
}

void history_update(sloth_state_t *s) {
    for (int i = 0; i < s->iface_count; i++) {
        const iface_stat_t *iface = &s->ifaces[i];
        iface_hist_t *h = history_find(s, iface->name);
        if (!h) continue;
        h->rx[h->head] = iface->rx_rate;
        h->tx[h->head] = iface->tx_rate;
        h->head = (h->head + 1) % HIST_LEN;
        if (h->count < HIST_LEN) h->count++;
    }
}
