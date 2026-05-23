#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "bandwidth.h"

/* ── Internal per-connection tracking entry ─────────────────── */

typedef struct {
    char     local_addr[46];
    uint16_t local_port;
    char     remote_addr[46];
    uint16_t remote_port;
    int      proto;
    int      active;         /* reset each poll; set when matched */
    uint64_t rx_accum;       /* cumulative attributed bytes (RX) */
    uint64_t tx_accum;       /* cumulative attributed bytes (TX) */
    uint64_t rx_last;        /* accum at last rate computation */
    uint64_t tx_last;
    struct timespec ts;      /* timestamp of last rate computation */
    /* sparkline state lives here; copied to conn_bw_t each poll */
    float    rx_hist[CONN_BW_HIST];
    float    tx_hist[CONN_BW_HIST];
    int      hist_head;
    int      hist_count;
} bw_entry_t;

static bw_entry_t g_bw[MAX_CONNS];
static int        g_bw_n = 0;

void bw_reset(void) {
    memset(g_bw, 0, sizeof(g_bw));
    g_bw_n = 0;
}

/* ── Internal helpers ───────────────────────────────────────── */

static bw_entry_t *bw_find(const char *la, uint16_t lp,
                            const char *ra, uint16_t rp, int proto) {
    for (int i = 0; i < g_bw_n; i++) {
        bw_entry_t *e = &g_bw[i];
        if (e->proto      == proto &&
            e->local_port  == lp   &&
            e->remote_port == rp   &&
            strcmp(e->local_addr,  la) == 0 &&
            strcmp(e->remote_addr, ra) == 0)
            return e;
    }
    return NULL;
}

static bw_entry_t *bw_get_or_create(const conn_t *c,
                                     const struct timespec *now) {
    bw_entry_t *e = bw_find(c->local_addr,  c->local_port,
                             c->remote_addr, c->remote_port, c->proto);
    if (e) return e;
    if (g_bw_n >= MAX_CONNS) return NULL;
    e = &g_bw[g_bw_n++];
    memset(e, 0, sizeof(*e));
    memcpy(e->local_addr,  c->local_addr,  sizeof(e->local_addr));
    memcpy(e->remote_addr, c->remote_addr, sizeof(e->remote_addr));
    e->local_port  = c->local_port;
    e->remote_port = c->remote_port;
    e->proto       = c->proto;
    e->ts          = *now;
    return e;
}

/* ── Public API ─────────────────────────────────────────────── */

void bw_update(sloth_state_t *s) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    /* mark all entries inactive */
    for (int i = 0; i < g_bw_n; i++)
        g_bw[i].active = 0;

    /* sync with current connection set */
    for (int i = 0; i < s->conn_count; i++) {
        bw_entry_t *e = bw_get_or_create(&s->conns[i], &now);
        if (e) e->active = 1;
    }

#ifdef WITH_PCAP
    /* attribute new packets to connections by 5-tuple */
    int new_pkts = (s->pkt_head - s->pkt_bw_cursor + MAX_PACKETS) % MAX_PACKETS;
    /* if entire ring was overwritten between polls, cap */
    if (new_pkts > MAX_PACKETS) new_pkts = MAX_PACKETS;

    for (int i = 0; i < new_pkts; i++) {
        int idx = (s->pkt_bw_cursor + i) % MAX_PACKETS;
        const packet_info_t *p = &s->packets[idx];
        if (!p->len || !p->proto) continue;

        for (int j = 0; j < g_bw_n; j++) {
            bw_entry_t *e = &g_bw[j];
            if (!e->active || e->proto != p->proto) continue;
            /* TX: packet src = local, dst = remote */
            if (e->local_port  == p->src_port &&
                e->remote_port == p->dst_port &&
                strcmp(e->local_addr,  p->src) == 0 &&
                strcmp(e->remote_addr, p->dst) == 0) {
                e->tx_accum += p->len;
                break;
            }
            /* RX: packet dst = local, src = remote */
            if (e->local_port  == p->dst_port &&
                e->remote_port == p->src_port &&
                strcmp(e->local_addr,  p->dst) == 0 &&
                strcmp(e->remote_addr, p->src) == 0) {
                e->rx_accum += p->len;
                break;
            }
        }
    }
#endif /* WITH_PCAP */
    s->pkt_bw_cursor = s->pkt_head;

    /* compute rates, push sparkline samples, build public snapshot */
    int out = 0;
    for (int i = 0; i < g_bw_n; i++) {
        bw_entry_t *e = &g_bw[i];
        if (!e->active || out >= MAX_CONNS) continue;

        double dt = (double)(now.tv_sec  - e->ts.tv_sec)
                  + (double)(now.tv_nsec - e->ts.tv_nsec) / 1e9;
        double rx_rate = 0.0, tx_rate = 0.0;
        if (dt > 0.001) {
            rx_rate = (double)(e->rx_accum - e->rx_last) / dt;
            tx_rate = (double)(e->tx_accum - e->tx_last) / dt;
        }
        e->rx_last = e->rx_accum;
        e->tx_last = e->tx_accum;
        e->ts      = now;

        /* push to sparkline ring */
        e->rx_hist[e->hist_head] = (float)rx_rate;
        e->tx_hist[e->hist_head] = (float)tx_rate;
        e->hist_head = (e->hist_head + 1) % CONN_BW_HIST;
        if (e->hist_count < CONN_BW_HIST) e->hist_count++;

        /* copy to public conn_bw snapshot */
        conn_bw_t *bw = &s->conn_bw[out++];
        memcpy(bw->local_addr,  e->local_addr,  sizeof(bw->local_addr));
        memcpy(bw->remote_addr, e->remote_addr, sizeof(bw->remote_addr));
        bw->local_port  = e->local_port;
        bw->remote_port = e->remote_port;
        bw->proto       = e->proto;
        bw->rx_rate     = rx_rate;
        bw->tx_rate     = tx_rate;
        bw->rx_bytes    = e->rx_accum;
        bw->tx_bytes    = e->tx_accum;
        memcpy(bw->rx_hist, e->rx_hist, sizeof(bw->rx_hist));
        memcpy(bw->tx_hist, e->tx_hist, sizeof(bw->tx_hist));
        bw->hist_head   = e->hist_head;
        bw->hist_count  = e->hist_count;
    }
    s->conn_bw_count = out;

    /* compact: remove evicted (inactive) entries */
    int n = 0;
    for (int i = 0; i < g_bw_n; i++) {
        if (g_bw[i].active)
            g_bw[n++] = g_bw[i];
    }
    g_bw_n = n;
}

const conn_bw_t *bw_lookup(const sloth_state_t *s, const conn_t *c) {
    for (int i = 0; i < s->conn_bw_count; i++) {
        const conn_bw_t *bw = &s->conn_bw[i];
        if (bw->proto      == c->proto      &&
            bw->local_port  == c->local_port  &&
            bw->remote_port == c->remote_port &&
            strcmp(bw->local_addr,  c->local_addr)  == 0 &&
            strcmp(bw->remote_addr, c->remote_addr) == 0)
            return bw;
    }
    return NULL;
}

void bw_fmt_rate(double bps, char *buf, int sz) {
    if (bps >= 1e9)      snprintf(buf, sz, "%.1fG", bps / 1e9);
    else if (bps >= 1e6) snprintf(buf, sz, "%.1fM", bps / 1e6);
    else if (bps >= 1e3) snprintf(buf, sz, "%.1fK", bps / 1e3);
    else if (bps >  0.0) snprintf(buf, sz, "%.0fB", bps);
    else                 snprintf(buf, sz, "--");
}
