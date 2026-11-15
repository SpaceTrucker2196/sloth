#include <stdio.h>
#include <string.h>

#include "sys_status.h"
#include "ble_hci.h"
#include "bt_stream.h"
#include "capture/capture.h"

/* The capture side's source rows (#213): the IP capture, the monitor
 * radio, the Bluetooth HCI monitor and the Ubertooth stream. Out of
 * src/sys_status.c, unchanged, so that file no longer names the
 * capture; src/sys_status.h says what registers this and what a daemon
 * without it reports. */

static void pcap_source(sys_source_t *o, const capture_health_t *h, const char *err) {
    o->count  = h->ps_recv;
    o->errors = h->ps_drop + h->ps_ifdrop;
    o->age_s  = h->stale_secs;
    if (!h->open) {
        o->state = SYS_ST_DOWN;
        snprintf(o->detail, sizeof(o->detail), "%s", err && err[0] ? err : "not open");
    } else if (!h->running) {
        o->state = SYS_ST_DOWN;
        snprintf(o->detail, sizeof(o->detail), "exit: %s%s%.60s",
                 capture_exit_name((capture_exit_t)h->exit_reason),
                 h->exit_detail[0] ? ": " : "", h->exit_detail);
    } else if (h->stale_secs < 0) {
        o->state = SYS_ST_STALE;
        snprintf(o->detail, sizeof(o->detail), "no frame yet");
    } else {
        o->state = h->stale_secs > SYS_SRC_STALE_S ? SYS_ST_STALE : SYS_ST_OK;
    }
}

void sys_status_capture_fill(const sloth_state_t *s, sys_source_t *src) {
    sys_source_t *o;

    o = &src[SYS_SRC_CAPTURE];
    o->name = "capture"; o->flag = "--iface"; o->unit = "frames";
    o->age_s = -1;
    snprintf(o->endpoint, sizeof(o->endpoint), "%s", s->pkt_iface);
    snprintf(o->kind, sizeof(o->kind), "%s",
             s->pkt_linktype == 127 ? "wifi-monitor"
             : sys_status_cap_wireless(s->pkt_iface)
               ? "wifi-managed" : "ip-capture");
    if (!s->pkt_iface[0]) {
#ifdef WITH_PCAP
        snprintf(o->detail, sizeof(o->detail), "no capture interface");
#else
        snprintf(o->detail, sizeof(o->detail), "built without libpcap");
#endif
    } else {
        pcap_source(o, &s->cap_health, "");
        sys_status_tie(o, s->pkt_iface);
    }

    o = &src[SYS_SRC_MONITOR];
    o->name = "monitor"; o->flag = "a monitor-mode interface"; o->unit = "frames";
    o->age_s = -1;
    snprintf(o->kind, sizeof(o->kind), "wifi-monitor");
    snprintf(o->endpoint, sizeof(o->endpoint), "%s", s->probe_iface);
    if (!s->probe_iface[0]) {
#ifdef WITH_PCAP
        snprintf(o->detail, sizeof(o->detail), "%s",
                 s->probe_err[0] ? s->probe_err : "no monitor-mode interface found");
#else
        snprintf(o->detail, sizeof(o->detail), "built without libpcap");
#endif
    } else {
        pcap_source(o, &s->mon_health, s->probe_err);
        sys_status_tie(o, s->probe_iface);
    }

    o = &src[SYS_SRC_BTMON];
    o->name = "btmon"; o->flag = "--bt-monitor"; o->unit = "records";
    o->age_s = -1;
    snprintf(o->kind, sizeof(o->kind), "bluetooth");
    snprintf(o->endpoint, sizeof(o->endpoint), "%s", s->bt_iface);
    if (!s->bt_iface[0]) {
        snprintf(o->detail, sizeof(o->detail), "%s", s->bt_err);
    } else {
        /* The monitor channel carries every controller: no one hci to
         * tie it to. */
        pcap_source(o, &s->bt_health, s->bt_err);
        o->count  = s->ble_host.records;
        o->errors = s->ble_host.malformed;
    }

    o = &src[SYS_SRC_BTCAP];
    o->name = "btcap"; o->flag = "--bt-capture"; o->unit = "records";
    o->age_s = -1;
    snprintf(o->kind, sizeof(o->kind), "bluetooth-sniffer");
    if (s->btcap.configured) {
        const bt_capture_health_t *c = &s->btcap;
        snprintf(o->endpoint, sizeof(o->endpoint), "%s", BT_CAPTURE_IFACE);
        o->count = c->recv; o->errors = c->drop; o->age_s = c->stale_secs;
        snprintf(o->detail, sizeof(o->detail), "%s%s%.70s", bt_cap_state_name(c->state),
                 c->err[0] ? ": " : "", c->err);
        if (c->state == BT_CAP_STREAMING)
            o->state = (c->stale_secs < 0 || c->stale_secs > SYS_SRC_STALE_S)
                       ? SYS_ST_STALE : SYS_ST_OK;
        else
            o->state = c->state == BT_CAP_WAITING ? SYS_ST_STALE : SYS_ST_DOWN;
    }
}
