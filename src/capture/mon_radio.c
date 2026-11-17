/* The sensor radios beside radio 0; see mon_radio.h. */
#include "capture/mon_radio.h"

#include <stdio.h>
#include <string.h>

#include "mon_radios.h"

#ifdef WITH_PCAP

#include <pcap.h>
#include <pthread.h>
#include <stdint.h>

#include "sloth.h"
#include "ble_hci.h"
#include "capture/probe_internal.h"
#include "run_flag.h"
#include "worker_thread.h"

typedef struct {
    int                radio;        /* mon_radios.c's index, 1.. */
    pcap_t            *ph;
    pthread_t          thread;
    capture_run_flag_t running;
} mr_t;

static mr_t g_x[MON_RADIO_MAX];
static int  g_n;
static int  g_init;

static void init_once(void) {
    if (g_init) return;
    for (int i = 0; i < MON_RADIO_MAX; i++) {
        memset(&g_x[i], 0, sizeof(g_x[i]));
        capture_run_flag_t f = CAPTURE_RUN_FLAG_INIT;
        g_x[i].running = f;
    }
    g_init = 1;
}

int mon_radio_open(int radio, const char *iface, char *err, size_t errsz) {
    init_once();
    if (err && errsz) err[0] = '\0';
    if (radio < 1 || radio >= MON_RADIO_MAX || !iface || !iface[0] ||
        strlen(iface) >= 16 || g_n >= MON_RADIO_MAX) {
        if (err) snprintf(err, errsz, "not a sensor radio");
        return 0;
    }
    /* The checks probe.c makes of a pinned radio 0, in its words. */
    int type = probe_iface_type(iface);
    if (type == -1) {
        if (err) snprintf(err, errsz, "monitor iface %.15s not found", iface);
        return 0;
    }
    if (type == -2) {
        if (err) snprintf(err, errsz, "monitor iface %.15s: type unreadable", iface);
        return 0;
    }
    if (type != 803) {
        if (err) snprintf(err, errsz, "monitor iface %.15s is not in monitor "
                                      "mode (type %d)", iface, type);
        return 0;
    }
    if (bt_dev_is_raw_hci(iface)) {
        if (err) snprintf(err, errsz, "%.15s refused: raw HCI device", iface);
        return 0;
    }
    char eb[PCAP_ERRBUF_SIZE];
    /* Radio 0's snaplen and buffer timeout: these frames are parsed
     * whole, as its are. */
    pcap_t *ph = pcap_open_live(iface, 65535, 1, 100, eb);
    if (!ph) {
        if (err) snprintf(err, errsz, "pcap(%.15s): %.50s", iface, eb);
        return 0;
    }
    if (pcap_datalink(ph) != DLT_IEEE802_11_RADIO) {
        if (err) snprintf(err, errsz, "%.15s: DLT %d not radiotap", iface,
                          pcap_datalink(ph));
        pcap_close(ph);
        return 0;
    }
    mr_t *r = &g_x[g_n++];
    r->radio = radio;
    r->ph = ph;
    mon_radios_set_state(radio, MON_RADIO_OPEN, "");
    return 1;
}

static void *reader(void *arg) {
    mr_t *r = arg;
    int rc = 0;
    while (capture_run_flag_get(&r->running)) {
        rc = pcap_dispatch(r->ph, 32, probe_radio_frame,
                           (u_char *)(intptr_t)r->radio);
        if (rc < 0) break;
    }
    /* A stop request reads as stopped whatever dispatch returned; any
     * other way out of the loop is the radio gone (a USB adapter off
     * the bus is PCAP_ERROR with libpcap's text, kept as the reason). */
    if (!capture_run_flag_get(&r->running)) {
        mon_radios_set_state(r->radio, MON_RADIO_STOPPED, "");
    } else {
        char why[80];
        const char *e = rc == PCAP_ERROR ? pcap_geterr(r->ph) : "";
        snprintf(why, sizeof(why), "%.79s",
                 e && e[0] ? e : "capture ended");
        mon_radios_set_state(r->radio, MON_RADIO_LOST, why);
    }
    return NULL;
}

void mon_radio_run(void) {
    for (int i = 0; i < g_n; i++) {
        mr_t *r = &g_x[i];
        if (!r->ph || capture_run_flag_get(&r->running)) continue;
        capture_run_flag_set(&r->running, 1);
        mon_radios_set_state(r->radio, MON_RADIO_RUNNING, "");
        if (worker_thread_create(&r->thread, reader, r) != 0) {
            capture_run_flag_set(&r->running, 0);
            mon_radios_set_state(r->radio, MON_RADIO_LOST,
                                 "reader thread not started");
        }
    }
}

void mon_radio_stop(void) {
    for (int i = 0; i < g_n; i++) {
        mr_t *r = &g_x[i];
        /* The flag stays 1 after a reader ends on its own, so a lost
         * radio's thread is joined here like a running one's. */
        if (capture_run_flag_take(&r->running)) {
            if (r->ph) pcap_breakloop(r->ph);
            pthread_join(r->thread, NULL);
        }
        if (r->ph) { pcap_close(r->ph); r->ph = NULL; }
    }
    g_n = 0;
}

#else  /* !WITH_PCAP */

int  mon_radio_open(int radio, const char *iface, char *err, size_t errsz) {
    (void)radio; (void)iface;
    if (err && errsz) err[0] = '\0';
    return 0;
}
void mon_radio_run(void) {}
void mon_radio_stop(void) {}

#endif
