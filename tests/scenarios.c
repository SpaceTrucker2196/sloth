#include <string.h>
#include <math.h>
#include <stdio.h>

#include "ntop.h"
#include "scenarios.h"

/* ── helpers ────────────────────────────────────────────── */

static iface_stat_t make_iface(const char *name,
                                double rx_rate, double tx_rate,
                                uint64_t rx_bytes, uint64_t tx_bytes) {
    iface_stat_t s;
    memset(&s, 0, sizeof(s));
    snprintf(s.name, sizeof(s.name), "%s", name);
    s.rx_rate   = rx_rate;
    s.tx_rate   = tx_rate;
    s.rx_bytes  = rx_bytes;
    s.tx_bytes  = tx_bytes;
    return s;
}

static conn_t make_conn(const char *local, uint16_t lport,
                         const char *remote, uint16_t rport,
                         int proto, int state) {
    conn_t c;
    memset(&c, 0, sizeof(c));
    snprintf(c.local_addr,  sizeof(c.local_addr),  "%s", local);
    snprintf(c.remote_addr, sizeof(c.remote_addr), "%s", remote);
    c.local_port  = lport;
    c.remote_port = rport;
    c.proto = proto;
    c.state = state;
    return c;
}

static wifi_ap_t make_ap(const char *ssid, const char *bssid,
                          int dbm, int ch, const char *enc) {
    wifi_ap_t ap;
    memset(&ap, 0, sizeof(ap));
    snprintf(ap.ssid,  sizeof(ap.ssid),  "%s", ssid);
    snprintf(ap.bssid, sizeof(ap.bssid), "%s", bssid);
    ap.signal_dbm = dbm;
    ap.channel    = ch;
    snprintf(ap.enc, sizeof(ap.enc), "%s", enc);
    return ap;
}

/* ── scenarios ───────────────────────────────────────────── */

void scenario_empty(void) {
    fake_net_reset();
}

void scenario_idle(void) {
    fake_net_reset();

    g_fake_net.ifaces[0] = make_iface("eth0",  120e3, 45e3, 1234567, 890123);
    g_fake_net.ifaces[1] = make_iface("wlan0",  80e3, 20e3,  654321, 123456);
    g_fake_net.ifaces[2] = make_iface("lo",      1e3,  1e3,    9999,   9999);
    g_fake_net.iface_count = 3;

    g_fake_net.conns[0] = make_conn("192.168.1.10", 54321, "8.8.8.8",    53,  PROTO_UDP, 0);
    g_fake_net.conns[1] = make_conn("192.168.1.10", 49152, "1.1.1.1",   443,  PROTO_TCP, 1);
    g_fake_net.conns[2] = make_conn("192.168.1.10", 49200, "93.184.216.34", 443, PROTO_TCP, 1);
    g_fake_net.conns[3] = make_conn("0.0.0.0",     22,    "0.0.0.0",     0,  PROTO_TCP, 10);
    g_fake_net.conns[4] = make_conn("127.0.0.1",  6010,   "127.0.0.1", 6011, PROTO_TCP, 1);
    g_fake_net.conn_count = 5;

    g_fake_net.aps[0] = make_ap("HomeNetwork",    "AA:BB:CC:DD:EE:01", -45, 6,  "WPA2");
    g_fake_net.aps[1] = make_ap("Neighbor_2.4G",  "AA:BB:CC:DD:EE:02", -72, 11, "WPA2");
    g_fake_net.aps[2] = make_ap("CoffeeShop",     "AA:BB:CC:DD:EE:03", -80, 1,  "OPEN");
    g_fake_net.ap_count = 3;
}

void scenario_busy(void) {
    fake_net_reset();

    g_fake_net.ifaces[0] = make_iface("eth0",  980e6, 450e6,
                                       (uint64_t)500e9, (uint64_t)200e9);
    g_fake_net.iface_count = 1;

    /* simulate many established connections */
    for (int i = 0; i < 200; i++) {
        char src[32], dst[32];
        snprintf(src, sizeof(src), "10.0.%d.%d", i / 256, i % 256);
        snprintf(dst, sizeof(dst), "203.0.113.%d", i % 256);
        g_fake_net.conns[i] = make_conn(src, (uint16_t)(50000 + i),
                                         dst, 443, PROTO_TCP, 1);
    }
    g_fake_net.conn_count = 200;

    g_fake_net.aps[0] = make_ap("OfficeAP",  "00:11:22:33:44:55", -38, 36, "WPA3");
    g_fake_net.ap_count = 1;
}

void scenario_many_conns(void) {
    fake_net_reset();

    g_fake_net.ifaces[0] = make_iface("eth0", 50e6, 25e6, (uint64_t)10e9, (uint64_t)5e9);
    g_fake_net.iface_count = 1;

    int n = 0;
    /* 300 TCP ESTABLISHED */
    for (int i = 0; i < 300 && n < MAX_CONNS; i++, n++) {
        char src[32], dst[32];
        snprintf(src, sizeof(src), "192.168.1.%d", (i % 254) + 1);
        snprintf(dst, sizeof(dst), "172.16.%d.%d", i / 254, i % 254);
        g_fake_net.conns[n] = make_conn(src, (uint16_t)(40000 + i),
                                         dst, 443, PROTO_TCP, 1);
    }
    /* 100 TCP LISTEN */
    for (int i = 0; i < 100 && n < MAX_CONNS; i++, n++) {
        char src[32];
        snprintf(src, sizeof(src), "0.0.0.0");
        g_fake_net.conns[n] = make_conn(src, (uint16_t)(i + 1),
                                         "0.0.0.0", 0, PROTO_TCP, 10);
    }
    /* 100 UDP */
    for (int i = 0; i < 100 && n < MAX_CONNS; i++, n++) {
        char src[32], dst[32];
        snprintf(src, sizeof(src), "192.168.1.100");
        snprintf(dst, sizeof(dst), "8.8.%d.%d", i / 256, i % 256);
        g_fake_net.conns[n] = make_conn(src, (uint16_t)(10000 + i),
                                         dst, 53, PROTO_UDP, 0);
    }
    g_fake_net.conn_count = n;
}

void scenario_wifi_crowded(void) {
    fake_net_reset();

    g_fake_net.ifaces[0] = make_iface("wlan0", 5e6, 1e6, 50000000, 10000000);
    g_fake_net.iface_count = 1;

    static const struct { const char *ssid; int dbm; int ch; const char *enc; } aps[] = {
        { "Apartment_5A",     -33,  1,  "WPA2"  },
        { "Apartment_5B",     -47,  6,  "WPA2"  },
        { "XFINITY_GUEST",    -51,  11, "OPEN"  },
        { "Office_5GHz",      -38,  36, "WPA3"  },
        { "Office_2.4GHz",    -44,  6,  "WPA2"  },
        { "IoT_Network",      -62,  1,  "WPA2"  },
        { "Printer_Network",  -70,  11, "WPA2"  },
        { "ATT_Guest",        -75,  6,  "OPEN"  },
        { "DIRECT-Roku",      -80,  11, "WPA2"  },
        { "Neighbor_5GHz_1",  -55,  149,"WPA2"  },
        { "Neighbor_5GHz_2",  -61,  153,"WPA2"  },
        { "Neighbor_2.4G_1",  -68,  1,  "WPA2"  },
        { "Neighbor_2.4G_2",  -72,  6,  "WEP"   },
        { "",                 -85,  11, "OPEN"  }, /* hidden SSID */
        { "VPN_Hotspot",      -58,  40, "WPA2"  },
        { "Lab_Isolated",     -42,  100,"WPA3"  },
        { "TestAP_NoEnc",     -90,  6,  "OPEN"  },
        { "UPnP_Device_42",   -77,  11, "WPA2"  },
        { "5G_Backhaul",      -35,  36, "WPA3"  },
        { "Mesh_Node_3",      -41,  6,  "WPA2"  },
    };
    int nap = (int)(sizeof(aps) / sizeof(aps[0]));
    if (nap > MAX_WIFI_APS) nap = MAX_WIFI_APS;

    for (int i = 0; i < nap; i++) {
        char bssid[18];
        snprintf(bssid, sizeof(bssid), "AA:BB:CC:DD:%02X:%02X", i / 16, i % 16);
        g_fake_net.aps[i] = make_ap(aps[i].ssid, bssid,
                                     aps[i].dbm, aps[i].ch, aps[i].enc);
    }
    g_fake_net.ap_count = nap;
}

void scenario_no_wifi(void) {
    scenario_idle();
    g_fake_net.ap_count = 0;
}

/* ── simulation ──────────────────────────────────────────── */

void scenario_simulate_step(void) {
    double t = g_fake_net.tick * 0.4;
    for (int i = 0; i < g_fake_net.iface_count; i++) {
        double base_rx = 50e6 * (i + 1);
        double base_tx = 20e6 * (i + 1);
        g_fake_net.ifaces[i].rx_rate = base_rx * (0.5 + 0.5 * sin(t + i * 0.7));
        g_fake_net.ifaces[i].tx_rate = base_tx * (0.5 + 0.5 * cos(t + i * 0.9));
        g_fake_net.ifaces[i].rx_bytes += (uint64_t)g_fake_net.ifaces[i].rx_rate;
        g_fake_net.ifaces[i].tx_bytes += (uint64_t)g_fake_net.ifaces[i].tx_rate;
    }
    g_fake_net.tick++;
}
