#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "runner.h"
#include "tui.h"
#include "sloth.h"
#include "rf_distance.h"

/* Every list view's page at the documented minimum terminal, 100x33,
 * drawn through tui_draw() so the tab bar's wrapped rows - six of them
 * at 100 columns - are spent the way they are in the running program
 * (#150). And the same views on a large terminal, so the fix cannot
 * have bought the fit by shrinking the page.
 *
 * Each view used to size its page as LINES - 5 (or 6, 8, 12, 16) from
 * the top of its draw, as if the tab bar were one row. At 100x33 that
 * overran the screen by five rows or more: rows below the last screen
 * line were appended to it or lost, the selection could sit off the
 * screen, and a legend under the table was never drawn. The fix is
 * view_page_budget() (src/views/view_page.h), taken after the view's
 * headers, with the rows under the table named per view.
 *
 * What a case asserts, for a fixture with more rows than can fit and
 * the last row selected (so a page that is too long puts the selection
 * below the screen):
 *   - no line reaches column 100 (it would wrap and push every row
 *     under it down one);
 *   - nothing was drawn below the last row (tui_test_overflow());
 *   - the last table row is exactly `tail` rows above the bottom, and
 *     is the selected one: the page is neither too long nor short;
 *   - with a tail, its last line is the screen's last row.
 *
 * Every 100x33 case was seen to fail with its view's old page constant
 * restored, one view at a time, each then restored; the comment on
 * each test names what went red. */

#define FIT_ROWS 33
#define FIT_COLS 100
#define BIG_ROWS 60
#define BIG_COLS 200

typedef struct {
    const char *name;
    view_t      view;
    int       (*seed)(sloth_state_t *s, time_t now); /* rows seeded */
    const char *marker;   /* in every table row and in nothing else drawn */
    int         tail;     /* rows the view draws under its table */
    const char *last;     /* on the screen's last row, when tail > 0 */
    int         big_rows; /* 0: BIG_ROWS; less where the table's cap is small */
} fit_case_t;

static void ip_of(char *out, size_t n, int i) {
    snprintf(out, n, "10.9.%d.%d", i / 256, i % 256);
}

static void mac_of(uint8_t mac[6], uint8_t second, int i) {
    mac[0] = 0x02; mac[1] = second; mac[2] = 0; mac[3] = 0;
    mac[4] = (uint8_t)(i >> 8); mac[5] = (uint8_t)i;
}

/* ── fixtures ─────────────────────────────────────────────── */

/* A distance estimate with a trend, so every row carries the widest
 * cell and a three-octet arrow: the clip and the column plans have to
 * count it as one cell, not three. 27.4 m, building, approaching. */
static void dist_of(rf_track_t *t) {
    memset(t, 0, sizeof(*t));
    t->valid = 1; t->est_dm = 274; t->lo_dm = 120; t->hi_dm = 624;
    t->band = RF_DIST_BUILDING; t->trend = RF_TREND_APPROACHING;
    t->ptx_source = RF_PTX_ASSUMED; t->ptx_dbm = 20;
}

static int seed_ntp(sloth_state_t *s, time_t now) {
    s->ntp_log_count = MAX_NTP_LOG;
    for (int i = 0; i < s->ntp_log_count; i++) {
        ntp_log_entry_t *e = &s->ntp_log[i];
        ip_of(e->src, sizeof(e->src), i);
        snprintf(e->dst, sizeof(e->dst), "192.0.2.1");
        snprintf(e->mode, sizeof(e->mode), "client");
        snprintf(e->ref, sizeof(e->ref), "GPS");
        e->version = 4; e->stratum = 2; e->ts = now;
    }
    s->ntp_log_sel = s->ntp_log_count - 1;
    return s->ntp_log_count;
}

static int seed_quic(sloth_state_t *s, time_t now) {
    s->quic_log_count = MAX_QUIC_LOG;
    for (int i = 0; i < s->quic_log_count; i++) {
        quic_log_entry_t *e = &s->quic_log[i];
        ip_of(e->src, sizeof(e->src), i);
        snprintf(e->dst, sizeof(e->dst), "192.0.2.1");
        snprintf(e->host, sizeof(e->host), "%s",
                 "a-long-quic-hostname-that-fills-the-column.example");
        snprintf(e->ver, sizeof(e->ver), "v1");
        e->ts = now;
    }
    s->quic_log_sel = s->quic_log_count - 1;
    return s->quic_log_count;
}

static int seed_tls(sloth_state_t *s, time_t now) {
    s->tls_log_count = MAX_TLS_LOG;
    for (int i = 0; i < s->tls_log_count; i++) {
        tls_log_entry_t *e = &s->tls_log[i];
        ip_of(e->src, sizeof(e->src), i);
        snprintf(e->dst, sizeof(e->dst), "198.51.100.200");
        snprintf(e->host, sizeof(e->host), "%s",
                 "a-long-sni-hostname-that-fills-the-column.example");
        snprintf(e->tls_ver, sizeof(e->tls_ver), "TLS 1.3");
        snprintf(e->ja3, sizeof(e->ja3), "%s", "0123456789abcdef0123456789abcdef");
        e->ts = now;
    }
    s->tls_log_sel = s->tls_log_count - 1;
    return s->tls_log_count;
}

static int seed_icmp(sloth_state_t *s, time_t now) {
    s->icmp_log_count = MAX_ICMP_LOG;
    for (int i = 0; i < s->icmp_log_count; i++) {
        icmp_log_entry_t *e = &s->icmp_log[i];
        ip_of(e->src, sizeof(e->src), i);
        snprintf(e->dst, sizeof(e->dst), "192.0.2.1");
        snprintf(e->desc, sizeof(e->desc), "Echo Req");
        e->type = 8; e->seq = (uint16_t)i; e->ts = now;
    }
    s->icmp_log_sel = s->icmp_log_count - 1;
    return s->icmp_log_count;
}

static int seed_http(sloth_state_t *s, time_t now) {
    s->http_log_count = MAX_HTTP_LOG;
    for (int i = 0; i < s->http_log_count; i++) {
        http_log_entry_t *e = &s->http_log[i];
        ip_of(e->src, sizeof(e->src), i);
        snprintf(e->dst, sizeof(e->dst), "192.0.2.1");
        snprintf(e->method, sizeof(e->method), "GET");
        snprintf(e->host, sizeof(e->host), "www.example.org");
        /* A path longer than the row has room for: unclipped, it wraps. */
        memset(e->path, 'p', sizeof(e->path) - 1);
        e->path[0] = '/';
        e->path[sizeof(e->path) - 1] = '\0';
        e->ts = now;
    }
    s->http_log_sel = s->http_log_count - 1;
    return s->http_log_count;
}

static int seed_dns(sloth_state_t *s, time_t now) {
    s->dns_log_count = MAX_DNS_LOG;
    for (int i = 0; i < s->dns_log_count; i++) {
        dns_log_entry_t *e = &s->dns_log[i];
        ip_of(e->src, sizeof(e->src), i);
        snprintf(e->qname, sizeof(e->qname), "host%d.example.org", i);
        snprintf(e->qtype, sizeof(e->qtype), "A");
        snprintf(e->answer, sizeof(e->answer), "192.0.2.53");
        e->is_resp = 1; e->ts = now;
    }
    s->dns_log_sel = s->dns_log_count - 1;
    return s->dns_log_count;
}

static int seed_nbns(sloth_state_t *s, time_t now) {
    s->nbns_count = MAX_NBNS_NAMES;
    for (int i = 0; i < s->nbns_count; i++) {
        nbns_name_t *e = &s->nbns_names[i];
        snprintf(e->name, sizeof(e->name), "WS%d", i);
        ip_of(e->ip, sizeof(e->ip), i);
        e->suffix = 0x20; e->last_seen = now;
    }
    s->nbns_sel = s->nbns_count - 1;
    return s->nbns_count;
}

static int seed_ssdp(sloth_state_t *s, time_t now) {
    s->ssdp_count = MAX_SSDP_DEVICES;
    for (int i = 0; i < s->ssdp_count; i++) {
        ssdp_device_t *e = &s->ssdp_devices[i];
        ip_of(e->ip, sizeof(e->ip), i);
        snprintf(e->type, sizeof(e->type), "urn:schemas-upnp-org:device:MediaRenderer:1");
        snprintf(e->location, sizeof(e->location), "%s",
                 "http://192.0.2.1:49152/description-of-a-media-renderer.xml");
        snprintf(e->nts, sizeof(e->nts), "alive");
        e->last_seen = now;
    }
    s->ssdp_sel = s->ssdp_count - 1;
    return s->ssdp_count;
}

static int seed_dhcp(sloth_state_t *s, time_t now) {
    s->dhcp_event_count = MAX_DHCP_EVENTS;
    for (int i = 0; i < s->dhcp_event_count; i++) {
        dhcp_event_t *e = &s->dhcp_events[i];
        snprintf(e->mac, sizeof(e->mac), "02:fa:00:00:%02x:%02x",
                 (i >> 8) & 0xff, i & 0xff);
        ip_of(e->ip, sizeof(e->ip), i);
        snprintf(e->hostname, sizeof(e->hostname), "laptop-%d", i);
        e->msg_type = 5; e->last_seen = now;
    }
    s->dhcp_event_sel = s->dhcp_event_count - 1;
    return s->dhcp_event_count;
}

static int seed_mdns(sloth_state_t *s, time_t now) {
    s->mdns_count = MAX_MDNS_SERVICES;
    for (int i = 0; i < s->mdns_count; i++) {
        mdns_service_t *m = &s->mdns_services[i];
        snprintf(m->service, sizeof(m->service), "_ipp._tcp");
        snprintf(m->instance, sizeof(m->instance), "Printer %d._ipp._tcp.local", i);
        snprintf(m->host, sizeof(m->host), "printer%d.local", i);
        ip_of(m->ip, sizeof(m->ip), i);
        m->port = 631; m->last_seen = now;
    }
    s->mdns_sel = s->mdns_count - 1;
    return s->mdns_count;
}

static int seed_arp(sloth_state_t *s, time_t now) {
    (void)now;
    s->arp_count = MAX_ARP_ENTRIES;
    for (int i = 0; i < s->arp_count; i++) {
        arp_entry_t *e = &s->arp_entries[i];
        ip_of(e->ip, sizeof(e->ip), i);
        mac_of(e->mac, 0xfa, i);
        snprintf(e->iface, sizeof(e->iface), "enx0123456789ab");
    }
    s->arp_sel = s->arp_count - 1;
    return s->arp_count;
}

static int seed_alerts(sloth_state_t *s, time_t now) {
    s->alert_count = MAX_ALERTS;
    for (int i = 0; i < s->alert_count; i++) {
        alert_t *a = &s->alerts[i];
        a->sev = ALERT_SEV_WARN;
        snprintf(a->title, sizeof(a->title), "Port scan");
        /* Longer than the row: the Detail column is unbounded. */
        snprintf(a->detail, sizeof(a->detail),
                 "fitrow%03d probed 40 ports in 10s from a host that is not on "
                 "the inventory and has no reverse name", i);
        snprintf(a->key, sizeof(a->key), "PORT_SCAN:%d", i);
        /* An unknown region and owner with a port: the longest
         * enrichment line draw_enrichment() can print. */
        snprintf(a->match_ip, sizeof(a->match_ip), "203.0.113.%d", i % 250);
        a->match_port = 44333;
        a->count = 1; a->first_seen = now; a->last_seen = now;
    }
    s->alert_sel = s->alert_count - 1;
    return s->alert_count;
}

static int seed_conns(sloth_state_t *s, time_t now) {
    (void)now;
    s->conn_count = 300;
    for (int i = 0; i < s->conn_count; i++) {
        conn_t *c = &s->conns[i];
        ip_of(c->local_addr, sizeof(c->local_addr), i);
        snprintf(c->remote_addr, sizeof(c->remote_addr), "198.51.100.7");
        c->local_port = 50000; c->remote_port = 443;
        c->proto = PROTO_TCP; c->state = 1;
        c->pid = 1000 + i;
        snprintf(c->proc, sizeof(c->proc), "firefox-esr");
        s->conn_idx[i] = i;
    }
    s->conn_idx_count = s->conn_count;
    s->conn_sel = s->conn_count - 1;
    return s->conn_count;
}

static int seed_procs(sloth_state_t *s, time_t now) {
    (void)now;
    /* Process ids above any default pid_max reach no live process, so
     * the tree's /proc ppid lookup finds nothing and every row is a
     * root - the table is just the rows seeded. */
    s->conn_count = 150;
    for (int i = 0; i < s->conn_count; i++) {
        conn_t *c = &s->conns[i];
        ip_of(c->local_addr, sizeof(c->local_addr), i);
        snprintf(c->remote_addr, sizeof(c->remote_addr), "198.51.100.7");
        c->remote_port = 443; c->proto = PROTO_TCP; c->state = 1;
        c->pid = 5000000 + i;
        snprintf(c->proc, sizeof(c->proc), "fit-%03d", i);
    }
    s->proc_sel = 1 << 20;          /* clamped to the last visible row */
    return s->conn_count;
}

#ifdef WITH_PCAP
static int seed_packets(sloth_state_t *s, time_t now) {
    s->pkt_count = MAX_PACKETS - 1;
    for (int i = 0; i < s->pkt_count; i++) {
        packet_info_t *p = &s->packets[i];
        p->ts_sec = (uint32_t)now; p->ts_usec = (uint32_t)i;
        ip_of(p->src, sizeof(p->src), i);
        snprintf(p->dst, sizeof(p->dst), "192.0.2.1");
        p->src_port = 50000; p->dst_port = 443; p->proto = 6; p->len = 1500;
        snprintf(p->info, sizeof(p->info), "TLS application data");
        p->raw_len = sizeof(p->raw);
        for (int b = 0; b < p->raw_len; b++) p->raw[b] = (uint8_t)(b + 0x20);
    }
    /* Not paused: the view follows the newest packet, so the last row
     * is the selection. */
    return s->pkt_count;
}
#endif

static int seed_wifi(sloth_state_t *s, time_t now) {
    (void)now;
    s->ap_count = MAX_WIFI_APS;
    for (int i = 0; i < s->ap_count; i++) {
        wifi_ap_t *ap = &s->aps[i];
        snprintf(ap->ssid, sizeof(ap->ssid), "%s", "A-thirty-two-octet-SSID-name-XYZ");
        snprintf(ap->bssid, sizeof(ap->bssid), "02:fa:00:00:%02x:%02x",
                 (i >> 8) & 0xff, i & 0xff);
        ap->signal_dbm = -55; ap->channel = 36;
        snprintf(ap->enc, sizeof(ap->enc), "WPA2");
        snprintf(ap->akm, sizeof(ap->akm), "PSK");
        ap->mfp = 1;
        snprintf(ap->phy, sizeof(ap->phy), "Wi-Fi 6");
    }
    s->wifi_sel = s->ap_count - 1;
    return s->ap_count;
}

static int seed_probe(sloth_state_t *s, time_t now) {
    s->probe_count = MAX_PROBE_CLIENTS;
    for (int i = 0; i < s->probe_count; i++) {
        probe_client_t *c = &s->probe_clients[i];
        mac_of(c->mac, 0xfa, i);
        snprintf(c->ssid, sizeof(c->ssid), "%s", "A-thirty-two-octet-SSID-name-XYZ");
        c->signal_dbm = -60; c->channel = 6;
        c->first_seen = now - 100; c->last_seen = now; c->frame_count = 12;
        dist_of(&c->dist);
    }
    s->probe_sel = s->probe_count - 1;
    return s->probe_count;
}

static int seed_twins(sloth_state_t *s, time_t now) {
    s->twin_episode_count = MAX_TWIN_EPISODES;
    for (int i = 0; i < s->twin_episode_count; i++) {
        twin_episode_t *e = &s->twin_episodes[i];
        snprintf(e->ssid, sizeof(e->ssid), "CorpWiFi-guest-%d", i);
        mac_of(e->real_bssid, 0xfa, i);
        mac_of(e->twin_bssid, 0xfb, i);
        snprintf(e->enc, sizeof(e->enc), "WPA2");
        e->rssi_swing_dbm = 18; e->confidence = 80;
        /* Every flag: the widest Flags cell, `!*#?`. */
        e->attack_in_progress = 1; e->attacker_oui = 1;
        e->hash_mismatch = 1; e->attributed = 0;
        e->last_seen = now - 1234567;
    }
    s->twin_episode_sel = s->twin_episode_count - 1;
    return s->twin_episode_count;
}

static int seed_beacon(sloth_state_t *s, time_t now) {
    s->beacon_count = MAX_BEACON_APS;
    for (int i = 0; i < s->beacon_count; i++) {
        beacon_ap_t *ap = &s->beacon_aps[i];
        snprintf(ap->ssid, sizeof(ap->ssid), "Neighbour-network-%d", i);
        mac_of(ap->bssid, 0xfa, i);
        ap->signal_dbm = -70; ap->channel = 149;
        snprintf(ap->enc, sizeof(ap->enc), "WPA2");
        snprintf(ap->vendor, sizeof(ap->vendor), "Ubiquiti");
        /* Ten octets, the whole AKM column: the distance plan is
         * checked against its last cell. */
        snprintf(ap->akm, sizeof(ap->akm), "PSK-SHA256");
        ap->last_seen = now;
        dist_of(&ap->dist);
    }
    s->beacon_sel = s->beacon_count - 1;
    /* An 802.11k survey, so the one-line footer under the table is
     * drawn and has to be budgeted for. */
    s->rrm_pair_count = 1;
    s->rrm_pairs[0].targeted_reqs = 3;
    s->rrm_pairs[0].reports_seen  = 1;
    return s->beacon_count;
}

static int seed_rogue_radius(sloth_state_t *s, time_t now) {
    s->rogue_radius_count = MAX_ROGUE_RADIUS;
    for (int i = 0; i < s->rogue_radius_count; i++) {
        rogue_radius_ap_t *r = &s->rogue_radius[i];
        mac_of(r->bssid, 0xfa, i);
        r->eap_types_seen = 0xffffffffu;
        r->weak_method = 1; r->identity_leaks = 3; r->nocert_sessions = 1;
        /* The identity is cut at 40; with the age it outruns the row. */
        snprintf(r->last_identity, sizeof(r->last_identity), "%s",
                 "firstname.lastname@corp.example.org.long");
        r->first_seen = now - 2000000;
        r->last_seen  = now - 1000000 - i;   /* newest first: index order */
    }
    s->rogue_radius_sel = s->rogue_radius_count - 1;
    return s->rogue_radius_count;
}

static int seed_deauth(sloth_state_t *s, time_t now) {
    s->deauth_count = MAX_DEAUTH_ENTRIES;
    for (int i = 0; i < s->deauth_count; i++) {
        deauth_event_t *e = &s->deauth_events[i];
        mac_of(e->src, 0xfa, i);
        mac_of(e->dst, 0xfb, i);
        mac_of(e->bssid, 0xfc, i);
        e->subtype = 12; e->reason = 7; e->reason_valid = 1;
        e->count = 9; e->first_seen = now; e->last_seen = now;
    }
    s->deauth_sel = s->deauth_count - 1;
    return s->deauth_count;
}

static int seed_research(sloth_state_t *s, time_t now) {
    (void)now;
    s->research_open = 1;
    s->research_cov_count = MAX_RESEARCH_COV;
    for (int i = 0; i < s->research_cov_count; i++) {
        research_cov_t *c = &s->research_cov[i];
        snprintf(c->kind, sizeof(c->kind), "PORT_SCAN_%d", i);
        snprintf(c->label, sizeof(c->label), "fitlabel%02d", i);
        c->severity = ALERT_SEV_WARN; c->fired = 2; c->doc_count = 1;
        snprintf(c->docs[0].title, sizeof(c->docs[0].title),
                 "MITRE ATT&CK T1046 Network Service Discovery");
        snprintf(c->docs[0].source_url, sizeof(c->docs[0].source_url),
                 "https://attack.mitre.org/techniques/T1046/");
    }
    s->research_sel = s->research_cov_count - 1;
    return s->research_cov_count;
}

static int seed_fragattack(sloth_state_t *s, time_t now) {
    s->frag_row_count = MAX_FRAG_ROWS;
    for (int i = 0; i < s->frag_row_count; i++) {
        frag_bss_row_t *r = &s->frag_rows[i];
        mac_of(r->bssid, 0xfa, i);
        /* The marker is the SA, which only the table row prints: the
         * detail pane under it names the BSSID. */
        mac_of(r->last_sa, 0xfb, i);
        mac_of(r->last_da, 0xfc, i);
        r->plaintext_unicast = 2; r->protected_frames = 40;
        r->last_hit = now;
    }
    s->frag_sel = s->frag_row_count - 1;
    return s->frag_row_count;
}

static int seed_ble(sloth_state_t *s, time_t now) {
    s->ble_device_count = MAX_BLE_DEVICES;
    for (int i = 0; i < s->ble_device_count; i++) {
        ble_device_t *d = &s->ble_devices[i];
        mac_of(d->addr, 0xfa, i);
        d->addr_type = 1;
        snprintf(d->sensor_iface, sizeof(d->sensor_iface), "bluetooth-monitor");
        d->adv_count = 40; d->first_seen = now; d->last_seen = now;
        d->has_rssi = 1; d->rssi = -60;
        dist_of(&d->dist);
    }
    s->ble_sel = s->ble_device_count - 1;
    return s->ble_device_count;
}

static int seed_devices(sloth_state_t *s, time_t now) {
    s->device_count = MAX_DEVICES;
    for (int i = 0; i < s->device_count; i++) {
        device_t *d = &s->devices[i];
        mac_of(d->mac, 0xfa, i);
        ip_of(d->ip, sizeof(d->ip), i);
        snprintf(d->hostname, sizeof(d->hostname), "workstation-%d", i);
        d->last_seen = now;
        dist_of(&d->dist);
    }
    s->device_sel = s->device_count - 1;
    return s->device_count;
}

static int seed_iface(sloth_state_t *s, time_t now) {
    (void)now;
    s->iface_count = MAX_IFACES;
    for (int i = 0; i < s->iface_count; i++) {
        iface_stat_t *f = &s->ifaces[i];
        snprintf(f->name, sizeof(f->name), "fitif%02d", i % 100);
        mac_of(f->mac, 0xfa, i);
    }
    s->iface_sel = s->iface_count - 1;
    return s->iface_count;
}

static int seed_karma(sloth_state_t *s, time_t now) {
    s->karma_count = MAX_KARMA_APS;
    for (int i = 0; i < s->karma_count; i++) {
        karma_ap_t *k = &s->karma_aps[i];
        mac_of(k->bssid, 0xfa, i);
        k->ssid_count = 12; k->score = 9; k->last_seen = now;
        snprintf(k->top_ssid, sizeof(k->top_ssid), "Starbucks");
    }
    s->karma_sel = s->karma_count - 1;
    return s->karma_count;
}

/* HTTP with wide glyphs at the end of every path, in the one segment
 * of the row that crosses the edge: forty octets, "/", thirty ASCII and
 * three U+5BB6, 37 cells. Counted one cell per glyph the segment fits
 * in the room left; drawn, it is three cells wider and wraps. A wide
 * glyph in a segment that ends short of the edge (WiFi's SSID column)
 * never reaches the clip's count, which is why this is HTTP. */
static int seed_http_wide(sloth_state_t *s, time_t now) {
    int n = seed_http(s, now);
    for (int i = 0; i < s->http_log_count; i++)
        snprintf(s->http_log[i].path, sizeof(s->http_log[i].path), "/%s%s",
                 "pppppppppppppppppppppppppppppp",
                 "\xe5\xae\xb6\xe5\xae\xb6\xe5\xae\xb6");
    return n;
}

/* A source URL at the 127-octet cap, longer than the screen is wide:
 * the corpus has URLs to ~174 characters, cut on load to 127. */
#define FIT_LONG_URL \
    "https://www.example.org/standards/ieee-802.11-2020/clause-12/" \
    "robust-security-network/fourway-handshake/section-12-7-6-4/x"
static int seed_research_long_url(sloth_state_t *s, time_t now) {
    int n = seed_research(s, now);
    for (int i = 0; i < s->research_cov_count; i++) {
        research_doc_t *d = &s->research_cov[i].docs[0];
        snprintf(d->source_url, sizeof(d->source_url), "%s", FIT_LONG_URL);
        snprintf(d->retrieved, sizeof(d->retrieved), "2026-10-01");
    }
    return n;
}

/* No document behind the selected kind, in both of the pane's forms. */
static int seed_research_no_basis(sloth_state_t *s, time_t now) {
    int n = seed_research(s, now);
    research_cov_t *c = &s->research_cov[s->research_sel];
    c->doc_count = 0; c->no_basis = 1;
    return n;
}
static int seed_research_uncited(sloth_state_t *s, time_t now) {
    int n = seed_research(s, now);
    research_cov_t *c = &s->research_cov[s->research_sel];
    c->doc_count = 0; c->no_basis = 0;
    return n;
}
static int seed_research_truncated(sloth_state_t *s, time_t now) {
    int n = seed_research(s, now);
    s->research_cov[s->research_sel].docs_truncated = 1;
    return n;
}

/* Every sensor-health fault the strip can carry from state, so it runs
 * well past 100 columns. */
static int seed_iface_faults(sloth_state_t *s, time_t now) {
    int n = seed_iface(s, now);
    s->cap_health.open = 1; s->cap_health.running = 1;
    s->mon_health.open = 1; s->mon_health.running = 1;
    s->cap_health.ps_drop = 123456789ULL; s->cap_health.ps_ifdrop = 23456789ULL;
    s->mon_health.ps_drop = 345678901ULL; s->mon_health.ps_ifdrop = 4567890ULL;
    s->mon_health.parse_rejects = 98765ULL;
    s->chan_retune_failures = 17; s->chan_retune_last_errno = EBUSY;
    s->hop_activity.channels = 13; s->hop_activity.silent_channels = 4;
    s->hop_dwell.completed = 10;
    s->hop_dwell.mean_planned_ms = 200; s->hop_dwell.mean_measured_ms = 900;
    s->scope_health.state = CAPTURE_SCOPE_STATE_DEGRADED;
    s->scope_health.enforced = 1; s->scope_health.requested = 2;
    snprintf(s->probe_err, sizeof(s->probe_err), "%s",
             "wlan9: SIOCSIWMODE: Device or resource busy");
    s->cap_health.stale_secs = 61;
    s->mon_health.stale_secs = 3600;   /* "monitor stale" is the last token */
    return n;
}

/* ── the cases ────────────────────────────────────────────── */

static const fit_case_t C_NTP     = { "ntp",     VIEW_NTP,     seed_ntp,     "10.9.", 0, NULL, 0 };
static const fit_case_t C_QUIC    = { "quic",    VIEW_QUIC,    seed_quic,    "10.9.", 0, NULL, 0 };
static const fit_case_t C_TLS     = { "tls",     VIEW_TLS,     seed_tls,     "10.9.", 0, NULL, 0 };
static const fit_case_t C_ICMP    = { "icmp",    VIEW_ICMP,    seed_icmp,    "10.9.", 0, NULL, 0 };
static const fit_case_t C_HTTP    = { "http",    VIEW_HTTP,    seed_http,    "10.9.", 0, NULL, 0 };
static const fit_case_t C_DNS     = { "dns",     VIEW_DNS,     seed_dns,     "10.9.", 0, NULL, 0 };
static const fit_case_t C_NBNS    = { "nbns",    VIEW_NBNS,    seed_nbns,    "10.9.", 0, NULL, 0 };
static const fit_case_t C_SSDP    = { "ssdp",    VIEW_SSDP,    seed_ssdp,    "10.9.", 0, NULL, 0 };
static const fit_case_t C_DHCP    = { "dhcp",    VIEW_DHCP,    seed_dhcp,    "10.9.", 0, NULL, 0 };
static const fit_case_t C_MDNS    = { "mdns",    VIEW_MDNS,    seed_mdns,    "10.9.", 0, NULL, 0 };
static const fit_case_t C_ARP     = { "arp",     VIEW_ARP,     seed_arp,     "10.9.", 0, NULL, 0 };
static const fit_case_t C_ALERTS  = { "alerts",  VIEW_ALERTS,  seed_alerts,  "fitrow", 2,
                                      "owner=unknown (not in list)", 0 };
static const fit_case_t C_CONNS   = { "conns",   VIEW_CONNS,   seed_conns,   "10.9.", 0, NULL, 0 };
static const fit_case_t C_PROCS   = { "procs",   VIEW_PROCS,   seed_procs,   "fit-", 0, NULL, 0 };
#ifdef WITH_PCAP
static const fit_case_t C_PACKETS = { "packets", VIEW_PACKETS, seed_packets, "10.9.", 0, NULL, 0 };
#endif
static const fit_case_t C_WIFI    = { "wifi",    VIEW_WIFI,    seed_wifi,    "02:fa:", 0, NULL, 0 };
static const fit_case_t C_PROBE   = { "probe",   VIEW_PROBE,   seed_probe,   "02:fa:", 0, NULL, 0 };
static const fit_case_t C_TWINS   = { "twins",   VIEW_TWINS,   seed_twins,   "02:fa:", 6,
                                      "needs controller/switch/DHCP correlation", 0 };
static const fit_case_t C_BEACON  = { "beacon",  VIEW_BEACON,  seed_beacon,  "02:fa:", 1, "RRM surveys:", 0 };
static const fit_case_t C_RADIUS  = { "rogue_radius", VIEW_ROGUE_RADIUS, seed_rogue_radius, "02:fa:", 2,
                                      "(CVE-2023-52160)", 38 };
static const fit_case_t C_DEAUTH  = { "deauth",  VIEW_DEAUTH,  seed_deauth,  "02:fa:", 0, NULL, 0 };
static const fit_case_t C_RESEARCH = { "research", VIEW_RESEARCH, seed_research, "fitlabel", 4,
                                       "https://attack.mitre.org/techniques/T1046/", 38 };
static const fit_case_t C_FRAG    = { "fragattack", VIEW_FRAGATTACK, seed_fragattack, "02:fb:", 12,
                                      "protected frames witnessed", 0 };
static const fit_case_t C_BLE     = { "ble",     VIEW_BLE,     seed_ble,     "02:fa:", 1, "T: P public", 0 };
static const fit_case_t C_DEVICES = { "devices", VIEW_DEVICES, seed_devices, "02:fa:", 0, NULL, 0 };
static const fit_case_t C_IFACE   = { "iface",   VIEW_IFACE,   seed_iface,   "fitif", 2, "navigate", 38 };
static const fit_case_t C_KARMA   = { "karma",   VIEW_KARMA,   seed_karma,   "02:fa:", 2,
                                      "UNVERIFIED signature", 0 };
static const fit_case_t C_HTTP_WIDE = { "http-wide", VIEW_HTTP, seed_http_wide, "10.9.", 0, NULL, 0 };
/* The pane: blank, rule, title, and the URL line broken onto two rows. */
static const fit_case_t C_RESEARCH_URL = { "research-long-url", VIEW_RESEARCH,
                                           seed_research_long_url, "fitlabel", 5,
                                           "(retrieved 2026-10-01)", 0 };
static const fit_case_t C_RESEARCH_NOBASIS = { "research-no-basis", VIEW_RESEARCH,
                                               seed_research_no_basis, "fitlabel", 6,
                                               "which is where that is recorded.", 0 };
static const fit_case_t C_RESEARCH_UNCITED = { "research-uncited", VIEW_RESEARCH,
                                               seed_research_uncited, "fitlabel", 6,
                                               "for how to add one.", 0 };
static const fit_case_t C_RESEARCH_TRUNC = { "research-truncated", VIEW_RESEARCH,
                                             seed_research_truncated, "fitlabel", 5,
                                             "more in the corpus than fit here", 0 };

/* ── the check ────────────────────────────────────────────── */

/* Cells in a read-back line. tui_test_line() reads cell by cell, and
 * the second cell of a wide glyph reads back as the glyph again (a
 * U+5BB6 is two in the line), so one glyph read back is one cell -
 * which is why this can count lead octets and the clip cannot. */
static int line_cells(const char *line) {
    int cells = 0;
    for (const char *p = line; *p; p++)
        if (((unsigned char)*p & 0xC0) != 0x80) cells++;
    return cells;
}

/* The selection is reverse video, or for the views that mark it with a
 * '>' instead (Research, FragAttacks), that glyph in the first columns. */
static int selected_row(int y) {
    char line[4096];
    if (tui_test_line(y, line, sizeof(line)) < 0) return 0;
    if (tui_test_is_reverse(y, 2) == 1) return 1;
    return line[0] == '>' || (line[0] && line[1] == '>');
}

static void check_fit(const fit_case_t *c, int rows, int cols) {
    static sloth_state_t s;
    memset(&s, 0, sizeof(s));
    int seeded = c->seed(&s, time(NULL));
    s.active_view = c->view;

    ASSERT_EQ(tui_init_offscreen(rows, cols), 0);
    tui_test_erase();
    tui_draw(&s);

    char line[4096];
    int wide = 0, twice = 0, shown = 0, last_row = -1;
    for (int y = 0; y < rows; y++) {
        if (tui_test_line(y, line, sizeof(line)) < 0) break;
        /* tui_draw()'s rule under the tab bar is full width by design. */
        if (strncmp(line, "\xe2\x94\x80", 3) == 0) continue;
        if (line_cells(line) >= cols) wide++;
        const char *m = strstr(line, c->marker);
        if (!m) continue;
        shown++;
        last_row = y;
        if (strstr(m + 1, c->marker)) twice++;   /* a row appended to another */
    }
    int overflow = tui_test_overflow();
    int want_last = rows - 1 - c->tail;
    int sel_ok = last_row >= 0 && selected_row(last_row);
    int tail_ok = !c->last || runner_line_has(rows - 1, c->last);
    if (wide || twice || overflow || last_row != want_last || !sel_ok ||
        !tail_ok || shown >= seeded) {
        fprintf(stderr, "    %s at %dx%d: wide=%d twice=%d overflow=%d "
                        "last table row=%d (want %d) selected=%d tail=%d "
                        "shown=%d of %d\n",
                c->name, cols, rows, wide, twice, overflow, last_row,
                want_last, sel_ok, tail_ok, shown, seeded);
        tui_test_dump(stderr);
    }
    ASSERT_EQ(wide, 0);
    ASSERT_EQ(twice, 0);
    ASSERT_EQ(overflow, 0);
    ASSERT_EQ(last_row, want_last);
    ASSERT(sel_ok);
    ASSERT(tail_ok);
    /* The fixture really had more rows than the screen: a test that
     * fits trivially proves nothing about the budget. */
    ASSERT(shown > 0);
    ASSERT(shown < seeded);

    tui_init_offscreen(TEST_SCREEN_ROWS, TEST_SCREEN_COLS);
}

static void fit_min(const fit_case_t *c) { check_fit(c, FIT_ROWS, FIT_COLS); }

/* ── 100x33, one test per view ────────────────────────────── */

/* The eleven three-line-chrome tables: status, two header lines, rows,
 * nothing under them. Each went red with `LINES - 5` restored (the
 * selection ran below the screen and overflow counted the rows past
 * it). */
static void test_ntp_fits_100x33(void)   { fit_min(&C_NTP); }
static void test_quic_fits_100x33(void)  { fit_min(&C_QUIC); }
static void test_tls_fits_100x33(void)   { fit_min(&C_TLS); }
static void test_icmp_fits_100x33(void)  { fit_min(&C_ICMP); }
static void test_dns_fits_100x33(void)   { fit_min(&C_DNS); }
static void test_nbns_fits_100x33(void)  { fit_min(&C_NBNS); }
static void test_ssdp_fits_100x33(void)  { fit_min(&C_SSDP); }
static void test_dhcp_fits_100x33(void)  { fit_min(&C_DHCP); }
static void test_mdns_fits_100x33(void)  { fit_min(&C_MDNS); }
static void test_arp_fits_100x33(void)   { fit_min(&C_ARP); }
static void test_probe_fits_100x33(void) { fit_min(&C_PROBE); }

/* Also red with tui_clip_rows(1) removed from view_http_draw(): the
 * 127-octet path wraps every row onto a second line. */
static void test_http_fits_100x33(void)  { fit_min(&C_HTTP); }

/* Red with `LINES - 5` and the old `page -= 2` footer reserve restored.
 * The enrichment line is the last row and must be whole: with the old
 * "(unknown / not in embedded list)" owner text it was 110 columns, and
 * red here (the clip cut it at the edge; before the clip it wrapped). */
static void test_alerts_fits_100x33(void) { fit_min(&C_ALERTS); }

/* Conns is 136 columns wide and WiFi 114: red with `LINES - 5`, and red
 * again with tui_clip_rows(1) removed (every row wrapped). */
static void test_conns_fits_100x33(void) { fit_min(&C_CONNS); }
static void test_wifi_fits_100x33(void)  { fit_min(&C_WIFI); }

/* Red with `LINES - 5` restored. */
static void test_procs_fits_100x33(void) { fit_min(&C_PROCS); }

#ifdef WITH_PCAP
/* The 143-column header wrapped too; red with `LINES - 5` and with the
 * clip removed. */
static void test_packets_fits_100x33(void) { fit_min(&C_PACKETS); }
#endif

/* The six-line legend was never in the page: red with `LINES - 5`. */
static void test_twins_fits_100x33(void)  { fit_min(&C_TWINS); }

/* The RRM footer row: red with `LINES - 5`, and with rrm_rows set to 0
 * (the footer line lands below the screen). */
static void test_beacon_fits_100x33(void) { fit_min(&C_BEACON); }

/* Two-line legend left out of `LINES - 5`: red with it restored. */
static void test_rogue_radius_fits_100x33(void) { fit_min(&C_RADIUS); }

/* `LINES - 6`: red with it restored. The BTM split is
 * test_deauth_with_btm_fits_100x33 below. */
static void test_deauth_fits_100x33(void) { fit_min(&C_DEAUTH); }

/* `LINES - 12` assumed a seven-row detail pane; one source is four
 * rows. Red with it restored (the pane's URL line below the screen). */
static void test_research_fits_100x33(void) { fit_min(&C_RESEARCH); }

/* `LINES - 16` counted the twelve-row pane but not the three lines
 * above the table, so it overran by one even under a one-row tab bar:
 * red with it restored. */
static void test_fragattack_fits_100x33(void) { fit_min(&C_FRAG); }

/* `LINES - 8`: red with it restored. */
static void test_ble_fits_100x33(void) { fit_min(&C_BLE); }

/* This was the one view measuring from the cursor already, as
 * rows_left() - 1: it fitted, but left the last row empty. Red with
 * the `- 1` restored (the last table row one above where it belongs). */
static void test_devices_fits_100x33(void) { fit_min(&C_DEVICES); }

/* getmaxy() - 4 counted one tab-bar row: red with it restored (the
 * selected interface below the health strip and hint). */
static void test_iface_fits_100x33(void) { fit_min(&C_IFACE); }

/* [y] KARMA's own fit test, with its worst-case rows, is
 * tests/test_karma.c :: test_view_full_page_fits_a_100x33_terminal;
 * this case is here so the large-terminal pass below covers it too. */
static void test_karma_fits_100x33(void) { fit_min(&C_KARMA); }

/* Deauth with 802.11v steering to show: the BTM section under the
 * table, capped at a third of what is left. Its old budget counted
 * three of its four chrome rows and not the "... N more" line, so the
 * section ran two rows past the rows it was given. Red with `rows - 3`
 * restored in draw_btm_section(), and with `LINES - 6` restored. */
static void test_deauth_with_btm_fits_100x33(void) {
    static sloth_state_t s;
    memset(&s, 0, sizeof(s));
    time_t now = time(NULL);
    seed_deauth(&s, now);
    s.btm_steer_count = MAX_BTM_PAIRS;
    for (int i = 0; i < s.btm_steer_count; i++) {
        btm_steer_t *b = &s.btm_steers[i];
        mac_of(b->bssid, 0xfd, i);
        mac_of(b->sta, 0xfe, i);
        b->req_count = 4; b->first_seen = now; b->last_seen = now;
    }
    s.active_view = VIEW_DEAUTH;

    ASSERT_EQ(tui_init_offscreen(FIT_ROWS, FIT_COLS), 0);
    tui_test_erase();
    tui_draw(&s);

    int sel_row = -1, btm_last = -1;
    char line[4096];
    for (int y = 0; y < FIT_ROWS; y++) {
        if (tui_test_line(y, line, sizeof(line)) < 0) break;
        if (strstr(line, "02:fa:") && tui_test_is_reverse(y, 2) == 1) sel_row = y;
        if (strstr(line, "02:fd:")) btm_last = y;
    }
    int more = runner_line_has(FIT_ROWS - 1, " more");
    if (tui_test_overflow() || sel_row < 0 || !more)
        tui_test_dump(stderr);
    ASSERT_EQ(tui_test_overflow(), 0);
    ASSERT(sel_row >= 0);                   /* the selection is on screen */
    ASSERT(btm_last > sel_row);             /* steers under the table */
    ASSERT_EQ(btm_last, FIT_ROWS - 2);      /* and the last but one row */
    ASSERT(more);                           /* "... N more" is the last */

    tui_init_offscreen(TEST_SCREEN_ROWS, TEST_SCREEN_COLS);
}

/* ── what the clip must not take ──────────────────────────── */

/* Every row's text, concatenated with nothing between: a line that
 * wrapped reads back whole. */
static void screen_joined(char *out, size_t n) {
    char line[4096];
    size_t used = 0;
    out[0] = '\0';
    for (int y = 0; y < tui_test_rows(); y++) {
        int len = tui_test_line(y, line, sizeof(line));
        if (len <= 0) continue;
        if (used + (size_t)len + 1 > n) break;
        memcpy(out + used, line, (size_t)len);
        used += (size_t)len;
        out[used] = '\0';
    }
}

/* The scan banner above Conns' table names attacker addresses, and it
 * is prose: it has to wrap, not be cut at the edge. With the row clip
 * switched on at the top of the draw, the 100-column banner stopped at
 * "203.0.113.202(1002)  203" - the fourth address and "+2 more" were
 * gone. Red with tui_clip_rows(1) moved back above the status line.
 * The page still fits: the budget is measured after the banner. */
static void test_conns_scan_banner_wraps_at_100x33(void) {
    static sloth_state_t s;
    memset(&s, 0, sizeof(s));
    time_t now = time(NULL);
    int seeded = seed_conns(&s, now);
    s.scan_count = 6;
    for (int i = 0; i < s.scan_count; i++) {
        scan_entry_t *se = &s.scan_entries[i];
        snprintf(se->ip, sizeof(se->ip), "203.0.113.%d", 200 + i);
        se->port_count = 1000 + i;
        se->flagged = 1;
        se->first_seen = se->last_seen = now;
    }
    s.active_view = VIEW_CONNS;

    ASSERT_EQ(tui_init_offscreen(FIT_ROWS, FIT_COLS), 0);
    tui_test_erase();
    tui_draw(&s);

    static char all[FIT_ROWS * 4096];
    screen_joined(all, sizeof(all));
    char line[4096];
    int wide_rows = 0, shown = 0, last_row = -1;
    for (int y = 0; y < FIT_ROWS; y++) {
        if (tui_test_line(y, line, sizeof(line)) < 0) break;
        if (!strstr(line, "10.9.")) continue;
        shown++;
        last_row = y;
        if (line_cells(line) >= FIT_COLS) wide_rows++;
    }
    int ok = strstr(all, "203.0.113.203(1003)") && strstr(all, "+2 more");
    if (!ok || tui_test_overflow() || last_row != FIT_ROWS - 1)
        tui_test_dump(stderr);
    ASSERT(strstr(all, "203.0.113.203(1003)") != NULL);
    ASSERT(strstr(all, "+2 more") != NULL);
    ASSERT_EQ(tui_test_overflow(), 0);
    ASSERT_EQ(wide_rows, 0);                /* table rows still clipped */
    ASSERT_EQ(last_row, FIT_ROWS - 1);
    ASSERT(selected_row(last_row));
    ASSERT(shown > 0 && shown < seeded);

    tui_init_offscreen(TEST_SCREEN_ROWS, TEST_SCREEN_COLS);
}

/* Twins in full is wider than 100 columns, and Flags sat at column
 * 97: under the row clip a `!*#?` row showed `!*`, dropping the
 * hash-mismatch mark and the `?` that says neither half is accused.
 * Every table row has to carry all four. Red with twins_plan()'s SSID
 * held at its 18-column maximum. */
static void test_twins_flags_whole_at_100x33(void) {
    static sloth_state_t s;
    memset(&s, 0, sizeof(s));
    seed_twins(&s, time(NULL));
    s.active_view = VIEW_TWINS;

    ASSERT_EQ(tui_init_offscreen(FIT_ROWS, FIT_COLS), 0);
    tui_test_erase();
    tui_draw(&s);

    char line[4096];
    int rows = 0, whole = 0;
    for (int y = 0; y < FIT_ROWS; y++) {
        if (tui_test_line(y, line, sizeof(line)) < 0) break;
        if (!strstr(line, "02:fa:")) continue;
        rows++;
        if (strstr(line, "!*#?")) whole++;
    }
    if (rows == 0 || whole != rows) tui_test_dump(stderr);
    ASSERT(rows > 0);
    ASSERT_EQ(whole, rows);

    tui_init_offscreen(TEST_SCREEN_ROWS, TEST_SCREEN_COLS);
}

/* Text after a newline on the last row has no row to go to. It used
 * to be appended to the last row (curses leaves the cursor there);
 * now it is dropped and counted. Red with the drop branch in t_put()
 * made to addnstr() the segment: row 1 read "bc" and overflow 0. */
static void test_text_below_the_last_row_is_dropped(void) {
    ASSERT_EQ(tui_init_offscreen(2, 20), 0);
    tui_test_erase();
    tui_addstr("a\nb\nc");

    char line[64];
    ASSERT(tui_test_line(0, line, sizeof(line)) >= 0);
    ASSERT(strcmp(line, "a") == 0);
    ASSERT(tui_test_line(1, line, sizeof(line)) >= 0);
    ASSERT(strcmp(line, "b") == 0);
    ASSERT_EQ(tui_test_overflow(), 1);

    tui_init_offscreen(TEST_SCREEN_ROWS, TEST_SCREEN_COLS);
}

/* ── wide glyphs, long prose, the cut mark ────────────────── */

/* Seventy U+5BB6 are 140 cells. Counted one cell per lead octet, the
 * clip let all seventy through: the row filled the screen and wrapped,
 * and NEXT landed on row 2. Red with t_fit() counting lead octets. */
static void test_clip_counts_wide_glyphs_as_two_cells(void) {
    ASSERT_EQ(tui_init_offscreen(4, FIT_COLS), 0);
    tui_test_erase();
    tui_clip_rows(1);
    char text[70 * 3 + 8];
    size_t o = 0;
    for (int i = 0; i < 70; i++) { memcpy(text + o, "\xe5\xae\xb6", 3); o += 3; }
    memcpy(text + o, "\nNEXT", 6);
    text[o + 6] = '\0';
    tui_addstr(text);

    char line[4096];
    int next_row = -1;
    for (int y = 0; y < 4; y++)
        if (tui_test_line(y, line, sizeof(line)) >= 0 && strstr(line, "NEXT"))
            next_row = y;
    ASSERT(tui_test_line(0, line, sizeof(line)) >= 0);
    int cells = line_cells(line);
    if (next_row != 1 || cells >= FIT_COLS) tui_test_dump(stderr);
    ASSERT_EQ(next_row, 1);
    ASSERT(cells < FIT_COLS);
    ASSERT_EQ(tui_test_overflow(), 0);

    tui_init_offscreen(TEST_SCREEN_ROWS, TEST_SCREEN_COLS);
}

/* HTTP with wide glyphs where the row is cut, at the minimum: red with
 * t_fit() counting one cell per glyph (every row wrapped; the selection
 * ran below the screen). */
static void test_http_wide_path_fits_100x33(void) { fit_min(&C_HTTP_WIDE); }

/* A cut that hides a column ends the row with the mark, in its last
 * allowed cell; a cut through trailing padding does not. Red with the
 * mark's addstr() removed (first half) and with t_has_ink() returning 1
 * unconditionally (second half). */
static void test_cut_mark_only_when_something_is_hidden(void) {
    char line[4096];
    ASSERT_EQ(tui_init_offscreen(4, 20), 0);

    tui_test_erase();
    tui_clip_rows(1);
    tui_addstr("0123456789abcdefghijKLMN\n");
    ASSERT(tui_test_line(0, line, sizeof(line)) >= 0);
    if (strcmp(line, "0123456789abcdefgh\xe2\x80\xba") != 0) tui_test_dump(stderr);
    ASSERT(strcmp(line, "0123456789abcdefgh\xe2\x80\xba") == 0);

    /* Cut at a segment boundary: the hidden text arrives in a later
     * write with no room left, and marks the cell before it. */
    tui_test_erase();
    tui_clip_rows(1);
    tui_addstr("0123456789abcdefghi");
    tui_addstr("HIDDEN\n");
    ASSERT(tui_test_line(0, line, sizeof(line)) >= 0);
    ASSERT(strcmp(line, "0123456789abcdefgh\xe2\x80\xba") == 0);

    tui_test_erase();
    tui_clip_rows(1);
    tui_addstr("0123456789                    \n");
    ASSERT(tui_test_line(0, line, sizeof(line)) >= 0);
    if (strstr(line, "\xe2\x80\xba")) tui_test_dump(stderr);
    ASSERT(strstr(line, "\xe2\x80\xba") == NULL);
    ASSERT(strcmp(line, "0123456789") == 0);

    tui_init_offscreen(TEST_SCREEN_ROWS, TEST_SCREEN_COLS);
}

/* Every row with its leading spaces dropped, concatenated: text that
 * was broken onto indented rows reads back whole. */
static void screen_joined_trimmed(char *out, size_t n) {
    char line[4096];
    size_t used = 0;
    out[0] = '\0';
    for (int y = 0; y < tui_test_rows(); y++) {
        int len = tui_test_line(y, line, sizeof(line));
        if (len <= 0) continue;
        const char *p = line;
        while (*p == ' ') p++;
        size_t k = strlen(p);
        if (used + k + 1 > n) break;
        memcpy(out + used, p, k);
        used += k;
        out[used] = '\0';
    }
}

/* The source URL is longer than the screen is wide. Under the table's
 * row clip it was cut at column 99 with its retrieval date; now it is
 * broken onto a second row, and the page still fits with the pane's
 * extra row counted. Red with the URL line drawn by TPRINT again (the
 * clip cut it: URL and date not read back), and with detail_rows()
 * counting it as one row (the table one row too long, overflow 1). */
static void test_research_long_url_reads_whole_at_100x33(void) {
    fit_min(&C_RESEARCH_URL);

    static sloth_state_t s;
    memset(&s, 0, sizeof(s));
    seed_research_long_url(&s, time(NULL));
    s.active_view = VIEW_RESEARCH;
    ASSERT_EQ(tui_init_offscreen(FIT_ROWS, FIT_COLS), 0);
    tui_test_erase();
    tui_draw(&s);
    static char all[FIT_ROWS * 4096];
    screen_joined_trimmed(all, sizeof(all));
    int ok = strstr(all, FIT_LONG_URL "  (retrieved 2026-10-01)") != NULL;
    if (!ok) tui_test_dump(stderr);
    ASSERT(ok);
    ASSERT_EQ(tui_test_overflow(), 0);
    tui_init_offscreen(TEST_SCREEN_ROWS, TEST_SCREEN_COLS);
}

/* The pane's other bodies. Red with RESEARCH_NO_SOURCE_ROWS made 3
 * (both no-source cases: the last line below the screen), and with the
 * docs_truncated row left out of detail_rows() (the truncated case). */
static void test_research_no_basis_fits_100x33(void)  { fit_min(&C_RESEARCH_NOBASIS); }
static void test_research_uncited_fits_100x33(void)   { fit_min(&C_RESEARCH_UNCITED); }
static void test_research_truncated_fits_100x33(void) { fit_min(&C_RESEARCH_TRUNC); }

/* Every fault on the sensor-health strip: past 100 columns, and under
 * the row clip its last faults were cut. Broken onto rows instead, with
 * the rows counted in the page. The tail is the strip's rows plus the
 * hint, computed here from the strip's length, not from the view's own
 * count: first row 99 cells, each later one 97 after its indent. Red
 * with the strip drawn by tui_printf() again (cut: "monitor stale" not
 * read back, and the table a row short), with the budget's tail fixed
 * at 2 (overflow), and with the strip buffer at its old 160 octets
 * (truncated before it was drawn). */
static void test_iface_health_strip_reads_whole_at_100x33(void) {
    static sloth_state_t s;
    memset(&s, 0, sizeof(s));
    seed_iface_faults(&s, time(NULL));
    char strip[1024];
    iface_fmt_health_strip(&s, strip, (int)sizeof(strip));
    int len = (int)strlen(strip);
    int strip_rows = len <= FIT_COLS - 1 ? 1
                   : 1 + (len - (FIT_COLS - 1) + (FIT_COLS - 4)) / (FIT_COLS - 3);
    ASSERT(strip_rows >= 3);   /* the fixture really overruns the width */

    fit_case_t c = { "iface-faults", VIEW_IFACE, seed_iface_faults, "fitif",
                     1 + strip_rows, "navigate", 0 };
    fit_min(&c);

    memset(&s, 0, sizeof(s));
    seed_iface_faults(&s, time(NULL));
    s.active_view = VIEW_IFACE;
    ASSERT_EQ(tui_init_offscreen(FIT_ROWS, FIT_COLS), 0);
    tui_test_erase();
    tui_draw(&s);
    static char all[FIT_ROWS * 4096];
    screen_joined_trimmed(all, sizeof(all));
    int ok = strstr(all, "monitor stale 3600s") && strstr(all, "hop silent 4/13");
    if (!ok) tui_test_dump(stderr);
    ASSERT(strstr(all, "monitor stale 3600s") != NULL);
    ASSERT(strstr(all, "hop silent 4/13") != NULL);
    tui_init_offscreen(TEST_SCREEN_ROWS, TEST_SCREEN_COLS);
}

/* ── the distance column (2026-10-26) ─────────────────────── */

/* The selected row's text at rows x cols, for the view `c` names. */
static int selected_line(const fit_case_t *c, sloth_state_t *s, int rows,
                         int cols, char *out, size_t n) {
    memset(s, 0, sizeof(*s));
    c->seed(s, time(NULL));
    s->active_view = c->view;
    if (tui_init_offscreen(rows, cols) != 0) return -1;
    tui_test_erase();
    tui_draw(s);
    for (int y = 0; y < rows; y++) {
        if (tui_test_line(y, out, n) < 0) break;
        if (strstr(out, c->marker) && selected_row(y)) return y;
    }
    return -1;
}

/* Each view plans the cell by width (AGENTS.md: column widths flex
 * with panel width). At the 100x33 minimum only BLE has room, and
 * draws the short form; Beacons keeps AKM on screen, Probe keeps the
 * 27 SSID cells it had, and Devices keeps its 15-cell name, so none of
 * them draws it. On a wide terminal all four take the full form, and
 * Beacons and Probe take the short one in between.
 *
 * The absences are seen red: Devices with plan_cols() keeping the
 * short cell at any width (the 100-column row carried "~27m"); Beacons
 * and Probe with their dist_column_width() returning RF_CELL_SHORT
 * unconditionally (the cell came back, "PSK-SHA256" lost its last
 * cells on Beacons and the SSID its last eight on Probe). */
static void test_distance_column_reads_at_100x33(void) {
    static sloth_state_t s;
    char line[4096];
    const char *full  = "~27m bldg \xe2\x86\x98";
    const char *shrt  = "~27m\xe2\x86\x98";
    ASSERT(selected_line(&C_PROBE, &s, FIT_ROWS, FIT_COLS, line, sizeof(line)) >= 0);
    ASSERT(strstr(line, "~27m") == NULL);
    ASSERT(strstr(line, "A-thirty-two-octet-SSID-nam") != NULL);
    ASSERT(selected_line(&C_BEACON, &s, FIT_ROWS, FIT_COLS, line, sizeof(line)) >= 0);
    ASSERT(strstr(line, "~27m") == NULL);
    ASSERT(strstr(line, "PSK-SHA256") != NULL);
    ASSERT(selected_line(&C_BLE, &s, FIT_ROWS, FIT_COLS, line, sizeof(line)) >= 0);
    ASSERT(strstr(line, shrt) != NULL);
    ASSERT(selected_line(&C_DEVICES, &s, FIT_ROWS, FIT_COLS, line, sizeof(line)) >= 0);
    ASSERT(strstr(line, "~27m") == NULL);
    ASSERT(strstr(line, "workstation-") != NULL);
    /* The plans' edges: Beacons short from 107, Probe from 105, AKM and
     * 24 SSID cells still on screen. */
    ASSERT(selected_line(&C_BEACON, &s, FIT_ROWS, 106, line, sizeof(line)) >= 0);
    ASSERT(strstr(line, "~27m") == NULL);
    ASSERT(selected_line(&C_BEACON, &s, FIT_ROWS, 107, line, sizeof(line)) >= 0);
    ASSERT(strstr(line, shrt) != NULL);
    ASSERT(strstr(line, "PSK-SHA256") != NULL);
    ASSERT(selected_line(&C_PROBE, &s, FIT_ROWS, 104, line, sizeof(line)) >= 0);
    ASSERT(strstr(line, "~27m") == NULL);
    ASSERT(selected_line(&C_PROBE, &s, FIT_ROWS, 105, line, sizeof(line)) >= 0);
    ASSERT(strstr(line, shrt) != NULL);
    ASSERT(strstr(line, "A-thirty-two-octet-SSID-") != NULL);
    /* Wide: every view takes the full form. */
    ASSERT(selected_line(&C_PROBE, &s, BIG_ROWS, BIG_COLS, line, sizeof(line)) >= 0);
    ASSERT(strstr(line, full) != NULL);
    ASSERT(strstr(line, "A-thirty-two-octet-SSID-name-XYZ") != NULL);
    ASSERT(selected_line(&C_BEACON, &s, BIG_ROWS, BIG_COLS, line, sizeof(line)) >= 0);
    ASSERT(strstr(line, full) != NULL);
    ASSERT(selected_line(&C_BLE, &s, BIG_ROWS, BIG_COLS, line, sizeof(line)) >= 0);
    ASSERT(strstr(line, full) != NULL);
    ASSERT(selected_line(&C_DEVICES, &s, BIG_ROWS, BIG_COLS, line, sizeof(line)) >= 0);
    ASSERT(strstr(line, full) != NULL);
    tui_init_offscreen(TEST_SCREEN_ROWS, TEST_SCREEN_COLS);
}

/* [a] Associations was 118 columns and wrapped at 100 before the
 * distance cell made it 126; it now cuts at the edge like every other
 * table (#150), with the cell left of the cut. Seen red with its
 * tui_clip_rows(1) removed: every row reached column 100. The view
 * draws every row (MAX_ASSOC_ENTRIES is not paged), so this seeds a
 * screenful rather than an overfull table. */
static void test_assoc_rows_cut_at_100_with_distance(void) {
    static sloth_state_t s;
    memset(&s, 0, sizeof(s));
    time_t now = time(NULL);
    s.assoc_count = 5;
    for (int i = 0; i < s.assoc_count; i++) {
        assoc_t *a = &s.assocs[i];
        mac_of(a->bssid, 0xfa, i);
        mac_of(a->sta_mac, 0xfb, i);
        snprintf(a->ssid, sizeof(a->ssid), "A-sixteen-octet-");
        a->channel = 6; a->signal_dbm = -60; a->source = ASSOC_SRC_EAPOL;
        a->first_seen = now; a->last_seen = now;
        dist_of(&a->dist);
    }
    s.active_view = VIEW_ASSOC;
    ASSERT_EQ(tui_init_offscreen(FIT_ROWS, FIT_COLS), 0);
    tui_test_erase();
    tui_draw(&s);
    char line[4096];
    int wide = 0, rows = 0, cells = 0;
    for (int y = 0; y < FIT_ROWS; y++) {
        if (tui_test_line(y, line, sizeof(line)) < 0) break;
        if (strncmp(line, "\xe2\x94\x80", 3) == 0) continue;
        if (line_cells(line) >= FIT_COLS) wide++;
        if (!strstr(line, "02:fa:")) continue;
        rows++;
        if (strstr(line, "~27m\xe2\x86\x98")) cells++;
    }
    if (wide || rows != 5 || cells != 5) tui_test_dump(stderr);
    ASSERT_EQ(wide, 0);
    ASSERT_EQ(rows, 5);
    ASSERT_EQ(cells, 5);
    tui_init_offscreen(TEST_SCREEN_ROWS, TEST_SCREEN_COLS);
}

/* ── a large terminal ─────────────────────────────────────── */

/* The same checks at 200 columns and 60 rows (38 for the three tables
 * capped at 32 rows, so the fixture still overfills them): the page
 * reaches the bottom row, so the fit was not bought by a short page.
 * Red for every case with view_page_budget() made one row short, and
 * for Interfaces alone with its scroll-offset clamp removed: the offset
 * kept from the 100x33 draw left eight rows empty under the table. */
static void test_every_list_view_fills_a_large_terminal(void) {
    static const fit_case_t *const all[] = {
        &C_NTP, &C_QUIC, &C_TLS, &C_ICMP, &C_HTTP, &C_DNS, &C_NBNS,
        &C_SSDP, &C_DHCP, &C_MDNS, &C_ARP, &C_ALERTS, &C_CONNS, &C_PROCS,
#ifdef WITH_PCAP
        &C_PACKETS,
#endif
        &C_WIFI, &C_PROBE, &C_TWINS, &C_BEACON, &C_RADIUS, &C_DEAUTH,
        &C_RESEARCH, &C_FRAG, &C_BLE, &C_DEVICES, &C_IFACE, &C_KARMA,
    };
    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++)
        check_fit(all[i], all[i]->big_rows ? all[i]->big_rows : BIG_ROWS,
                  BIG_COLS);
}

void run_view_fit_tests(void) {
    TEST_SUITE("list views fit the 100x33 minimum (#150)");
    RUN_TEST(test_ntp_fits_100x33);
    RUN_TEST(test_quic_fits_100x33);
    RUN_TEST(test_tls_fits_100x33);
    RUN_TEST(test_icmp_fits_100x33);
    RUN_TEST(test_http_fits_100x33);
    RUN_TEST(test_dns_fits_100x33);
    RUN_TEST(test_nbns_fits_100x33);
    RUN_TEST(test_ssdp_fits_100x33);
    RUN_TEST(test_dhcp_fits_100x33);
    RUN_TEST(test_mdns_fits_100x33);
    RUN_TEST(test_arp_fits_100x33);
    RUN_TEST(test_probe_fits_100x33);
    RUN_TEST(test_alerts_fits_100x33);
    RUN_TEST(test_conns_fits_100x33);
    RUN_TEST(test_wifi_fits_100x33);
    RUN_TEST(test_procs_fits_100x33);
#ifdef WITH_PCAP
    RUN_TEST(test_packets_fits_100x33);
#endif
    RUN_TEST(test_twins_fits_100x33);
    RUN_TEST(test_beacon_fits_100x33);
    RUN_TEST(test_rogue_radius_fits_100x33);
    RUN_TEST(test_deauth_fits_100x33);
    RUN_TEST(test_deauth_with_btm_fits_100x33);
    RUN_TEST(test_research_fits_100x33);
    RUN_TEST(test_fragattack_fits_100x33);
    RUN_TEST(test_ble_fits_100x33);
    RUN_TEST(test_devices_fits_100x33);
    RUN_TEST(test_iface_fits_100x33);
    RUN_TEST(test_karma_fits_100x33);
    RUN_TEST(test_conns_scan_banner_wraps_at_100x33);
    RUN_TEST(test_twins_flags_whole_at_100x33);
    RUN_TEST(test_text_below_the_last_row_is_dropped);
    RUN_TEST(test_clip_counts_wide_glyphs_as_two_cells);
    RUN_TEST(test_http_wide_path_fits_100x33);
    RUN_TEST(test_cut_mark_only_when_something_is_hidden);
    RUN_TEST(test_research_long_url_reads_whole_at_100x33);
    RUN_TEST(test_research_no_basis_fits_100x33);
    RUN_TEST(test_research_uncited_fits_100x33);
    RUN_TEST(test_research_truncated_fits_100x33);
    RUN_TEST(test_iface_health_strip_reads_whole_at_100x33);
    RUN_TEST(test_distance_column_reads_at_100x33);
    RUN_TEST(test_assoc_rows_cut_at_100_with_distance);
    RUN_TEST(test_every_list_view_fills_a_large_terminal);
}
