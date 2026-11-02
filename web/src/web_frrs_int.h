/* web_frrs.c, web_frrs_report.c and web_frrs_tacdb.c's shared insides:
 * the ledger's tables and the helpers the three files share. Not a
 * public header: nothing outside the three includes it. */
#ifndef SLOTHWEB_FRRS_INT_H
#define SLOTHWEB_FRRS_INT_H

#include "web_frrs.h"

/* A distance estimate as the record carried it (jsonl-schema.md,
 * "Distance estimate fields"): all four or none. */
typedef struct {
    int    have;
    double m;
    char   band[12], trend[14], ptx[20];
} frrs_est_t;

/* One BSSID (or MLD address): the latest beacon, wifi_regulatory and
 * wifi_mld records that named it. */
typedef struct {
    char      mac[18];
    unsigned long long touch;
    /* beacon */
    int       has_b;
    long long ts_b;
    int       channel, primary_channel, secondary_offset, operating_width, channel_source;
    int       beacon_ms, signal_dbm, rssi_min, rssi_max, has_rssi60;
    char      ssid[33], phy[24], enc[12], pairwise[40], group[24], akm[40];
    long long akm_bits, downgrade_flags, fp_flags;
    int       mfp, has_wps, wps_state, wps_locked, ie_order_count;
    long long wps_config_methods, wps_device_pwd_id;
    char      wps_manufacturer[33], wps_model_name[33], wps_model_number[33];
    char      vendor_ies_hash[24], ie_order_hash[24];
    long long tbtt_jitter_us, tbtt_jitter_samples;
    frrs_est_t est;
    /* wifi_regulatory */
    int       has_r;
    long long ts_r;
    int       country_present, triplets_truncated, power_constraint_present;
    int       power_constraint_db, tpc_present, tpc_tx_power_dbm, tpc_link_margin_db;
    int       he6_present;
    char      country[8], env[16], he6_name[16];
    long long malformed_country;
    /* wifi_mld (keyed by mld_mac) */
    int       has_m;
    long long ts_m;
    int       link_count, links_truncated, nlinks;
    char      links[WEB_FRRS_MLD_LINKS][18];
} frrs_bss_t;

typedef struct {
    char      mac[18];
    int       confidence, fwd_gap, gap, earlier;   /* earlier: this side ran first */
    long long window_start, window_end, ts;
} frrs_seq_t;

/* One Wi-Fi station: wifi_assoc_req, probe_client, pnl_client and the
 * seqnum_correlation pairs that name it. */
typedef struct {
    char      mac[18];
    unsigned long long touch;
    int       has_ar;
    long long ts_ar;
    char      ar_bssid[18], ar_phy[24], ar_vie[24];
    int       listen_interval, requested_mfp;
    long long capability_info, akm_bits, pairwise_bits, supported_rates, downgrade_flags;
    int       has_p;
    long long ts_p, frame_count, burst_frames, burst_span_ms;
    int       flood, signal_dbm, channel;
    frrs_est_t est;
    int       has_pnl;
    long long ts_pnl, probe_count;
    int       mac_random, phy_confirmed;
    char      os_fp[24], phy[24];
    int       nseq;
    frrs_seq_t seq[WEB_FRRS_SEQ_PARTNERS];
} frrs_sta_t;

/* One BLE advertiser as one sensor heard it (ble_device's identity). */
typedef struct {
    char      addr[18];
    int       addr_type;
    char      iface[24];
    unsigned long long touch;
    long long ts, first_seen, last_seen, adv_count;
    int       adapter, sampled, channel, name_complete, tx_power, has_rssi, rssi, rssi_best;
    int       ext_adv, primary_phy, secondary_phy, adv_sid;
    long long pdu_mask, uuid16, mfr_id, mfr_subtype, svc_data_uuid16, appearance, hid, flags;
    char      last_pdu[16], name[33], watch[24];
    frrs_est_t est;
} frrs_ble_t;

/* One IP address: what the capture saw it send (counts and the last
 * TLS server names, the protocols seen in the clear). */
enum { FRRS_P_HTTP = 1, FRRS_P_QUIC = 2, FRRS_P_TLS = 4, FRRS_P_DNS = 8,
       FRRS_P_CRED = 16, FRRS_P_NTP = 32 };
typedef struct {
    char      ip[WEB_KEY_MAX + 1];
    unsigned long long touch;
    unsigned  proto;
    long long dns_n, tls_n, quic_n, http_n, cred_n, ts;
    int       nsni;
    char      sni[WEB_FRRS_SNI][WEB_FRRS_SNI_MAX + 1];
    unsigned long long sni_h[WEB_FRRS_SNI];
    char      tls_ver[12];
    char      cred_protos[48];
} frrs_ip_t;

typedef struct {
    int       ch;
    char      band[12];
    long long ctrl_total, ts;
    int       ap_count, assoc_count;
} frrs_chan_t;

struct web_frrs_led {
    unsigned long long clock;
    frrs_bss_t  bss[WEB_FRRS_LEDGER_BSSID];
    frrs_sta_t  sta[WEB_FRRS_LEDGER_STA];
    frrs_ble_t  ble[WEB_FRRS_LEDGER_BLE];
    frrs_ip_t   ip[WEB_FRRS_LEDGER_IP];
    frrs_chan_t chan[WEB_FRRS_LEDGER_CHAN];
    int         nbss, nsta, nble, nip, nchan;
    char        mon_iface[24], cap_iface[24];
    long long   ts_sh;
};

/* Ledger lookups, under f->lmu (the caller holds it). NULL when absent. */
const frrs_bss_t *frrs_led_bss(const web_frrs_t *f, const char *mac);
const frrs_sta_t *frrs_led_sta(const web_frrs_t *f, const char *mac);
/* The BLE rows of addr (any type when addr_type < 0), into out. */
int  frrs_led_ble(const web_frrs_t *f, const char *addr, int addr_type,
                  const frrs_ble_t **out, int max);
const frrs_ip_t  *frrs_led_ip(const web_frrs_t *f, const char *ip);
const frrs_chan_t *frrs_led_chan(const web_frrs_t *f, int ch);
/* The MLD whose link list holds mac (an AP's link BSSID or a client's
 * link address), or NULL. */
const frrs_bss_t *frrs_led_mld_of(const web_frrs_t *f, const char *mac);

/* Emitter kinds, as tacdb_emitter.kind stores them. */
enum { FRRS_K_STA = 0, FRRS_K_BSSID, FRRS_K_BLE, FRRS_K_COUNT };
const char *frrs_kind_word(int k);
int  frrs_kind_find(const char *w);
/* A canonical emitter address for kind k: a MAC (web_key_mac), or for
 * BLE "aa:bb:cc:dd:ee:ff/N" with N the addr_type 0..3 or 255. 0, or -1. */
int  frrs_addr_canon(int k, const char *in, char *out, size_t outsz);

/* The first MAC-shaped token in s, canonical, into out[18]; 1 or 0. */
int  frrs_mac_in(const char *s, char out[18]);

/* JSON helpers. */
void frrs_str_or_null(web_jw_t *w, const char *s);
/* The answer's error body {"error":why[,"member":m]}. */
int  frrs_error(int status, const char *why, const char *member, char *body,
                size_t cap, size_t *len, int *st);

/* The report (web_frrs_report.c): the record of one emitter into w,
 * one object. m carries sloth.db (may be unconfigured); live may be
 * NULL. */
void frrs_report_json(const web_m4_t *m, web_live_t *live, int kind, const char *addr,
                      long long now_s, web_jw_t *w);

/* TACDB (web_frrs_tacdb.c). Each a route: the body into body, *status
 * set; 0, or -1 when not even an error fit. */
int  frrs_tacdb_get(const web_m4_t *m, const char *query, long long now_s,
                    char *body, size_t cap, size_t *len, int *status);
int  frrs_tacdb_view(const web_m4_t *m, const char *query, long long now_s,
                     char *body, size_t cap, size_t *len, int *status);
int  frrs_suggest_get(const web_m4_t *m, const char *query, long long now_s,
                      char *body, size_t cap, size_t *len, int *status);
int  frrs_export(const web_m4_t *m, long long now_s, char **big, size_t *biglen,
                 char *body, size_t cap, size_t *len, int *status);
/* The POSTs: the decoded body r, the peer, the clock. */
int  frrs_tacdb_post(const web_m4_t *m, const char *path, const web_jrec_t *r,
                     const char *peer, long long now_s, char *body, size_t cap,
                     size_t *len, int *status);
int  frrs_import(const web_m4_t *m, const web_req_t *rq, long long now_s,
                 char *body, size_t cap, size_t *len, int *status);
/* The platform and unit an emitter is filed under, as the report's
 * "tacdb" member; null when none. */
void frrs_tacdb_of(web_frrs_t *f, int kind, const char *addr, web_jw_t *w);
/* The triage history's export lines (web_frrs.c), appended to w. */
void frrs_triage_export(web_frrs_t *f, web_jw_t *w, long long *rows);
/* One imported triage line, checked (write 0) or merged; 0 merged or
 * would be, 1 skipped (why set), -1 a store error. */
int  frrs_triage_import(web_frrs_t *f, const web_jrec_t *r, int write,
                        long long now_s, const char *peer, const char **why);

/* A member check: every member of r is in allowed (a NULL-ended list)
 * and none is a nested value; else *bad names the first that is not. */
int  frrs_members_ok(const web_jrec_t *r, const char *const *allowed, const char **bad);
/* A string member: absent (1, *out ""), present and fit (1), else 0
 * with *why "too_long" or "bad_text" (a control byte, or not a string). */
int  frrs_text(const web_jrec_t *r, const char *name, size_t max, char *out,
               const char **why);

#endif
