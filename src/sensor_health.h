#ifndef SENSOR_HEALTH_H
#define SENSOR_HEALTH_H

#include <stdint.h>

/* ── Table-overflow accounting (#91 slice 3) ──────────────────────
 *
 * Every synthesis table in sloth is bounded, and every one of them
 * silently discards an observation when it fills — LRU eviction in most,
 * a plain refusal in the device table. That is the correct behaviour for
 * a passive sensor (an attacker spraying identities must not be able to
 * make sloth allocate), but until now it was *invisible*: a sensor at max
 * occupancy and a sensor on a quiet segment produced the same empty
 * delta, which is the "healthy with no detections vs. not observing"
 * confusion this issue is about.
 *
 * These counters are deliberately a tally, not a rate or a ring: the
 * question a consumer asks is "is this sensor losing observations at
 * all", and a monotonic lifetime count answers it from any two samples.
 *
 * Counted tables are exactly the ones listed below, and that list is
 * NOT every bounded table in sloth — stating which are covered is the
 * point, since a tally that silently omits a table reads as "no loss"
 * when it means "not measured", and claiming completeness it does not
 * have is the same failure wearing a better hat. Further bounded
 * tables still LRU-evict or refuse on full with no field — at least
 * one in each of these modules, and five in action_snoop alone:
 * cleartext_creds, transit, the dns.c reverse
 * cache, beacon_detect, action_snoop, bandwidth, twins and sensors.
 * The rule to read the tally by is therefore mechanical: a table
 * either has an `evict_<name>` field or its loss is unmeasured.
 *
 * The list grows by slices. The beacon, seqnum and assoc tables joined
 * in the #91 wave-6 slice; wps_session followed, then evidence_frame
 * with the #92 evidence ring, then probe_client on 2026-10-08, the six
 * per-protocol flow rings on 2026-10-09, pm_forge with #107, and
 * rf_channel + http_flow on 2026-10-13.
 *
 * The flow rings differ from every other counted table in what their
 * count *means*, and a consumer reading `evict_dns_log` has to know it:
 * `*_log_record()` hands the record to the JSONL / data-socket export
 * BEFORE touching the ring, unconditionally. So a flow-ring eviction is
 * the loss of the operator's in-memory scrollback — the 256 newest
 * records a view can show — not the loss of an observation from the
 * forensic log. On a busy segment these counters climb steadily by
 * design and a rising value is not in itself a fault, the same caveat
 * evidence_frame carries. What they answer is "is the live view a
 * complete picture of this protocol right now", which is a real
 * question and was previously unanswerable. */
typedef enum {
    SH_EVICT_ALERT = 0,     /* src/alerts/engine.c — oldest incident dropped (resolved first) */
    SH_EVICT_TOP_HOST,      /* src/top_hosts.c — oldest/quietest remote IP dropped */
    SH_EVICT_PNL_CLIENT,    /* src/probe_pnl.c — oldest client dropped from the PNL table */
    SH_EVICT_PNL_SSID,      /* src/probe_pnl.c — oldest SSID dropped from one client's list */
    SH_EVICT_DHCP_EVENT,    /* src/dhcp_snoop.c — oldest DHCP client dropped */
    SH_EVICT_EAP_SESSION,   /* src/eap_track.c — oldest 802.1X conversation dropped */
    SH_EVICT_DEVICE,        /* src/devices.c — a NEW device refused (drop-on-full, not LRU) */
    SH_EVICT_BEACON_AP,     /* src/beacon_snoop.c — oldest AP record dropped */
    SH_EVICT_SEQNUM_CLIENT, /* src/seqnum_track.c — least-recently-seen client dropped */
    SH_EVICT_ASSOC_PAIR,    /* src/assoc_track.c — oldest (BSSID,STA) grant pair dropped */
    SH_EVICT_ASSOC_REQ,     /* src/assoc_track.c — oldest pending assoc request dropped */
    SH_EVICT_WPS_SESSION,   /* src/wps_track.c — oldest WPS registration session dropped */
    SH_EVICT_EVIDENCE_FRAME,/* src/evidence_ring.c — oldest retained raw 802.11 frame dropped */
    SH_EVICT_PROBE_CLIENT,  /* src/capture/probe.c — least-recently-seen probing client dropped */
    SH_EVICT_PM_FORGE,      /* src/pm_forge.c — least-recently-seen PM-state entry dropped (#107) */
    SH_EVICT_QUEUE_EVICT,   /* src/queue_evict.c — least-recently-seen (BSSID,STA) eviction-window row dropped (#107) */
    SH_EVICT_PCAP_COOLDOWN, /* src/alerts/engine.c — oldest per-alert-pcap export cooldown row dropped (#96) */
    /* The six per-protocol flow rings: plain circular buffers, so the
     * oldest record is overwritten by an append onto a full ring. */
    SH_EVICT_DNS_LOG,       /* src/dns_log.c  — oldest DNS record overwritten */
    SH_EVICT_TLS_LOG,       /* src/tls_log.c  — oldest TLS ClientHello overwritten */
    SH_EVICT_QUIC_LOG,      /* src/quic_log.c — oldest QUIC initial overwritten */
    SH_EVICT_HTTP_LOG,      /* src/http_log.c — oldest HTTP request/response overwritten */
    SH_EVICT_NTP_LOG,       /* src/ntp_log.c  — oldest NTP exchange overwritten */
    SH_EVICT_ICMP_LOG,      /* src/icmp_log.c — oldest ICMP record overwritten */
    /* Two more synthesis tables, appended rather than filed with their
     * family above: src/jsonl.c emits the breakout in enum order, so
     * inserting mid-enum would shift the position of already-published
     * `evict_*` fields, against the "every earlier field keeps its name
     * and position" rule in docs/wiki/jsonl-schema.md. Nothing reads
     * this enum as an ordered range — sh_evict_is_flow_ring() is a
     * switch — so appending costs nothing. */
    SH_EVICT_RF_CHANNEL,    /* src/rf_quality.c — stalest per-channel RF-quality row dropped */
    SH_EVICT_HTTP_FLOW,     /* src/http_log.c — oldest HTTP request/response pairing slot dropped */
    /* The stab_t migration (#110): the eight snoop tables that evicted
     * the oldest row without tallying it, then the three tables that
     * refused every new key forever once full. Appended, per the rule
     * above. mdns_service and nbns_name are STAB_REFUSE_AGING tables
     * and count something different from the rest: a NEW key refused
     * because no row had gone 3600 s unseen — not a row reclaimed, which
     * is a TTL expiry and loses nothing current. arp_hist is
     * STAB_OLDEST keyed by IP; an IP that was evicted and comes back
     * with a different MAC is a fresh baseline, not a spoof. */
    SH_EVICT_BGP_SESSION,   /* src/bgp_snoop.c  — least-recently-seen peer pair dropped */
    SH_EVICT_LDAP_EVENT,    /* src/ldap_snoop.c — least-recently-seen LDAP client dropped */
    SH_EVICT_KERB_EVENT,    /* src/kerb_snoop.c — least-recently-seen Kerberos client dropped */
    SH_EVICT_SMB_SESSION,   /* src/smb_snoop.c  — least-recently-seen (client,server,port) dropped */
    SH_EVICT_SSH_FLOW,      /* src/ssh_snoop.c  — least-recently-seen (client,server) dropped */
    SH_EVICT_RDP_FLOW,      /* src/rdp_snoop.c  — least-recently-seen (client,server) dropped */
    SH_EVICT_SNMP_FLOW,     /* src/snmp_snoop.c — least-recently-seen (src,dst) dropped */
    SH_EVICT_MQTT_FLOW,     /* src/mqtt_snoop.c — least-recently-seen (client,broker) dropped */
    SH_EVICT_MDNS_SERVICE,  /* src/mdns_snoop.c — a NEW service instance refused, none stale (REFUSE_AGING) */
    SH_EVICT_NBNS_NAME,     /* src/nbns_snoop.c — a NEW NetBIOS name refused, none stale (REFUSE_AGING) */
    SH_EVICT_ARP_HIST,      /* src/alerts/rules_wired.c — least-recently-seen IP dropped from the ARP-spoof baseline */
    /* The rest of the #110 migration, appended for the same reason:
     * fragattack's five tables (they waited on #111's lock) and the
     * remaining hand-written find_or_alloc / find_or_create tables that
     * evicted without a tally. All STAB_OLDEST. frag_session and
     * frag_mpdu count only rows that still meant something: a session
     * that completed and an MPDU record past FRAG_MPDU_WINDOW_S are
     * retired with stab_del()/stab_expire(), not evicted. */
    SH_EVICT_FRAG_BSS,      /* src/fragattack.c — least-recently-seen BSS's FragAttacks counters dropped */
    SH_EVICT_FRAG_STA,      /* src/fragattack.c — least-recently-seen key-install witness (BSSID,STA) dropped */
    SH_EVICT_FRAG_SESSION,  /* src/fragattack.c — least-recently-seen open reassembly dropped */
    SH_EVICT_FRAG_ASSOC,    /* src/fragattack.c — oldest (BSSID,STA) (re)association timestamp dropped */
    SH_EVICT_FRAG_MPDU,     /* src/fragattack.c — oldest in-window (TA,PN) A-MSDU-flip record dropped */
    SH_EVICT_NDP_RA,        /* src/ndp_snoop.c  — least-recently-seen router-advertisement source dropped */
    SH_EVICT_ROGUE_RADIUS,  /* src/eap_track.c  — least-recently-seen per-BSSID EAP posture row dropped */
    SH_EVICT_SSDP_DEVICE,   /* src/ssdp_snoop.c — least-recently-seen SSDP device dropped */
    SH_EVICT_ONVIF_DEVICE,  /* src/onvif_discovery.c — least-recently-seen WS-Discovery device dropped */
    SH_EVICT_SMTP_FLOW,     /* src/smtp_snoop.c — least-recently-seen AUTH LOGIN flow dropped */
    SH_EVICT_EAPOL_PENDING, /* src/eapol_log.c  — least-recently-heard in-flight 4-way handshake dropped */
    /* #143: the two deauth tables, the last hand-written find-or-add
     * pair. Appended after EAPOL_PENDING for the same reason as above.
     * Rows aged out after DEAUTH_AGE_SECS of silence are retired, not
     * counted. */
    SH_EVICT_DEAUTH_OBS,    /* src/deauth_snoop.c — least-recently-heard (BSSID,TA,RA,subtype) stream dropped */
    SH_EVICT_DEAUTH_VICTIM, /* src/deauth_snoop.c — least-recently-hit (BSSID,victim) aggregate dropped */
    /* #106 slice B: the RTSP observer's two tables, appended. */
    SH_EVICT_RTSP_EXCHANGE, /* src/rtsp_snoop.c — least-recently-seen RTSP connection with DESCRIBEs in flight dropped */
    SH_EVICT_RTSP_STREAM,   /* src/rtsp_snoop.c — least-recently-answered (server, port, path) stream row dropped */
    /* #155: the router-role table the camera classifier vetoes from. */
    SH_EVICT_LAN_ROLE,      /* src/lan_role.c — least-recently-seen DHCP-server / DNS-responder address dropped */
    /* #144 slice 2: the BLE advertiser table, appended. STAB_OLDEST —
     * random addresses rotate and an advertiser chooses its own, so the
     * key space is the transmitter's, not sloth's. */
    SH_EVICT_BLE_DEVICE,    /* src/ble_hci.c — least-recently-heard (address, type) advertiser dropped */
    SH_EVICT_KIND_COUNT
} sh_evict_t;

/* Record one discarded observation. Out-of-range kinds are ignored so a
 * caller can never corrupt the tally. */
void sh_evict_note(sh_evict_t kind);

/* Lifetime tally for one kind, and across all kinds. */
uint64_t sh_evict_count(sh_evict_t kind);
uint64_t sh_evict_total(void);

/* True for the six per-protocol flow rings, false for every synthesis
 * table. The distinction is not cosmetic: a flow ring rolls over
 * continuously on a busy segment by design, so the two cannot share a
 * "has this sensor lost anything" test. */
int sh_evict_is_flow_ring(sh_evict_t kind);

/* Lifetime tally over the synthesis tables only — every kind for which
 * sh_evict_is_flow_ring() is false.
 *
 * This is the figure for anything that treats a non-zero tally as news:
 * the faults-only TUI health strip, and the change-only signature on the
 * `sensor_health` JSONL record. Both exist on the principle that a
 * counter which climbs every tick of a *working* sensor must not drive
 * them — the same reason `ps_recv` and `stale_secs` are kept out of that
 * signature. The flow rings are exactly such a counter.
 *
 * The `evictions` JSONL field stays sh_evict_total(), because it is
 * published as the sum of the per-table breakout and changing that
 * would be a non-additive schema change. */
uint64_t sh_evict_total_tables(void);

/* Stable lower-case name, part of the `sensor_health` JSONL contract:
 * "alert", "top_host", "pnl_client", "pnl_ssid", "dhcp_event",
 * "eap_session", "device", "beacon_ap", "seqnum_client", "assoc_pair",
 * "assoc_req", "wps_session", "evidence_frame", "probe_client",
 * "pm_forge", "queue_evict", "pcap_cooldown", "dns_log", "tls_log",
 * "quic_log", "http_log", "ntp_log", "icmp_log", "rf_channel",
 * "http_flow", "bgp_session", "ldap_event", "kerb_event",
 * "smb_session", "ssh_flow", "rdp_flow", "snmp_flow", "mqtt_flow",
 * "mdns_service", "nbns_name", "arp_hist", "frag_bss", "frag_sta",
 * "frag_session", "frag_assoc", "frag_mpdu", "ndp_ra", "rogue_radius",
 * "ssdp_device", "onvif_device", "smtp_flow", "eapol_pending",
 * "deauth_obs", "deauth_victim", "rtsp_exchange", "rtsp_stream",
 * "lan_role".
 * "ble_device".
 * Unknown kinds return "". */
const char *sh_evict_name(sh_evict_t kind);

/* Zero every tally. For tests — nothing in the running binary resets
 * these, because a counter that clears has no lifetime meaning. */
void sh_evict_reset(void);

/* ── Parse-fault accounting (#126) ────────────────────────────────
 *
 * A sibling of the eviction tally, deliberately NOT folded into
 * sh_evict_t. The two answer different questions — "did sloth drop an
 * observation it had parsed" against "did a frame fail to parse" — and
 * `evictions` is published as the exact sum of the `evict_*` breakout,
 * so adding a parse kind there would silently change what that sum
 * means for every existing consumer.
 *
 * Append-only, for the same reason as sh_evict_t: src/jsonl.c emits the
 * `parse_fault_<name>` breakout in enum order, and a field's position is
 * part of the published contract.
 *
 * What is counted is a WALK that hit the fault, not a frame. Several
 * parsers walk one frame's element list — an association request goes
 * through assoc_track's rate walk and through beacon_parse_ies() — so a
 * single malformed frame can add more than one. The figure answers "is
 * malformed input reaching the parsers, and roughly how much", which a
 * frame-exact count would answer no better; making it frame-exact is
 * #130's job (decode each frame once), not this one's.
 *
 * Not every kind has a writer yet, and the gap is stated rather than
 * left to read as "no faults": see sh_parse_fault_is_wired(). A kind
 * that is not wired reports 0 because nothing measures it. */
typedef enum {
    SH_PF_RADIOTAP_BAD = 0, /* src/capture/probe.c — radiotap_parse() refused the header */
    SH_PF_DOT11_RUNT,       /* src/capture/probe.c — 802.11 frame shorter than FC+duration+addr1 */
    SH_PF_IE_OVERRUN,       /* an element / subelement / KDE walk ended in TLV_OVERRUN (src/bytes.h) */
    SH_PF_RSN_MALFORMED,    /* src/beacon_snoop.c — rsn_ie_parse() found an RSNE field cut off (#128) */
    SH_PF_MLE_MALFORMED,    /* src/mle.c — a Multi-Link element failed one of its three bounds rules */
    SH_PF_IP_TRUNCATED,     /* src/capture/capture.c — IPv4 Total Length / IPv6 Payload Length or extension header past the packet (#132) */
    SH_PF_IP_FRAGMENT,      /* src/capture/capture.c — a non-first IPv4/IPv6 fragment, labelled and not parsed (#132) */
    SH_PF_DNS_NAME_BAD,     /* reserved for #131 (DNS name reader once) — not yet wired */
    SH_PF_TLS_MALFORMED,    /* reserved for #131 (TLS parser under test) — not yet wired */
    SH_PF_FRAME_EDGE,       /* src/capture/frame_edge.c — a pcap record header refused at the edge (#141) */
    SH_PF_KIND_COUNT
} sh_parse_fault_t;

/* Record one parse fault. Out-of-range kinds are ignored. Safe from any
 * thread; the lock is cold — it is reached only on malformed input. */
void sh_parse_fault_note(sh_parse_fault_t kind);

/* Lifetime tally for one kind, and across all kinds. */
uint64_t sh_parse_fault_count(sh_parse_fault_t kind);
uint64_t sh_parse_fault_total(void);

/* Stable lower-case name, part of the `sensor_health` JSONL contract
 * (`parse_fault_<name>`): "radiotap_bad", "dot11_runt", "ie_overrun",
 * "rsn_malformed", "mle_malformed", "ip_truncated", "ip_fragment",
 * "dns_name_bad", "tls_malformed", "frame_edge". Unknown kinds return "". */
const char *sh_parse_fault_name(sh_parse_fault_t kind);

/* 1 when some parser in this build calls sh_parse_fault_note() for the
 * kind, 0 for a reserved kind whose writer lands with a later slice.
 * Kept beside the enum so wiring a kind and flipping this are one edit
 * in one place; tests/test_sensor_health.c pins the set, and the schema
 * doc lists it. */
int sh_parse_fault_is_wired(sh_parse_fault_t kind);

/* Zero the parse-fault tally. For tests only, like sh_evict_reset(). */
void sh_parse_fault_reset(void);

/* ── Process memory sample (#121) ─────────────────────────────────
 *
 * The production sensor once reached 7.7 GB RSS over twelve days and
 * nothing in the stream said so: the figure came from systemd's
 * accounting at stop. These are the numbers that would have shown the
 * slope while it was happening, and which subsystem it was in — the
 * kernel's view (rss), SQLite's own allocator, glibc's heap, the fd
 * table, and the one call (getnameinfo, through NSS) that loads code
 * sloth does not control.
 *
 * Every field reads -1 for "not measured" — built without SQLite, a
 * libc without mallinfo2(), /proc unreadable — never 0, which would
 * read as "measured, empty".
 *
 * Own process only. Nothing here opens another pid's /proc.
 *
 * NOT in the change-only signature. Every one of these moves on a live
 * sensor without anything having gone wrong, so signing over them would
 * turn the record into the per-tick firehose AGENTS.md forbids. They
 * ride the 300 s heartbeat (and any other transition's line), which is
 * the sampling rate a leak of MB/hour needs. src/jsonl.c samples only
 * after the change check has passed, so a suppressed tick costs no
 * /proc read. */
typedef struct {
    long long rss_kb;            /* VmRSS, kB                              */
    long long rss_hwm_kb;        /* VmHWM — peak RSS, kB                   */
    long long sqlite_mem_kb;     /* sqlite3_memory_used() / 1024           */
    long long sqlite_mem_hwm_kb; /* sqlite3_memory_highwater(0) / 1024     */
    long long malloc_kb;         /* mallinfo2 uordblks + hblkhd, kB        */
    long long fd_count;          /* open descriptors, the sampler's own excluded */
    long long resolver_calls;    /* getnameinfo(3) calls, lifetime (src/dns.c) */
} sh_mem_t;

/* Fill *out from this process. Never fails; unmeasurable fields are -1. */
void sh_mem_sample(sh_mem_t *out);

/* Pull VmRSS / VmHWM (kB) out of /proc/self/status text. Split out so
 * the parse is tested against hand-built text rather than whatever the
 * host's kernel happens to print. `len` bounds the read; the text need
 * not be NUL-terminated. A field that is absent or not a number leaves
 * its output at -1 (a kernel thread has no VmRSS line at all). */
void sh_mem_parse_status(const char *text, int len,
                         long long *rss_kb, long long *hwm_kb);

#endif /* SENSOR_HEALTH_H */
