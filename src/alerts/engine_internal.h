#ifndef SLOTH_ALERTS_ENGINE_INTERNAL_H
#define SLOTH_ALERTS_ENGINE_INTERNAL_H

/* What the rule files share with the engine and with each other (#118).
 * Private to src/alerts/: nothing outside it includes this, and the
 * public API stays src/alerts.h. These were file statics while every
 * rule lived in one translation unit; they are external now only
 * because the rules moved, and their contracts are the comments at
 * their definitions. */

#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include "alerts.h"
#include "tool_fingerprint.h"

/* src/alerts/engine.c — the engine's entry points for a rule. */
void fire_inv(alert_type_t type, alert_sev_t sev, int confidence,
              const char *inv_hash, int ap_class, int wired,
              const sloth_tool_sig_t *tool_row,
              const uint64_t *ev_ids, int ev_n,
              const char *title, const char *detail,
              const char *key,
              const char *match_ip, uint16_t match_port,
              time_t now);
void fire_conf(alert_type_t type, alert_sev_t sev, int confidence,
               const char *title, const char *detail,
               const char *key,
               const char *match_ip, uint16_t match_port,
               time_t now);
void fire_ev(alert_type_t type, alert_sev_t sev,
             const uint64_t *ev_ids, int ev_n,
             const char *title, const char *detail,
             const char *key,
             const char *match_ip, uint16_t match_port,
             time_t now);
void fire(alert_type_t type, alert_sev_t sev,
          const char *title, const char *detail,
          const char *key,
          const char *match_ip, uint16_t match_port,
          time_t now);

/* src/alerts/engine.c — for a rule that caps its own findings (#148):
 * is `key` an open incident, and close it now with `reason` (an
 * `alert.resolve` reason, docs/wiki/jsonl-schema.md). A closed or
 * unknown key is a no-op. */
int  alert_key_open(const char *key);
void alert_key_resolve(const char *key, time_t now, const char *reason);

/* src/alerts/engine.c — the tainted-BSSID tracker's writer; the reader
 * is evil_twin_bssid_is_tainted() in src/alerts.h. */
void taint_mark(const uint8_t bssid[6], time_t now);

/* src/alerts/rules_twin.c — read by rule_btm_abuse as well. */
int btm_candidate_is_twin(const sloth_state_t *s, const uint8_t bssid[6]);

/* src/alerts/rules_wired.c — drops the ARP-spoof baseline; called by
 * alerts_clear(). */
void rules_wired_forget(void);

/* Formatting helpers every rule file uses. static inline rather than
 * external: a name as generic as mac_to_str() has no business in
 * libsloth_core.a's symbol table. */
static inline void mac_to_str(const uint8_t mac[6], char *out, int sz) {
    snprintf(out, sz, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static inline void fmt_bssid(char out[20], const uint8_t b[6]) {
    snprintf(out, 20, "%02x:%02x:%02x:%02x:%02x:%02x",
             b[0], b[1], b[2], b[3], b[4], b[5]);
}

#endif
