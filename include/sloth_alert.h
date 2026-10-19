#ifndef SLOTH_ALERT_H
#define SLOTH_ALERT_H

/* The alert-type enum and its per-type lookups, generated from
 * sloth_alerts.def (#117).
 *
 * Split out of sloth.h because nothing here depends on anything else in
 * it. sloth.h re-includes this header, so every existing includer
 * compiles unchanged. */

typedef enum {
#define X(id, technique) ALERT_TYPE_##id,
#include "sloth_alerts.def"
#undef X
    ALERT_TYPE_COUNT
} alert_type_t;

/* MITRE ATT&CK technique ID for an alert type, e.g. "T1046". Returns
 * "" for alert types that describe a posture or sloth's own state
 * rather than adversary behaviour, and for anything out of range.
 * Defined in src/alerts/engine.c so tests can compile against the table
 * directly. */
const char *alert_technique(alert_type_t type);

/* The enum's own name, e.g. "ALERT_TYPE_BTM_ABUSE"; "" out of range.
 *
 * Not derivable from alert_t.title: titles are display strings capped
 * at ALERT_TITLE_LEN and abbreviated to fit — BLOCKACK_ATK for
 * ALERT_TYPE_BLOCKACK_ATTACK, PEAP_NO_CERT for
 * ALERT_TYPE_PEAP_NO_SERVER_CERT. Anything keying on the identity
 * rather than the label needs this (#73). */
const char *alert_type_name(alert_type_t type);

#endif /* SLOTH_ALERT_H */
