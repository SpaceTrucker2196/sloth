#ifndef SLOTHWEB_SECRET_H
#define SLOTHWEB_SECRET_H

#include <stddef.h>

/* slothweb's withheld columns of sloth.db (#163, M5).
 *
 * One list, read by both readers of sloth.db: the M4 reader's
 * authorizer (web_slothdb.h) and the SQL box (web_sqlbox.h), which is not on the allow-list's terms (it may
 * read any table) but is on these. A column is withheld when it is
 * named here, or when it is a TEXT or BLOB column whose name holds one
 * of web_sdb_secret_words[]: tests/test_db.c's guardrail words (the
 * suite reads that file and fails if one is missing here) and the
 * credential words M4's allow-list test holds every column to. The
 * explicit rows are the credential-bearing columns the words do not
 * catch: alerts.key and alerts.detail carry a cleartext credential's
 * username (rule_cleartext_cred()), an RDP mstshash cookie (an account
 * name) and an MQTT username in their text. Withholding them in the SQL
 * box too is deliberate: the box is the operator's own sqlite3, but a
 * browser tab is not a terminal, and what the box can read is what any
 * peer the allow list admits can read. */
typedef struct {
    const char *table, *column;
} web_sdb_secret_t;

extern const web_sdb_secret_t web_sdb_secret[];
extern const size_t           web_sdb_secret_n;
extern const char *const      web_sdb_secret_words[];   /* NULL-ended */

/* Is (table, column) withheld? decl_type is the column's declared type:
 * "" for none (which, by SQLite's affinity rules, can hold text), NULL
 * when unknown (then only the explicit list applies). ASCII
 * case-insensitive, as SQLite's names are. */
int web_sdb_is_secret(const char *table, const char *column,
                      const char *decl_type);

#endif
