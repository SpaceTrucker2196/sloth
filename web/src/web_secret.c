#include "web_secret.h"

#include <string.h>

/* web_secret.h says why each is here. */
const web_sdb_secret_t web_sdb_secret[] = {
    { "alerts", "key" },                 /* a credential's username (akey_remote) */
    { "alerts", "detail" },              /* the same username, an RDP cookie,
                                            an MQTT username in the text */
    { "cleartext_creds", "username" },
    { "mqtt_flows", "last_username" },
    { "rogue_radius", "last_identity" }, /* a leaked EAP identity */
    { "rdp_flows", "last_cookie" },      /* mstshash: an account name */
};
const size_t web_sdb_secret_n = sizeof(web_sdb_secret) / sizeof(web_sdb_secret[0]);

const char *const web_sdb_secret_words[] = {
    /* tests/test_db.c test_no_column_can_hold_secret_material() */
    "pmkid", "nonce", "mic", "password", "passwd", "community", "secret",
    "key_material",
    /* the credential words test_slothdb.c holds the allow-list to */
    "user", "identity", "pass", "pw_", "cred", "token", "psk", "pmk",
    "auth", "login", "cookie", "hash",
    NULL
};

static int lc(int c) { return c >= 'A' && c <= 'Z' ? c + 32 : c; }

static int eq_ci(const char *a, const char *b) {
    for (; *a && *b; a++, b++)
        if (lc((unsigned char)*a) != lc((unsigned char)*b)) return 0;
    return !*a && !*b;
}

static int has_ci(const char *hay, const char *needle) {
    size_t n = strlen(needle);
    for (; *hay; hay++) {
        size_t i = 0;
        while (i < n && hay[i] && lc((unsigned char)hay[i]) == lc((unsigned char)needle[i]))
            i++;
        if (i == n) return 1;
    }
    return 0;
}

/* TEXT or BLOB by SQLite's own affinity rules (§3.1 of its datatype
 * page): a declared type holding CHAR, CLOB, TEXT or BLOB, or none at
 * all, can hold the material. */
static int can_hold_text(const char *t) {
    if (!t || !t[0]) return 1;
    if (has_ci(t, "INT")) return 0;
    return has_ci(t, "CHAR") || has_ci(t, "CLOB") || has_ci(t, "TEXT") ||
           has_ci(t, "BLOB");
}

int web_sdb_is_secret(const char *table, const char *column,
                      const char *decl_type) {
    if (!table || !column) return 0;
    for (size_t i = 0; i < web_sdb_secret_n; i++)
        if (eq_ci(web_sdb_secret[i].table, table) &&
            eq_ci(web_sdb_secret[i].column, column))
            return 1;
    if (!decl_type || !can_hold_text(decl_type)) return 0;
    for (int i = 0; web_sdb_secret_words[i]; i++)
        if (has_ci(column, web_sdb_secret_words[i])) return 1;
    return 0;
}
