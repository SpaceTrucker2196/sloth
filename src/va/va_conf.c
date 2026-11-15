/* Parsers for victron-va.conf and victron.keys; see va_conf.h. */
#include "va/va_conf.h"
#include "va/va_aes.h"
#include "va/va_victron.h"

#include <ctype.h>
#include <string.h>

#define LINE_MAX_LEN 255
#define MAX_FIELDS   4

const char *va_conf_err_name(va_conf_err_t e) {
    switch (e) {
    case VA_CE_NONE:      return "ok";
    case VA_CE_FIELDS:    return "wrong number of fields";
    case VA_CE_SERIAL:    return "serial is not 6-20 letters and digits";
    case VA_CE_PIN:       return "PIN is not exactly 6 digits";
    case VA_CE_MAC:       return "address is not aa:bb:cc:dd:ee:ff";
    case VA_CE_KEY:       return "key is not 32 hex digits";
    case VA_CE_DUPLICATE: return "device listed twice";
    case VA_CE_TOO_MANY:  return "too many devices";
    case VA_CE_LONG_LINE: return "line too long";
    }
    return "unknown";
}

/* Split one line (comment stripped) into whitespace-separated fields,
 * in place in `line`. Returns the field count, MAX_FIELDS + 1 for more. */
static int split(char *line, char *f[MAX_FIELDS]) {
    char *hash = strchr(line, '#');
    if (hash) *hash = '\0';
    int n = 0;
    char *p = line;
    for (;;) {
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) break;
        if (n == MAX_FIELDS) return MAX_FIELDS + 1;
        f[n++] = p;
        while (*p && !isspace((unsigned char)*p)) p++;
        if (*p) *p++ = '\0';
    }
    return n;
}

static int is_mac(const char *s, uint8_t mac[6]) {
    /* Colon form only: BlueZ's dev_ form is an object path, not
     * something an owner types. */
    return strlen(s) == 17 && strchr(s, '_') == NULL && va_mac_parse(s, mac) == 0;
}

static int hexv(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    c = tolower(c);
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

/* Walk `text` line by line; `fn` gets a writable copy of each line that
 * has content. The copy is wiped after every line: it may hold a PIN or
 * a key. */
typedef int (*line_fn)(void *st, char *line, int lineno);

static void walk(const char *text, line_fn fn, void *st,
                 va_conf_diag_fn diag, void *ctx) {
    char buf[LINE_MAX_LEN + 2];
    int lineno = 0;
    const char *p = text;
    while (p && *p) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        lineno++;
        if (n > LINE_MAX_LEN) {
            if (diag) diag(ctx, lineno, VA_CE_LONG_LINE);
        } else {
            memcpy(buf, p, n);
            buf[n] = '\0';
            if (n && buf[n - 1] == '\r') buf[n - 1] = '\0';
            int e = fn(st, buf, lineno);
            if (e != VA_CE_NONE && diag) diag(ctx, lineno, (va_conf_err_t)e);
        }
        va_wipe(buf, sizeof(buf));
        p = nl ? nl + 1 : NULL;
    }
}

typedef struct { va_dev_conf_t *out; int max, n; } dev_st_t;

static int dev_line(void *vst, char *line, int lineno) {
    dev_st_t *st = vst;
    char *f[MAX_FIELDS];
    (void)lineno;
    int k = split(line, f);
    if (k == 0) return VA_CE_NONE;
    if (k != 2 && k != 3) return VA_CE_FIELDS;
    size_t sl = strlen(f[0]);
    if (sl < 6 || sl > VA_SERIAL_MAX) return VA_CE_SERIAL;
    for (size_t i = 0; i < sl; i++)
        if (!isalnum((unsigned char)f[0][i])) return VA_CE_SERIAL;
    if (strlen(f[1]) != VA_PIN_LEN) return VA_CE_PIN;
    uint32_t pin = 0;
    for (int i = 0; i < VA_PIN_LEN; i++) {
        if (!isdigit((unsigned char)f[1][i])) return VA_CE_PIN;
        pin = pin * 10u + (uint32_t)(f[1][i] - '0');
    }
    va_dev_conf_t d;
    memset(&d, 0, sizeof(d));
    memcpy(d.serial, f[0], sl + 1);
    d.pin = pin;
    if (k == 3) {
        if (!is_mac(f[2], d.mac)) { va_wipe(&d, sizeof(d)); return VA_CE_MAC; }
        d.has_mac = 1;
    }
    for (int i = 0; i < st->n; i++) {
        int same_serial = 0;
        const char *a = st->out[i].serial, *b = d.serial;
        while (*a && *b && toupper((unsigned char)*a) == toupper((unsigned char)*b)) { a++; b++; }
        same_serial = (*a == '\0' && *b == '\0');
        int same_mac = d.has_mac && st->out[i].has_mac && !memcmp(d.mac, st->out[i].mac, 6);
        if (same_serial || same_mac) { va_wipe(&d, sizeof(d)); return VA_CE_DUPLICATE; }
    }
    if (st->n >= st->max) { va_wipe(&d, sizeof(d)); return VA_CE_TOO_MANY; }
    st->out[st->n++] = d;
    va_wipe(&d, sizeof(d));
    return VA_CE_NONE;
}

int va_conf_parse_devices(const char *text, va_dev_conf_t *out, int max,
                          va_conf_diag_fn diag, void *ctx) {
    dev_st_t st = { out, max, 0 };
    walk(text, dev_line, &st, diag, ctx);
    return st.n;
}

typedef struct { va_key_t *out; int max, n; } key_st_t;

static int key_line(void *vst, char *line, int lineno) {
    key_st_t *st = vst;
    char *f[MAX_FIELDS];
    (void)lineno;
    int k = split(line, f);
    if (k == 0) return VA_CE_NONE;
    if (k != 2) return VA_CE_FIELDS;
    va_key_t e;
    memset(&e, 0, sizeof(e));
    if (!is_mac(f[0], e.mac)) return VA_CE_MAC;
    if (strlen(f[1]) != 32) return VA_CE_KEY;
    for (int i = 0; i < 16; i++) {
        int hi = hexv((unsigned char)f[1][2 * i]), lo = hexv((unsigned char)f[1][2 * i + 1]);
        if (hi < 0 || lo < 0) { va_wipe(&e, sizeof(e)); return VA_CE_KEY; }
        e.key[i] = (uint8_t)(hi << 4 | lo);
    }
    for (int i = 0; i < st->n; i++)
        if (!memcmp(st->out[i].mac, e.mac, 6)) { va_wipe(&e, sizeof(e)); return VA_CE_DUPLICATE; }
    if (st->n >= st->max) { va_wipe(&e, sizeof(e)); return VA_CE_TOO_MANY; }
    st->out[st->n++] = e;
    va_wipe(&e, sizeof(e));
    return VA_CE_NONE;
}

int va_conf_parse_keys(const char *text, va_key_t *out, int max,
                       va_conf_diag_fn diag, void *ctx) {
    key_st_t st = { out, max, 0 };
    walk(text, key_line, &st, diag, ctx);
    return st.n;
}
