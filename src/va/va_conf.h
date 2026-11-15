#ifndef VA_CONF_H
#define VA_CONF_H

#include <stddef.h>
#include <stdint.h>

/* sloth-va's two secret files, parsed without I/O so the tests can feed
 * them text (tests/test_va.c). docs/wiki/victron.md has the formats.
 *
 * Devices (victron-va.conf), one per line:
 *     SERIAL PIN [MAC]   # comment
 *   SERIAL  the device's serial number as on its label, 6..20 of
 *           [A-Za-z0-9] ("HQ2501YV9FU");
 *   PIN     its Bluetooth PIN, exactly 6 decimal digits (Victron's PIN
 *           is six digits; the default is 000000);
 *   MAC     optional: the owner's statement of which address the device
 *           uses, for a device that broadcasts no Instant Readout (the
 *           VE.Direct dongle) and so cannot be learned from the keys.
 *
 * Keys (victron.keys), one per line:
 *     MAC KEY            # comment
 *   KEY     the 16-byte Instant Readout key as 32 hex digits.
 *
 * Diagnostics name the line number and a fixed reason, never the
 * line's text: a malformed line may be a PIN or a key with a typo, and
 * a log is the last place either belongs. */

#define VA_MAX_DEVICES 16
#define VA_SERIAL_MAX  20
#define VA_PIN_LEN     6

typedef struct {
    char     serial[VA_SERIAL_MAX + 1];
    uint32_t pin;              /* 0 .. 999999 */
    int      has_mac;
    uint8_t  mac[6];
} va_dev_conf_t;

typedef struct {
    uint8_t mac[6];
    uint8_t key[16];
} va_key_t;

typedef enum {
    VA_CE_NONE = 0,
    VA_CE_FIELDS,         /* wrong number of fields */
    VA_CE_SERIAL,         /* serial not 6..20 alphanumerics */
    VA_CE_PIN,            /* PIN not exactly 6 digits */
    VA_CE_MAC,            /* address not aa:bb:cc:dd:ee:ff */
    VA_CE_KEY,            /* key not 32 hex digits */
    VA_CE_DUPLICATE,      /* serial or address already listed */
    VA_CE_TOO_MANY,       /* more than VA_MAX_DEVICES entries */
    VA_CE_LONG_LINE       /* longer than 255 bytes */
} va_conf_err_t;

/* Called once per refused line; `line` is 1-based. May be NULL. */
typedef void (*va_conf_diag_fn)(void *ctx, int line, va_conf_err_t why);

const char *va_conf_err_name(va_conf_err_t e);

/* Parse NUL-terminated `text`. Accepted entries go to out[0..ret-1]; a
 * refused line is reported and skipped, never half-applied. Returns the
 * number accepted (>= 0). */
int va_conf_parse_devices(const char *text, va_dev_conf_t *out, int max,
                          va_conf_diag_fn diag, void *ctx);
int va_conf_parse_keys(const char *text, va_key_t *out, int max,
                       va_conf_diag_fn diag, void *ctx);

#endif /* VA_CONF_H */
