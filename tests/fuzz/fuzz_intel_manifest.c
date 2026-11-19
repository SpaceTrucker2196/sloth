#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "../../tools/intel_read.h"

/* libFuzzer target for sloth's intel-pack reader (#231): the strict
 * manifest JSON reader, the RFC 4180 CSV reader and the LOCK reader,
 * which tools/intel_gen runs on intel/ before every build. Their input
 * is committed data, not the air, but a pack arrives from another
 * repository through `make update-intel`, and a reader that refuses
 * hostile shapes has to be shown not to fault on them.
 *
 * One input, three readers: the first byte picks which, the rest is the
 * file. The CSV is read against a fixed two-column header, the shape of
 * oui_builtin.csv, so the fuzzer can get past the header check. Nothing
 * is written; every allocation is freed. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1 || size > (1u << 16)) return 0;
    const char *body = (const char *)data + 1;
    size_t len = size - 1;
    char err[IR_ERR];
    switch (data[0] % 4) {
    case 0: {
        static ir_manifest_t m;
        (void)ir_manifest_parse(body, len, &m, err, sizeof(err));
        break;
    }
    case 1: {
        static const char *const cols[] = { "oui", "vendor" };
        ir_csv_t c;
        if (ir_csv_parse(body, len, cols, 2, &c, err, sizeof(err)) == 0)
            ir_csv_free(&c);
        break;
    }
    case 2: {
        ir_lock_t l;
        (void)ir_lock_parse(body, len, &l, err, sizeof(err));
        break;
    }
    default:
        (void)ir_csv_count(body, len);
        break;
    }
    return 0;
}
