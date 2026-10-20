#include <stdint.h>
#include <stddef.h>

#include "reg_6g.h"

/* libFuzzer smoke target for reg_6g_element() and reg_6g_merge()
 * (#101 slice B).
 *
 * Both parsers take a sender-chosen length decision from inside the
 * body — the HE Operation Parameters flags that move the 6 GHz field's
 * offset, and the TPE Count that sets how many value octets follow —
 * which is the shape an over-read hides in. fuzz_beacon_parse_ies.c
 * reaches this code too, behind the element walk; this target hands it
 * an element directly. First input octet picks the tag (even: 195 TPE,
 * odd: 255 with the body's own first octet as the extension ID, so
 * extension 36 is one byte away); the rest is the element body. Each
 * parse is merged into a retained record, so the keyed TPE store and
 * the saturating counters see many frames per run. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1 || size > 256) return 0;
    static reg_6g_t kept;
    reg_6g_t one;
    reg_6g_reset(&one);
    uint8_t tag = (data[0] & 1) ? 255 : 195;
    reg_6g_element(&one, tag, data + 1, (int)(size - 1));
    reg_6g_merge(&kept, &one);

    volatile int sink = kept.he6_reg_info;
    for (int i = 0; i < kept.tpe_count && i < REG_6G_MAX_TPE; i++)
        for (int v = 0; v < kept.tpe[i].n_values; v++)
            sink ^= kept.tpe[i].values_half_db[v];
    (void)sink;
    return 0;
}
