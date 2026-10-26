/* oui_gen OUT.c SLOTH_OUI_C [CSV...] (#162, M4): the vendor table
 * slothweb is built with (web_oui.h). Build time only; it opens the
 * files it is named and nothing else, and never the network.
 *
 * With one or more registry CSVs (web/data/oui.csv and its MA-M, MA-S
 * and IAB siblings, committed since the 2026-10-26 ruling; see
 * web/data/SOURCE.md), the table is theirs ("ieee"), and a CSV that
 * does not parse fails the build: a malformed registry should not
 * quietly become a smaller table. With none (a WEB_OUI_DIR without
 * them), it is sloth's own 117-entry table read out of src/oui.c as
 * text ("sloth"), and if that is unreadable too, empty ("none"). Either
 * way the build succeeds and /api/health says which. The generated C is
 * build output and never committed. */
#include <stdio.h>
#include <string.h>

#include "oui_csv.h"

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: oui_gen OUT.c SLOTH_OUI_C [CSV...]\n");
        return 2;
    }
    static oui_build_t b;
    oui_build_init(&b);
    const char *source = "none";
    if (argc > 3) {
        for (int i = 3; i < argc; i++) {
            if (oui_build_csv(&b, argv[i]) != 0) {
                fprintf(stderr, "oui_gen: %s\n", b.err);
                oui_build_free(&b);
                return 1;
            }
        }
        source = "ieee";
    } else if (oui_build_sloth(&b, argv[2]) == 0 && b.n > 0) {
        source = "sloth";
    } else {
        oui_build_free(&b);
        oui_build_init(&b);
    }
    if (oui_build_finish(&b, source) != 0) {
        fprintf(stderr, "oui_gen: %s\n", b.err);
        oui_build_free(&b);
        return 1;
    }
    FILE *out = fopen(argv[1], "w");
    if (!out) {
        perror(argv[1]);
        oui_build_free(&b);
        return 1;
    }
    int rc = oui_build_emit(&b, out);
    if (fclose(out) != 0) rc = -1;
    fprintf(stderr, "oui_gen: %s table: %u MA-L, %u MA-M, %u MA-S/IAB "
                    "(%lu other-registry rows skipped, %lu duplicates)%s\n",
            source, b.counts[0], b.counts[1], b.counts[2], b.skipped,
            b.duplicates,
            !strcmp(source, "ieee") ? ""
            : "; no IEEE registry CSVs in WEB_OUI_DIR: the full table "
              "is built from web/data/ (web/data/SOURCE.md)");
    oui_build_free(&b);
    return rc == 0 ? 0 : 1;
}
