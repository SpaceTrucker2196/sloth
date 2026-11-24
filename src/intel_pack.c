#include "intel_pack.h"

/* SLOTH_INTEL_PACK_VERSION, SLOTH_INTEL_PACK_HASH and SLOTH_INTEL_PACK_DATE, written by
 * tools/intel_gen into build/intel/ from intel/LOCK and the manifests
 * it verified (the build refuses a LOCK the packs do not hash to). */
#include "intel_pack.inc"

const char *intel_pack_version(void) { return SLOTH_INTEL_PACK_VERSION; }
const char *intel_pack_hash(void)    { return SLOTH_INTEL_PACK_HASH; }
const char *intel_pack_date(void)    { return SLOTH_INTEL_PACK_DATE; }
