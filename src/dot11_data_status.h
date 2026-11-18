#ifndef DOT11_DATA_STATUS_H
#define DOT11_DATA_STATUS_H

/* The data-frame payload status codes, on their own so dot11_frame.h
 * can carry them without dot11_data.h. The contract archive
 * (libsloth-wire.a, #185) ships dot11_frame.h but not dot11_data.c;
 * taking the enum from dot11_data.h shipped eleven prototypes no
 * consumer could link (docs/wiki/contract.md, Gaps). */

/* Why a frame was rejected. Distinguishing these matters because
 * "encrypted" is the normal case on most networks and says nothing is
 * wrong, while "malformed" is a signal. */
typedef enum {
    DOT11_DATA_OK          =  0,
    DOT11_DATA_NOT_DATA    = -1,  /* not a type-2 frame              */
    DOT11_DATA_NO_PAYLOAD  = -2,  /* Null-function subtype, or empty */
    DOT11_DATA_ENCRYPTED   = -3,  /* Protected bit set               */
    DOT11_DATA_FRAGMENT    = -4,  /* More Fragments, or not fragment 0 */
    DOT11_DATA_AMSDU       = -5,  /* aggregated: several subframes   */
    DOT11_DATA_NOT_SNAP    = -6,  /* LLC present but not SNAP-encapsulated */
    DOT11_DATA_TRUNCATED   = -7,
} dot11_data_status_t;

#endif
