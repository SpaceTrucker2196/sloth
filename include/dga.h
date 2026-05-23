#ifndef SLOTH_DGA_H
#define SLOTH_DGA_H

/* Domain Generation Algorithm (DGA) heuristic.
 *
 * Most DGA-style malware C2 domains have:
 *   - long random-looking left label   (8+ chars, high Shannon entropy)
 *   - lots of digits or long consonant runs (kjxbqvz...)
 *
 * Real human-readable hostnames look very different. This function
 * gives a conservative yes/no — false positives are kept low at the
 * cost of missing dictionary-based DGAs (those need an n-gram model). */

/* Return 1 if `qname` looks like a DGA-generated domain; 0 otherwise.
 * NULL / empty / very short names always return 0. */
int dga_is_suspicious(const char *qname);

/* Compute the Shannon entropy of the leftmost label of `qname` in
 * bits-per-character. Exposed for tests + visualisation. Returns 0.0
 * for NULL / empty input. */
double dga_label_entropy(const char *qname);

#endif /* SLOTH_DGA_H */
