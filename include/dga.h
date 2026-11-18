#ifndef SLOTH_DGA_H
#define SLOTH_DGA_H

/* Domain Generation Algorithm (DGA) heuristic.
 *
 * Most DGA-style malware C2 domains have:
 *   - long random-looking left label (10+ chars; shorter is never
 *     scored, which is also why Conficker is out of reach)
 *   - few vowels, long consonant runs (kjxbqvz...), or dense digits
 *   - entropy close to the log2(len) ceiling for their length
 *
 * Real human-readable hostnames look very different. This function
 * gives a conservative yes/no — false positives are kept low at the
 * cost of missing dictionary-based DGAs, and since #222 also at the
 * cost of randoms with an ordinary vowel ratio; both need an n-gram
 * model. The scoring, the constants and what they do not catch are in
 * src/dga.c. */

/* Return 1 if `qname` looks like a DGA-generated domain; 0 otherwise.
 * NULL / empty / very short names always return 0. The floor is 10
 * characters on the leftmost label, applied per `-`-separated piece
 * (the header said 8 from the first commit to #222; the code has
 * always said 10). */
int dga_is_suspicious(const char *qname);

/* Compute the Shannon entropy of the leftmost label of `qname` in
 * bits-per-character. Exposed for tests + visualisation. Returns 0.0
 * for NULL / empty input. */
double dga_label_entropy(const char *qname);

#endif /* SLOTH_DGA_H */
