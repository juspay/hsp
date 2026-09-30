/* The GHC version a binary was built with, scanned out of .rodata: the RTS
 * info table (what `+RTS --info' prints) keeps it there as a bare
 * NUL-terminated version string.
 *
 * Neither a leading '9' nor a length of 8 can be assumed -- a hadrian tree
 * emits "9.8.4.20260910" and GHC 10 exists -- and getting it wrong is not
 * cosmetic: src/sampler.c picks the TSO offsets from it and src/symmap.cpp
 * picks an IPE layout.  Shared so that both read the same string the same way.
 */
#pragma once
#include <stdio.h>

/* Scans [p, end) for the first plausible version.  Returns 1 and sets *maj and
 * *min on a hit, 0 otherwise. */
static inline int ghcver_find(const char *p, const char *end, int *maj, int *min)
{
    /* No lower bound on the bytes left: the NUL search below is what keeps
     * this in range, and a 4-byte "9.8\0" can sit at the end of a section. */
    for (const char *q = p; q < end; q++) {
        if (q[0] < '0' || q[0] > '9') continue;
        if (q > p && q[-1] != 0) continue;            /* a string of its own */
        const char *z = q; while (z < end && *z) z++;
        if (z >= end || z - q < 3 || z - q > 24) continue;   /* NUL-terminated */
        int only_digits_and_dots = 1;
        for (const char *r = q; r < z; r++)
            if ((*r < '0' || *r > '9') && *r != '.') { only_digits_and_dots = 0; break; }
        if (!only_digits_and_dots) continue;
        int a = 0, b = 0, c = 0;
        if (sscanf(q, "%d.%d.%d", &a, &b, &c) < 2) continue;
        if (a < 8 || a > 99 || b > 99) continue;      /* 8.x .. 99.x */
        *maj = a; *min = b;
        return 1;
    }
    return 0;
}
