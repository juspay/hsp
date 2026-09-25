/* The sampler as a library: attach hsp.bpf.c to one process, hand every
 * record to a callback.  `hsp record' writes them to a file; `hsp agent'
 * aggregates them.  C, callable from C++. */
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "hsp_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

struct hs_sampler_opts {
    unsigned freq_hz;        /* per CPU; 0 = 99 */
    unsigned max_depth;      /* 0 = 512 */
    unsigned ring_mb;        /* 0 = 8 */
    int no_label, no_alloc, no_thunk;
};

struct hs_sampler_info {
    pid_t pid;
    char exe[4096];
    uint64_t exe_size;
    uint64_t text_lo, text_hi;
    int ghc_major, ghc_minor;   /* 0 when not found */
    int cpus;                   /* perf events attached */
    unsigned freq_hz, max_depth;
};

struct hs_sampler;

/* One record, exactly as the BPF program emitted it (HS_REC_FIXED + 16*depth
 * bytes).  Return 0; anything else stops the poll loop. */
typedef int (*hs_sampler_cb)(void *ctx, const struct hs_rec *r, size_t len);

/* Attach to `pid'.  `exe' is the executable to read (NULL: /proc/pid/exe;
 * a spawned child that has not exec'd yet needs it passed).  On failure
 * returns NULL with a message in err. */
struct hs_sampler *hs_sampler_attach(pid_t pid, const char *exe, const struct hs_sampler_opts *o,
                                     hs_sampler_cb cb, void *ctx, char *err, size_t errlen);
const struct hs_sampler_info *hs_sampler_info(const struct hs_sampler *s);
/* Drain the ring, waiting up to timeout_ms for records: number delivered, or -1. */
int hs_sampler_poll(struct hs_sampler *s, int timeout_ms);
int hs_sampler_alive(const struct hs_sampler *s);     /* the target still exists */
void hs_sampler_stats(const struct hs_sampler *s, uint64_t out[HS_ST_COUNT]);
void hs_sampler_close(struct hs_sampler *s);

#ifdef __cplusplus
}
#endif
