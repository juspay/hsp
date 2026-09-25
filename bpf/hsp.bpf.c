/* hsp: the BPF side.  One perf_event program, attached to a cpu-clock event
 * on every CPU.  Each tick for the target process becomes one hs_rec in the
 * ring buffer, and nothing else happens: no per-frame printf, no map
 * updates, no strings but the thread label.
 *
 * The x86-64 register snapshot is the interrupted state.  For a Haskell
 * mutator (rts/include/stg/MachRegs.h, MACHREGS_x86_64):
 *
 *     ip   what was running          -> leaf, resolved by address offline
 *     bp   Sp                        -> top of the Haskell stack
 *     r13  BaseReg (&cap->r)         -> rCurrentTSO, rCurrentNursery
 *     r12  Hp                        -> allocation counter
 *
 * Whether these registers ARE a mutator's: r13 + off_curtso must point at
 * an object whose header word is stg_TSO_info.  C code (GC, libc, foreign
 * calls) reuses r13 freely and then the read fails or finds something else:
 * such ticks are recorded with NOFRAME and depth 0, and their pc still says
 * what was running.  A stale-but-valid r13 in a GC thread passes this and
 * fails the next one: rbp must lie inside that TSO's current stack chunk.
 *
 * When the tick lands in kernel mode (a syscall), ctx->regs is kernel state
 * and the user registers are the ones saved at kernel entry
 * (bpf_task_pt_regs); those records carry HS_F_IN_KERNEL.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "hsp_abi.h"

#define HS_COUNTER_IN_MAP 1        /* see HS_N in hswalk.h */
#define HS_READ(dst, size, addr) \
    bpf_probe_read_user((dst), (size), (const void *)(unsigned long)(addr))
#include "hswalk.h"

char LICENSE[] SEC("license") = "GPL";

/* Filled in by the loader before load (skeleton rodata). */
const volatile struct hs_cfg cfg = {};

__u64 stats[HS_ST_COUNT] SEC(".bss");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 23);        /* the loader may change this */
} rb SEC(".maps");

/* One record's worth of scratch per CPU: the walk fills frames[] here and
 * the used prefix is copied to the ring. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct hs_rec);
} scratch SEC(".maps");

/* The walk's frame counter, per CPU, in map memory (see HS_N in hswalk.h). */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} walk_n SEC(".maps");

static __always_inline void bump(enum hs_stat s)
{
    __sync_fetch_and_add(&stats[s], 1);
}

/* bpf_loop body: one frame per iteration, so the verifier checks the step
 * once instead of unrolling HS_MAX_DEPTH copies of it. */
static long walk_cb(__u64 i, void *p)
{
    return hswalk_step((struct hswalk *)p) ? 1 : 0;
}

SEC("perf_event")
int hsp_sample(struct bpf_perf_event_data *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 ip, sp, base, hp, cs, tso = 0, hdr = 0, t0;
    __u32 zero = 0, depth = 0;
    __u8 flags = 0, status = HS_STATUS_NOFRAME;
    struct hs_rec *r;
    struct pt_regs *regs = (struct pt_regs *)&ctx->regs;

    if ((__u32)(pid_tgid >> 32) != cfg.tgid)
        return 0;
    bump(HS_ST_TICKS);

    /* A perf_event context only allows full-word reads of the register
     * block; the volatile load keeps clang from narrowing `cs & 3' to a
     * 16-bit access, which the verifier rejects. */
    cs = *(volatile __u64 *)&regs->cs;
    if ((cs & 3) != 3) {
        struct task_struct *task = bpf_get_current_task_btf();
        struct pt_regs *ur = (struct pt_regs *)bpf_task_pt_regs(task);
        flags |= HS_F_IN_KERNEL;
        bump(HS_ST_KERNEL);
        ip   = BPF_CORE_READ(ur, ip);
        sp   = BPF_CORE_READ(ur, bp);
        base = BPF_CORE_READ(ur, r13);
        hp   = BPF_CORE_READ(ur, r12);
    } else {
        ip   = *(volatile __u64 *)&regs->ip;
        sp   = *(volatile __u64 *)&regs->bp;
        base = *(volatile __u64 *)&regs->r13;
        hp   = *(volatile __u64 *)&regs->r12;
    }
    /* bpftrace's sampler skipped these too; a leaf in libc/vdso has no
     * Haskell name and its stack would be walked from a C rbp */
    if (ip < cfg.text_lo || ip >= cfg.text_hi) {
        bump(HS_ST_OUTSIDE_TEXT);
        return 0;
    }

    r = bpf_map_lookup_elem(&scratch, &zero);
    if (!r)
        return 0;
    t0 = bpf_ktime_get_ns();
    r->tso_id = 0;
    r->alloc = 0;
    r->label_len = 0;

    /* r13 -> rCurrentTSO -> header == stg_TSO_info: a live Haskell thread */
    if (base && !(base & 7) &&
        hs_read_u64(&tso, base + cfg.off_curtso) == 0 && tso &&
        hs_read_u64(&hdr, tso) == 0 && hdr == cfg.stg_tso_info) {
        __u64 stackobj = 0, lbl = 0, nursery = 0, start = 0;
        __u64 limit = 0;
        flags |= HS_F_TSO;
        bump(HS_ST_TSO);
        hs_read_u64(&r->tso_id, tso + cfg.off_id);

        /* the thread's label, if the program set one (GHC.Conc.labelThread) */
        if (cfg.want_label && hs_read_u64(&lbl, tso + cfg.off_label) == 0 && lbl) {
            __u64 len = 0;
            if (hs_read_u64(&len, lbl + HS_OFF_ARR_BYTES) == 0 && len) {
                if (len > HS_LABEL_MAX) len = HS_LABEL_MAX;
                if (bpf_probe_read_user(r->label, (__u32)len,
                                        (const void *)(unsigned long)(lbl + HS_OFF_ARR_PAYLOAD)) == 0) {
                    r->label_len = len;
                    flags |= HS_F_LABEL;
                }
            }
        }

        /* getAllocationCounter (PrimOps.cmm): alloc_limit counts down per
         * finished nursery block, minus the used part of the current one,
         * Hp - CurrentNursery->start.  Only meaningful with Hp inside it. */
        if (cfg.want_alloc &&
            hs_read_u64(&limit, tso + cfg.off_alloc_limit) == 0 &&
            hs_read_u64(&nursery, base + cfg.off_nursery) == 0 && nursery &&
            hs_read_u64(&start, nursery + HS_OFF_BDESCR_START) == 0 &&
            hp >= start && hp - start < HS_NURSERY_BLOCK_MAX) {
            r->alloc = (__s64)limit - (__s64)(hp - start);
            flags |= HS_F_ALLOC;
        }

        __u32 *np = bpf_map_lookup_elem(&walk_n, &zero);
        if (!np)
            return 0;
        struct hswalk w = {
            .text_lo = cfg.text_lo, .text_hi = cfg.text_hi,
            .max_depth = cfg.max_depth ? cfg.max_depth : HS_MAX_DEPTH,
            .frames = r->frames,
            .want_thunk = cfg.want_thunk,
            .np = np,
        };
        hs_read_u64(&stackobj, tso + cfg.off_stackobj);
        if (hswalk_begin(&w, stackobj, sp) == 0) {
            bump(HS_ST_WALKED);
            if (!w.done)
                bpf_loop(HS_MAX_DEPTH + HS_MAX_CHUNK_HOPS, walk_cb, &w, 0);
            depth = *np;
            status = w.status;
            r->hops = w.hops;
            r->scanned = w.scanned;
            if (status == HS_STATUS_STOP)          bump(HS_ST_STOP);
            else if (status == HS_STATUS_DEPTHCAP) bump(HS_ST_TRUNCATED);
            else                                   bump(HS_ST_BROKEN);
        }
    }
    if (status == HS_STATUS_NOFRAME) {
        r->hops = 0;
        r->scanned = 0;
    }
    if (depth > HS_MAX_DEPTH)
        depth = HS_MAX_DEPTH;

    r->ts_ns   = t0;
    r->pc      = ip;
    r->tid     = (__u32)pid_tgid;
    r->depth   = depth;
    r->status  = status;
    r->flags   = flags;
    r->cost_ns = (__u32)(bpf_ktime_get_ns() - t0);

    if (bpf_ringbuf_output(&rb, r, HS_REC_FIXED + (__u64)depth * 16, 0))
        bump(HS_ST_DROPPED);
    return 0;
}
