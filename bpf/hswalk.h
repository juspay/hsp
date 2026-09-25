/* hswalk: walk a GHC thread's stack from a register snapshot, reading the
 * target's memory through HS_READ.
 *
 * Included by hsp.bpf.c with HS_READ = bpf_probe_read_user, and by
 * tests/hswalk_test.c with HS_READ = memcpy over stacks it built itself, so
 * the logic the test proves is the logic the kernel runs.
 *
 * GHC keeps the Haskell stack in the heap (an StgStack chunk per TSO) and
 * points at its top with Sp, which on x86-64 is rbp.  A frame is [info
 * pointer][fields...]; the frame's size is in the info table 16 bytes
 * before the code the pointer names.  So given rbp every frame up to the
 * STOP_FRAME can be found without the RTS's help -- the same loop the GC
 * runs in scavenge_stack, from outside the process at an arbitrary
 * instruction.
 *
 * Two things an arbitrary instruction can do to the top of the stack:
 *   - the running procedure's own spill slots may sit at and above Sp,
 *     below its return frame: hswalk_begin scans up to HS_MAX_SCAN words for
 *     the first word that is a return-frame info pointer (7% of samples on
 *     a production service needed 1-22 words);
 *   - a mutator writes a frame's fields before its info pointer, so a tick
 *     in that window sees a stale pointer above new fields.  Every frame is
 *     validated (pointer inside the text, known frame type, sane size, Sp
 *     inside the chunk) and the walk stops at the first failure, keeping
 *     what it has, flagged BADFRAME.  How often is a printed statistic.
 */
#pragma once

#include "hsp_abi.h"

#ifndef HS_READ
#error "define HS_READ(dst_ptr, size, src_addr) -> 0 on success"
#endif

struct hswalk {
    /* inputs */
    hs_u64 text_lo, text_hi;
    hs_u32 max_depth;                /* <= HS_MAX_DEPTH */
    hs_u64 *frames;                  /* 2 * HS_MAX_DEPTH: (info, updatee) pairs */
    hs_u32 want_thunk;               /* read update frames' updatee (2 reads each) */
    /* state */
    hs_u64 sp;                       /* next frame to read */
    hs_u64 lo, hi;                   /* current chunk's stack[] bounds */
    hs_u32 n;                        /* frames written (host build; see HS_N) */
    hs_u32 *np;                      /* frames written (BPF build; see HS_N) */
    hs_u32 hops;                     /* underflow chunks followed */
    hs_u32 scanned;                  /* words skipped above Sp by begin */
    hs_u8  status;                   /* HS_STATUS_* once done */
    hs_u8  done;
};

/* The frame counter.  The BPF build keeps it in map memory (HS_COUNTER_IN_MAP,
 * w->np set by hsp.bpf.c): the verifier does not track map contents, so every
 * bpf_loop iteration of hswalk_step looks the same and the step is verified
 * once.  Kept in the on-stack struct instead, the counter is an exact scalar
 * (it indexes frames[]), iterations never converge, and the program is
 * rejected ("The sequence of 8193 jumps is too complex", -E2BIG) on kernel
 * 7.0.  The host test build uses the plain field. */
#ifdef HS_COUNTER_IN_MAP
#define HS_N(w) (*(w)->np)
#else
#define HS_N(w) ((w)->n)
#endif

static __always_inline int hs_read_u64(hs_u64 *dst, hs_u64 addr)
{
    return HS_READ(dst, sizeof(*dst), addr);
}

static __always_inline int hs_read_u32(hs_u32 *dst, hs_u64 addr)
{
    return HS_READ(dst, sizeof(*dst), addr);
}

static __always_inline int hs_is_frame_type(hs_u32 t)
{
    return (t >= HS_RET_BCO && t <= HS_STOP_FRAME) ||
           (t >= HS_ATOMICALLY_FRAME && t <= HS_CATCH_STM_FRAME);
}

/* Is the word at `addr' a return-frame info pointer?  Sets *type. */
/* The info table an info pointer names, read in one go: layout (8) | type
 * (4) | srt (4), the 16 bytes just before the code. */
struct hs_itbl { hs_u64 layout; hs_u32 type; hs_u32 srt; };

/* Is the word at `addr' a return-frame info pointer?  Sets *info and *t.
 * Two reads: the word, then its info table. */
static __always_inline int hs_frame_at(const struct hswalk *w, hs_u64 addr,
                                       hs_u64 *info, struct hs_itbl *t)
{
    if (hs_read_u64(info, addr))
        return 0;
    if (*info < w->text_lo + HS_ITBL_SIZE || *info >= w->text_hi)
        return 0;
    if (HS_READ(t, sizeof(*t), *info - HS_ITBL_SIZE))
        return 0;
    return hs_is_frame_type(t->type);
}

/* Point the walker at chunk `stackobj' (an StgStack *).  0 and lo/hi set,
 * or -1 if the object cannot be read or is absurd. */
static __always_inline int hswalk_enter_chunk(struct hswalk *w, hs_u64 stackobj)
{
    hs_u32 words;
    if (stackobj == 0 || (stackobj & 7))
        return -1;
    if (hs_read_u32(&words, stackobj + HS_OFF_STACK_SIZE))
        return -1;
    /* a chunk is at most a few MB; 1 << 28 words is the "not a stack
     * object" line, not a real limit */
    if (words == 0 || words > (1u << 28))
        return -1;
    w->lo = stackobj + HS_OFF_STACK_STACK;
    w->hi = w->lo + (hs_u64)words * 8;
    return 0;
}

static __always_inline void hswalk_stop(struct hswalk *w, hs_u8 status)
{
    w->status = status;
    w->done = 1;
}

/* Begin a walk at `sp' inside `stackobj': -1 with no frames if sp is not
 * inside that chunk (NOFRAME), else 0 with sp advanced past the running
 * procedure's slots to the first return frame (or the walk already stopped
 * BADFRAME when none is found within HS_MAX_SCAN words). */
static __always_inline int hswalk_begin(struct hswalk *w, hs_u64 stackobj, hs_u64 sp)
{
    hs_u64 info;
    struct hs_itbl t;
    hs_u32 i;
    HS_N(w) = 0;
    w->hops = 0;
    w->scanned = 0;
    w->status = 0;
    w->done = 0;
    if (hswalk_enter_chunk(w, stackobj))
        return -1;
    if ((sp & 7) || sp < w->lo || sp >= w->hi)
        return -1;
    w->sp = sp;
    for (i = 0; i < HS_MAX_SCAN; i++) {
        if (w->sp + 8 > w->hi)
            break;
        if (hs_frame_at(w, w->sp, &info, &t))
            return 0;
        w->sp += 8;
        w->scanned++;
    }
    hswalk_stop(w, HS_STATUS_BADFRAME);
    return 0;
}

/* Record one frame and advance.  1 when the walk is finished (inspect
 * w->status), 0 to continue. */
static __always_inline int hswalk_step(struct hswalk *w)
{
    hs_u64 info, layout, size_words, next, updatee = 0;
    struct hs_itbl t;
    hs_u32 type;

    if (w->done)
        return 1;
    hs_u32 n = HS_N(w);
    if (n >= w->max_depth || n >= HS_MAX_DEPTH) {
        hswalk_stop(w, HS_STATUS_DEPTHCAP);
        return 1;
    }
    if (w->sp < w->lo || w->sp + 8 > w->hi) {
        hswalk_stop(w, HS_STATUS_BADFRAME);
        return 1;
    }
    if (!hs_frame_at(w, w->sp, &info, &t)) {
        hswalk_stop(w, HS_STATUS_BADFRAME);
        return 1;
    }
    type = t.type;
    layout = t.layout;
    /* an update frame's updatee: the thunk under evaluation.  Its header
     * word names where it was created (or stg_BLACKHOLE_info once the RTS
     * has claimed it). */
    if (type == HS_UPDATE_FRAME && w->want_thunk) {
        hs_u64 u;
        if (hs_read_u64(&u, w->sp + HS_OFF_UPDATE_UPDATEE) == 0 && u)
            hs_read_u64(&updatee, u);
    }

    /* the frame is real: record it.  The mask is the verifier's bound. */
    w->frames[(2 * n) & (2 * HS_MAX_DEPTH - 1)] = info;
    w->frames[(2 * n + 1) & (2 * HS_MAX_DEPTH - 1)] = updatee;
    HS_N(w) = n + 1;

    switch (type) {
    case HS_STOP_FRAME:
        hswalk_stop(w, HS_STATUS_STOP);
        return 1;

    case HS_UNDERFLOW_FRAME:
        /* the rest of the stack is an older chunk; continue at its sp */
        if (hs_read_u64(&next, w->sp + HS_OFF_UNDERFLOW_NEXT) || next == 0
            || w->hops >= HS_MAX_CHUNK_HOPS || hswalk_enter_chunk(w, next)) {
            hswalk_stop(w, HS_STATUS_BADFRAME);
            return 1;
        }
        w->hops++;
        if (hs_read_u64(&w->sp, next + HS_OFF_STACK_SP)) {
            hswalk_stop(w, HS_STATUS_BADFRAME);
            return 1;
        }
        return 0;

    case HS_RET_BIG: {
        /* layout's low half: signed offset from the end of the info table
         * to an StgLargeBitmap whose first word is the size */
        hs_s32 off = (hs_s32)(layout & 0xffffffffu);
        hs_u64 lb = info + (hs_u64)(hs_s64)off;
        if (hs_read_u64(&size_words, lb + HS_OFF_LARGE_BITMAP_SIZE)) {
            hswalk_stop(w, HS_STATUS_BADFRAME);
            return 1;
        }
        size_words += 1;
        break;
    }

    case HS_RET_FUN:
        /* stg_gc_fun's frame caches its own payload size */
        if (hs_read_u64(&size_words, w->sp + HS_OFF_RETFUN_SIZE)) {
            hswalk_stop(w, HS_STATUS_BADFRAME);
            return 1;
        }
        size_words += HS_RETFUN_WORDS;
        break;

    case HS_RET_SMALL:
    case HS_UPDATE_FRAME:
    case HS_CATCH_FRAME:
    case HS_ATOMICALLY_FRAME:
    case HS_CATCH_RETRY_FRAME:
    case HS_CATCH_STM_FRAME:
        size_words = 1 + (layout & HS_BITMAP_SIZE_MASK);
        break;

    case HS_RET_BCO:
        hswalk_stop(w, HS_STATUS_BCO);
        return 1;

    default:
        hswalk_stop(w, HS_STATUS_BADFRAME);
        return 1;
    }

    /* a frame that does not fit inside its chunk is not a frame: it is
     * recorded (its info pointer named real code) and the walk ends here */
    if (size_words == 0 || size_words > (1u << 20)
        || w->sp + size_words * 8 > w->hi) {
        hswalk_stop(w, HS_STATUS_BADFRAME);
        return 1;
    }
    w->sp += size_words * 8;
    return 0;
}
