/* hsp: what the BPF program (hsp.bpf.c), the loader (record.c), the capture
 * reader (capture.cpp) and the host test (hswalk_test.c) share.  No kernel or
 * libbpf headers, so it compiles everywhere.
 *
 * Every number about the RTS is in `struct hs_cfg', filled by the loader:
 * the BPF program hardcodes nothing about GHC.  The defaults below are the
 * values of DerivedConstants.h for GHC 9.8 and 9.10 (non-profiling,
 * threaded, TABLES_NEXT_TO_CODE, x86-64), absolute, i.e. with the 8-byte
 * StgHeader added where DerivedConstants leaves it out.  They were proven
 * live on a production GHC 9.8.4 service.
 */
#pragma once

#ifndef __bpf__
#include <stdint.h>
typedef uint64_t hs_u64;
typedef uint32_t hs_u32;
typedef uint16_t hs_u16;
typedef uint8_t  hs_u8;
typedef int64_t  hs_s64;
typedef int32_t  hs_s32;
#else
typedef unsigned long long hs_u64;
typedef unsigned int hs_u32;
typedef unsigned short hs_u16;
typedef unsigned char hs_u8;
typedef long long hs_s64;
typedef int hs_s32;
#endif

/* -- RTS layout (defaults; see hs_cfg) ------------------------------------ */
#define HS_DEF_OFF_REGTABLE_CURTSO    872   /* OFFSET_StgRegTable_rCurrentTSO     */
#define HS_DEF_OFF_REGTABLE_NURSERY   888   /* OFFSET_StgRegTable_rCurrentNursery */
#define HS_DEF_OFF_TSO_STACKOBJ       24    /* 8 + OFFSET_StgTSO_stackobj         */
#define HS_DEF_OFF_TSO_ID             48    /* 8 + OFFSET_StgTSO_id               */
#define HS_DEF_OFF_TSO_LABEL          88    /* 8 + OFFSET_StgTSO_label            */
#define HS_DEF_OFF_TSO_ALLOC_LIMIT    112   /* 8 + OFFSET_StgTSO_alloc_limit      */

/* StgStack: header, then stack_size (u32, words) at +8, sp at +16, stack[] at +24 */
#define HS_OFF_STACK_SIZE             8
#define HS_OFF_STACK_SP               16
#define HS_OFF_STACK_STACK            24
/* StgArrBytes (a thread label): header, byte count at +8, bytes at +16 */
#define HS_OFF_ARR_BYTES              8
#define HS_OFF_ARR_PAYLOAD            16
/* bdescr.start is the block's first word: at +0 */
#define HS_OFF_BDESCR_START           0

/* Info tables: layout (8) | type (4) | srt (4), right before the code. */
#define HS_ITBL_SIZE                  16
#define HS_OFF_ITBL_LAYOUT            0
#define HS_OFF_ITBL_TYPE              8
#define HS_BITMAP_SIZE_MASK           0x3f
#define HS_OFF_LARGE_BITMAP_SIZE      0
#define HS_OFF_RETFUN_SIZE            8
#define HS_RETFUN_WORDS               3
#define HS_OFF_UNDERFLOW_NEXT         8
#define HS_OFF_UPDATE_UPDATEE         8

/* Closure types (rts/storage/ClosureTypes.h) */
#define HS_RET_BCO                    29
#define HS_RET_SMALL                  30
#define HS_RET_BIG                    31
#define HS_RET_FUN                    32
#define HS_UPDATE_FRAME               33
#define HS_CATCH_FRAME                34
#define HS_UNDERFLOW_FRAME            35
#define HS_STOP_FRAME                 36
#define HS_ATOMICALLY_FRAME           55
#define HS_CATCH_RETRY_FRAME          56
#define HS_CATCH_STM_FRAME            57

/* -- Limits ------------------------------------------------------------------ */
#define HS_MAX_DEPTH                  1024  /* power of two: the BPF side masks   */
#define HS_MAX_SCAN                   64    /* words looked at above Sp           */
#define HS_MAX_CHUNK_HOPS             64
#define HS_LABEL_MAX                  64    /* bytes of a thread label kept       */
#define HS_NURSERY_BLOCK_MAX          (1u << 20)

/* -- Walk outcome ------------------------------------------------------------
 * The numbers are hswalk_agg.py's, so fold reports the same status names. */
#define HS_STATUS_STOP                1     /* reached STOP_FRAME: the whole stack */
#define HS_STATUS_BADFRAME            2     /* a frame did not validate            */
#define HS_STATUS_BCO                 3     /* interpreter frame                   */
#define HS_STATUS_DEPTHCAP            4     /* max_depth reached                   */
#define HS_STATUS_NOFRAME             5     /* no Haskell stack for these registers*/

#define HS_F_IN_KERNEL                0x01  /* tick in a syscall; user regs used   */
#define HS_F_TSO                      0x02  /* r13 named a live TSO: tso_id valid  */
#define HS_F_ALLOC                    0x04  /* alloc is valid (Hp inside nursery)  */
#define HS_F_LABEL                    0x08  /* label_len bytes of label present    */

/* -- Capture file ------------------------------------------------------------
 * HSPREC01 header, then records exactly as the BPF program emitted them.
 * All little-endian. */
#define HS_FILE_MAGIC                 "HSPREC01"

struct hs_file_hdr {
    char   magic[8];
    hs_u32 version;              /* 1 */
    hs_u32 hdr_size;             /* sizeof(struct hs_file_hdr) */
    hs_u32 pid;
    hs_u32 freq_hz;
    hs_u64 text_lo, text_hi;     /* the target's executable range, as sampled */
    hs_u64 t0_ns;                /* CLOCK_MONOTONIC when sampling started */
    hs_u64 reserved[2];
};

/* One sample: fixed part, then `depth' pairs of (info pointer, updatee
 * info pointer or 0).  The updatee is set for UPDATE_FRAMEs only: the
 * closure being evaluated, whose info table names where the thunk was
 * created.  Size on the wire: sizeof(hs_rec) + 16 * depth. */
struct hs_rec {
    hs_u64 ts_ns;                /* bpf_ktime_get_ns at the tick */
    hs_u64 pc;                   /* user-mode program counter */
    hs_u64 tso_id;               /* StgTSO.id, if HS_F_TSO */
    hs_s64 alloc;                /* getAllocationCounter's value, if HS_F_ALLOC */
    hs_u32 tid;
    hs_u32 cost_ns;              /* the walk's in-kernel cost */
    hs_u16 depth;                /* pairs that follow */
    hs_u16 hops;                 /* underflow chunks followed */
    hs_u16 scanned;              /* words skipped above Sp */
    hs_u8  status;               /* HS_STATUS_* */
    hs_u8  flags;                /* HS_F_* */
    hs_u8  label_len;
    hs_u8  pad[7];
    char   label[HS_LABEL_MAX];
    hs_u64 frames[2 * HS_MAX_DEPTH];   /* only 2*depth are written out */
};
#define HS_REC_FIXED   (sizeof(struct hs_rec) - sizeof(hs_u64) * 2 * HS_MAX_DEPTH)

/* What the loader tells the BPF program.  Addresses are absolute in the
 * target (load base added). */
struct hs_cfg {
    hs_u32 tgid;                 /* process to sample */
    hs_u32 max_depth;            /* <= HS_MAX_DEPTH */
    hs_u64 text_lo, text_hi;     /* executable PT_LOAD range */
    hs_u64 stg_tso_info;         /* &stg_TSO_info: a live TSO's header word */
    hs_u32 off_curtso, off_nursery;
    hs_u32 off_stackobj, off_id, off_label, off_alloc_limit;
    hs_u32 want_label, want_alloc;
    hs_u32 want_thunk, pad_;       /* name update frames' thunks by their creator */
};

/* Counters the BPF program keeps, printed by the loader at exit. */
enum hs_stat {
    HS_ST_TICKS = 0,      /* ticks for the target process                */
    HS_ST_OUTSIDE_TEXT,   /* of which pc outside the binary (libc, vdso) */
    HS_ST_KERNEL,         /* of which in kernel mode                     */
    HS_ST_TSO,            /* r13 named a live TSO                        */
    HS_ST_WALKED,         /* a walk ran                                  */
    HS_ST_STOP,           /* ... and reached STOP_FRAME                  */
    HS_ST_BROKEN,
    HS_ST_TRUNCATED,
    HS_ST_DROPPED,        /* ring buffer full: record lost               */
    HS_ST_COUNT
};
