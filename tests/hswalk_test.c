/* hswalk_test: the stack walker on synthetic GHC stacks, no kernel, no root.
 *
 * Builds fake info tables in a fake "text" region and fake StgStack chunks
 * with the layouts hsp_abi.h pins, then runs the exact code hsp.bpf.c runs
 * (hswalk.h with HS_READ = memcpy) and checks what it records: frame sizing
 * for every accepted frame type, underflow into an older chunk, STOP_FRAME,
 * the depth cap, the scan above Sp, the updatee of an update frame, and every
 * validation failure.  What it cannot prove: that the pinned offsets match
 * the RTS -- the fakes are built from the same constants.  tests/smoke.sh
 * is the check for that.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int hs_memread(void *dst, size_t size, uint64_t addr)
{
    memcpy(dst, (const void *)(uintptr_t)addr, size);
    return 0;
}
#define HS_READ(dst, size, addr) hs_memread((dst), (size), (addr))
#undef __always_inline
#define __always_inline inline
#include "hswalk.h"

static int failures, checks;
#define CHECK(cond, ...) do { checks++; if (!(cond)) { failures++; \
    fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
    fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } } while (0)

/* ---- fake text: info tables followed by one byte of "code" ------------- */

static unsigned char text[8192] __attribute__((aligned(16)));
static size_t text_used = 64;                    /* margin at text_lo */

static uint64_t mk_itbl(uint32_t type, uint64_t layout)
{
    unsigned char *p = text + text_used;
    memcpy(p + HS_OFF_ITBL_LAYOUT, &layout, 8);
    memcpy(p + HS_OFF_ITBL_TYPE, &type, 4);
    text_used += HS_ITBL_SIZE + 16;              /* itbl, then "code" */
    return (uint64_t)(uintptr_t)(p + HS_ITBL_SIZE);
}

/* A RET_BIG needs an StgLargeBitmap in text; layout carries the signed
 * offset from the END of the info table (== the info pointer). */
static uint64_t mk_ret_big(uint64_t size_words)
{
    unsigned char *lb = text + text_used;
    memcpy(lb + HS_OFF_LARGE_BITMAP_SIZE, &size_words, 8);
    text_used += 16;
    uint64_t info = mk_itbl(HS_RET_BIG, 0);
    int32_t off = (int32_t)((int64_t)(uintptr_t)lb - (int64_t)info);
    uint64_t layout = (uint64_t)(uint32_t)off;
    memcpy((void *)(uintptr_t)(info - HS_ITBL_SIZE + HS_OFF_ITBL_LAYOUT), &layout, 8);
    return info;
}

/* ---- fake stack chunks --------------------------------------------------- */

struct chunk {
    uint64_t header;
    uint32_t stack_size;          /* HS_OFF_STACK_SIZE  == 8  */
    uint8_t  dirty, marking; uint16_t pad;
    uint64_t sp;                  /* HS_OFF_STACK_SP    == 16 */
    uint64_t stack[512];          /* HS_OFF_STACK_STACK == 24 */
};

static struct chunk *new_chunk(void)
{
    struct chunk *c = calloc(1, sizeof *c);
    c->stack_size = 512;
    c->sp = (uint64_t)(uintptr_t)c->stack;
    return c;
}

/* Frames are laid down from the top (lowest address) downwards, so a test
 * lists them top-first and gets sp == &stack[0]. */
struct builder { struct chunk *c; size_t at; };

static uint64_t *push(struct builder *b, uint64_t info, size_t words)
{
    uint64_t *f = b->c->stack + b->at;
    f[0] = info;
    b->at += words;
    return f;
}

/* ---- the tests ----------------------------------------------------------- */

static uint64_t frames[2 * HS_MAX_DEPTH];
#define INFO(k)    frames[2 * (k)]
#define UPDATEE(k) frames[2 * (k) + 1]

static uint32_t want_thunk = 1;

static struct hswalk walk_of(struct chunk *c, uint32_t max_depth, uint64_t sp)
{
    struct hswalk w = {
        .text_lo = (uint64_t)(uintptr_t)text,
        .text_hi = (uint64_t)(uintptr_t)text + sizeof text,
        .max_depth = max_depth, .frames = frames, .want_thunk = want_thunk,
    };
    int rc = hswalk_begin(&w, (uint64_t)(uintptr_t)c, sp);
    if (rc) w.done = 2;                           /* 2: begin refused */
    return w;
}

static void run(struct hswalk *w)
{
    for (int i = 0; i < HS_MAX_DEPTH + HS_MAX_CHUNK_HOPS; i++)
        if (hswalk_step(w)) break;
}

int main(void)
{
    uint64_t i_small2  = mk_itbl(HS_RET_SMALL, 1);       /* 1 field: 2 words */
    uint64_t i_small1  = mk_itbl(HS_RET_SMALL, 0);       /* just the info ptr */
    uint64_t i_upd     = mk_itbl(HS_UPDATE_FRAME, 1);    /* updatee: 2 words */
    uint64_t i_catch   = mk_itbl(HS_CATCH_FRAME, 1);
    uint64_t i_big     = mk_ret_big(5);                  /* 1 + 5 words */
    uint64_t i_fun     = mk_itbl(HS_RET_FUN, 0);         /* 3 + size words */
    uint64_t i_under   = mk_itbl(HS_UNDERFLOW_FRAME, 1);
    uint64_t i_stop    = mk_itbl(HS_STOP_FRAME, 0);
    uint64_t i_bco     = mk_itbl(HS_RET_BCO, 0);
    uint64_t i_bogus   = mk_itbl(99, 0);
    uint64_t i_atom    = mk_itbl(HS_ATOMICALLY_FRAME, 2);
    uint64_t i_thunk   = mk_itbl(17, 0);                 /* a THUNK's info table */
    uint64_t i_fun_tbl = mk_itbl(3, 0);                  /* a FUN's: not a frame */

    /* 1. The whole menu, across two chunks, ending at STOP_FRAME. */
    {
        struct chunk *old = new_chunk();
        struct builder ob = { old, 0 };
        push(&ob, i_small1, 1);
        push(&ob, i_atom, 3);
        push(&ob, i_stop, 1);

        uint64_t thunk[2] = { i_thunk, 0 };          /* a heap closure */
        struct chunk *young = new_chunk();
        struct builder yb = { young, 0 };
        push(&yb, i_small2, 2);
        push(&yb, i_big, 6);
        uint64_t *rf = push(&yb, i_fun, 3 + 4); rf[1] = 4;   /* StgRetFun.size */
        uint64_t *uf0 = push(&yb, i_upd, 2); uf0[1] = (uint64_t)(uintptr_t)thunk;
        push(&yb, i_catch, 2);
        uint64_t *uf = push(&yb, i_under, 2); uf[1] = (uint64_t)(uintptr_t)old;

        struct hswalk w = walk_of(young, 256, young->sp);
        run(&w);
        uint64_t want[] = { i_small2, i_big, i_fun, i_upd, i_catch, i_under,
                            i_small1, i_atom, i_stop };
        CHECK(w.done == 1, "walk finished");
        CHECK(w.status == HS_STATUS_STOP, "STOP, got %u", w.status);
        CHECK(w.n == 9, "9 frames, got %u", w.n);
        for (unsigned k = 0; k < 9 && k < w.n; k++)
            CHECK(INFO(k) == want[k], "frame %u", k);
        CHECK(UPDATEE(3) == i_thunk, "update frame carries its thunk's info pointer");
        CHECK(UPDATEE(0) == 0 && UPDATEE(4) == 0, "other frames carry 0");
        want_thunk = 0;
        w = walk_of(young, 256, young->sp);
        run(&w);
        CHECK(w.n == 9 && w.status == HS_STATUS_STOP && UPDATEE(3) == 0, "want_thunk=0: same walk, updatee not read");
        want_thunk = 1;
        CHECK(w.hops == 1, "one chunk hop, got %u", w.hops);
        CHECK(w.scanned == 0, "no scan needed");
        free(old); free(young);
    }

    /* 2. Depth cap reached before STOP. */
    {
        struct chunk *c = new_chunk();
        struct builder b = { c, 0 };
        for (int k = 0; k < 10; k++) push(&b, i_small2, 2);
        push(&b, i_stop, 1);
        struct hswalk w = walk_of(c, 3, c->sp);
        run(&w);
        CHECK(w.n == 3, "capped at 3, got %u", w.n);
        CHECK(w.status == HS_STATUS_DEPTHCAP, "DEPTHCAP, got %u", w.status);
        free(c);
    }

    /* 3. Broken: an info pointer outside the text.  Frames before it kept. */
    {
        struct chunk *c = new_chunk();
        struct builder b = { c, 0 };
        push(&b, i_small2, 2);
        push(&b, i_upd, 2);
        push(&b, 0xdeadbeef000, 1);
        struct hswalk w = walk_of(c, 256, c->sp);
        run(&w);
        CHECK(w.n == 2, "2 frames before the bad one, got %u", w.n);
        CHECK(w.status == HS_STATUS_BADFRAME, "BADFRAME, got %u", w.status);
        free(c);
    }

    /* 4. Unknown closure type breaks; RET_BCO is its own status.  Neither
     * is recorded: the scan/step only accept return-frame types. */
    {
        struct chunk *c = new_chunk();
        struct builder b = { c, 0 };
        push(&b, i_small2, 2);
        push(&b, i_bogus, 1);
        struct hswalk w = walk_of(c, 256, c->sp);
        run(&w);
        CHECK(w.n == 1 && w.status == HS_STATUS_BADFRAME, "bogus type breaks (n=%u st=%u)", w.n, w.status);

        c->stack[2] = i_bco;
        w = walk_of(c, 256, c->sp);
        run(&w);
        CHECK(w.n == 2 && w.status == HS_STATUS_BCO, "RET_BCO recorded then BCO status (n=%u st=%u)", w.n, w.status);
        free(c);
    }

    /* 5. A frame overhangs the chunk end (no STOP_FRAME): recorded, then
     * the walk stops rather than reading past the chunk. */
    {
        struct chunk *c = new_chunk();
        c->stack_size = 3;
        struct builder b = { c, 0 };
        push(&b, i_small2, 2);
        push(&b, i_small2, 2);
        struct hswalk w = walk_of(c, 256, c->sp);
        run(&w);
        CHECK(w.n == 2, "2 frames, the second flagged, got %u", w.n);
        CHECK(w.status == HS_STATUS_BADFRAME, "BADFRAME, got %u", w.status);
        c->stack_size = 2;
        w = walk_of(c, 256, c->sp);
        run(&w);
        CHECK(w.n == 1 && w.status == HS_STATUS_BADFRAME, "1 frame then off the end");
        free(c);
    }

    /* 6. Begin refuses an Sp outside the chunk, unaligned, or a null stack
     * object -- the NOFRAME decision. */
    {
        struct chunk *c = new_chunk();
        struct builder b = { c, 0 };
        push(&b, i_stop, 1);
        struct hswalk w;
        w = walk_of(c, 256, (uint64_t)(uintptr_t)c->stack - 8);
        CHECK(w.done == 2, "sp below chunk refused");
        w = walk_of(c, 256, (uint64_t)(uintptr_t)(c->stack + 512));
        CHECK(w.done == 2, "sp at chunk end refused");
        w = walk_of(c, 256, c->sp + 4);
        CHECK(w.done == 2, "unaligned sp refused");
        w = walk_of(NULL, 256, c->sp);
        CHECK(w.done == 2, "null stackobj refused");
        w = walk_of(c, 256, c->sp);
        CHECK(w.done == 0, "in-range sp accepted");
        free(c);
    }

    /* 7. Underflow into a dead chunk pointer is BADFRAME, not a crash. */
    {
        struct chunk *c = new_chunk();
        struct builder b = { c, 0 };
        uint64_t *uf = push(&b, i_under, 2); uf[1] = 0;
        struct hswalk w = walk_of(c, 256, c->sp);
        run(&w);
        CHECK(w.n == 1 && w.status == HS_STATUS_BADFRAME, "null next_chunk breaks");
        free(c);
    }

    /* 8. Scan above Sp: the running procedure's slots (a heap pointer, a
     * FUN's info pointer, an integer) sit above the first return frame. */
    {
        struct chunk *c = new_chunk();
        struct builder b = { c, 0 };
        uint64_t heap[2] = { i_fun_tbl, 0 };
        push(&b, (uint64_t)(uintptr_t)heap, 1);      /* a pointer into the heap */
        push(&b, i_fun_tbl, 1);                       /* an info pointer, not a frame's */
        push(&b, 42, 1);                              /* an unboxed value */
        push(&b, i_small2, 2);
        push(&b, i_stop, 1);
        struct hswalk w = walk_of(c, 256, c->sp);
        run(&w);
        CHECK(w.scanned == 3, "3 words skipped, got %u", w.scanned);
        CHECK(w.n == 2 && INFO(0) == i_small2 && w.status == HS_STATUS_STOP,
              "walk from the first frame (n=%u st=%u)", w.n, w.status);

        /* nothing frame-like within HS_MAX_SCAN words: BADFRAME, 0 frames */
        struct chunk *d = new_chunk();
        for (int k = 0; k < 512; k++) d->stack[k] = 7;
        w = walk_of(d, 256, d->sp);
        run(&w);
        CHECK(w.done && w.n == 0 && w.status == HS_STATUS_BADFRAME && w.scanned == HS_MAX_SCAN,
              "scan gives up (n=%u st=%u scanned=%u)", w.n, w.status, w.scanned);

        /* the scan stops at the chunk end */
        d->stack_size = 4;
        w = walk_of(d, 256, d->sp);
        run(&w);
        CHECK(w.n == 0 && w.status == HS_STATUS_BADFRAME && w.scanned == 4,
              "scan bounded by the chunk (scanned=%u)", w.scanned);
        free(c); free(d);
    }

    /* 9. Record layout the loader and the reader rely on. */
    {
        CHECK(HS_REC_FIXED == 120, "fixed part is 120 bytes, got %zu", (size_t)HS_REC_FIXED);
        CHECK(sizeof(struct hs_file_hdr) == 64, "file header is 64 bytes");
        CHECK((HS_MAX_DEPTH & (HS_MAX_DEPTH - 1)) == 0, "HS_MAX_DEPTH is a power of two");
    }

    printf("hswalk_test: %d/%d checks passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
