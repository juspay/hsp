/* C for hsp-testprog's `ffi' mode: CPU spent outside Haskell code.
 *
 * hsp_busy_unsafe overwrites r13 and r12 on every round.  In Haskell code
 * those are BaseReg and Hp; optimised C (a compressor's inner loop) uses them
 * as ordinary registers, so a sampler that finds the running thread through
 * r13 alone loses it here.  hsp_busy_safe leaves them alone: during a safe
 * call r13 can still point at the capability the caller gave up, which by
 * then is running another thread. */
#include <stdint.h>

#if defined(__x86_64__)
#define CLOBBER_STG_REGS() __asm__ volatile("xorl %%r13d, %%r13d\n\txorl %%r12d, %%r12d" : : : "r13", "r12")
#else
#define CLOBBER_STG_REGS() ((void)0)
#endif

__attribute__((noinline)) long hsp_busy_unsafe(long n)
{
    uint64_t x = 88172645463325252ull;
    for (long i = 0; i < n; i++) {
        CLOBBER_STG_REGS();
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    }
    return (long)(x & 0xff);
}

__attribute__((noinline)) long hsp_busy_safe(long n)
{
    uint64_t x = 2463534242ull;
    for (long i = 0; i < n; i++) {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    }
    return (long)(x & 0xff);
}
