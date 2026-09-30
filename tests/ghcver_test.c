/* src/ghcver.h: the version string scan that picks the TSO offsets
 * (src/sampler.c) and the IPE layout (src/symmap.cpp).  Host test, no root.
 *
 *   cc -Isrc -o build/ghcver_test tests/ghcver_test.c && ./build/ghcver_test
 */
#include <stdio.h>
#include <string.h>
#include "ghcver.h"

static int fails, checks;

/* `buf' is a .rodata slice: NUL-separated strings, given with its length so
 * embedded NULs survive. */
static void expect(const char *what, const char *buf, size_t len,
                   int want_hit, int want_maj, int want_min)
{
    int maj = -1, min_ = -1;
    int hit = ghcver_find(buf, buf + len, &maj, &min_);
    int ok = hit == want_hit && (!want_hit || (maj == want_maj && min_ == want_min));
    checks++;
    if (!ok) {
        fails++;
        printf("  FAIL  %s: got hit=%d %d.%d, wanted hit=%d %d.%d\n",
               what, hit, maj, min_, want_hit, want_maj, want_min);
    } else {
        printf("  ok    %s\n", what);
    }
}
#define LIT(s) s, sizeof(s) - 1

int main(void)
{
    /* the shapes that must be recognised */
    expect("9.8.4",                    LIT("\0" "9.8.4" "\0"),           1, 9, 8);
    expect("9.8.4.20260910 (hadrian)", LIT("\0" "9.8.4.20260910" "\0"),  1, 9, 8);
    expect("10.1.0 (GHC 10)",          LIT("\0" "10.1.0" "\0"),          1, 10, 1);
    expect("9.10.1",                   LIT("\0" "9.10.1" "\0"),          1, 9, 10);
    expect("8.10.7",                   LIT("\0" "8.10.7" "\0"),          1, 8, 10);
    expect("9.2.8",                    LIT("\0" "9.2.8" "\0"),           1, 9, 2);
    expect("two components: 9.8",      LIT("\0" "9.8" "\0"),             1, 9, 8);
    expect("at the very start",         LIT("9.8.4" "\0"),                1, 9, 8);

    /* and the shapes that must not be mistaken for one */
    expect("embedded in a longer name", LIT("\0" "ghc-9.8.4" "\0"),       0, 0, 0);
    expect("not a version at all",      LIT("\0" "hello, world" "\0"),    0, 0, 0);
    expect("trailing junk",             LIT("\0" "9.8.4x" "\0"),          0, 0, 0);
    expect("major too large",           LIT("\0" "123.456.7" "\0"),       0, 0, 0);
    expect("major too small",           LIT("\0" "1.2.3" "\0"),           0, 0, 0);
    expect("minor too large",           LIT("\0" "9.100.1" "\0"),         0, 0, 0);
    expect("no NUL terminator",         LIT("\0" "9.8.4"),                0, 0, 0);
    expect("a bare number",             LIT("\0" "12345" "\0"),           0, 0, 0);
    expect("two chars only",            LIT("\0" "9." "\0"),              0, 0, 0);
    expect("empty",                     LIT(""),                          0, 0, 0);

    /* the real thing: a version among other strings, as .rodata has it */
    expect("among other strings",
           LIT("\0" "some other string" "\0" "9.8.4.20260910" "\0" "more" "\0"),
           1, 9, 8);

    printf("ghcver_test: %d/%d checks passed\n", checks - fails, checks);
    return fails ? 1 : 0;
}
