/* structs whose integer fields share a register (tests/test_structval.py) */
#include <stdio.h>
#include "structval_packed.h"
__attribute__((noinline)) struct pair swap(struct pair p) { struct pair r = { p.b, p.a + 1 }; return r; }
__attribute__((noinline)) long tsum(struct tri t) { return t.x * 100 + t.y * 10 + t.z; }
__attribute__((noinline)) long first(struct name n) { return n.s[0] + n.s[7] + n.n; }
__attribute__((noinline)) struct tri mk(int k) { return (struct tri){ k, k * 2, -k }; }
int main(int argc, char **argv) {
    struct pair r = swap((struct pair){ argc, 7 });
    struct tri t = mk(argc);
    struct name n = { "abcdefg", argc };
    printf("%d %d %ld %ld %d %d %d\n", r.a, r.b, tsum(t), first(n), t.x, t.y, t.z);
    return 0;
}
