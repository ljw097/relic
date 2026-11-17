/* structs passed and returned by value (x86-64 System V): in registers (integer, SSE, both),
   on the stack, past the registers, through a hidden result pointer -- tests/test_structval.py */
#include <stdio.h>
#include "structval.h"

__attribute__((noinline)) struct pt add(struct pt a, struct pt b) { struct pt r = { a.x + b.x, a.y * b.y }; return r; }
__attribute__((noinline)) double norm(struct fpt p) { return p.x * p.x + p.y * p.y; }
__attribute__((noinline)) double scale(struct mix m, int k) { return m.tag * m.v * k; }
__attribute__((noinline)) struct big make(long n) { struct big b = { n, n * 2, n * 3 }; return b; }
__attribute__((noinline)) long total(struct big b) { return b.a + b.b - b.c; }
__attribute__((noinline)) long late(long a, long b, long c, long d, long e, struct q x, struct q y)
{
    return a + b + c + d + e + x.a * 3 + x.b * 5 + y.a * 7 + y.b * 11;
}
__attribute__((noinline)) struct wide build(struct q a, struct dq p)
{
    struct wide w = {{ a.a, a.b, (long)(p.d * 4), p.n }};
    return w;
}
__attribute__((noinline)) struct five fill(int k, struct five f) { f.a += k; f.e *= k; f.c = f.b - f.d; return f; }

int main(int argc, char **argv)
{
    struct pt p = { argc, 2 }, q = { 3, argc };
    struct pt r = add(p, q);
    struct fpt f = { argc, 1.5 };
    struct mix m = { argc, 2.5 };
    struct big b = make(argc);
    printf("%ld %ld %f %f %ld\n", r.x, r.y, norm(f), scale(m, 3), total(b));
    struct q x = { argc, 2 }, y = { 3, argc };
    struct dq d = { argc * 1.25, 9 };
    struct wide w = build(x, d);
    struct five v = { 1, argc, 3, 4, 5 };
    struct five g = fill(argc + 1, v);
    printf("%ld %ld %ld %ld %ld %d %d %d %d %d\n", late(1, 2, 3, 4, 5, x, y), w.w[0], w.w[1], w.w[2], w.w[3],
           g.a, g.b, g.c, g.d, g.e);
    return 0;
}
