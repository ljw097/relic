#include <stdio.h>
#include "structval_a64.h"

__attribute__((noinline)) struct pt add(struct pt a, struct pt b) { struct pt r = { a.x + b.x, a.y * b.y }; return r; }
__attribute__((noinline)) double norm(struct fpt p) { return p.x * p.x + p.y * p.y; }
__attribute__((noinline)) struct big make(long n) { struct big b = { n, n * 2, n * 3 }; return b; }
__attribute__((noinline)) long total(struct big b) { return b.a + b.b - b.c; }
__attribute__((noinline)) struct five fill(int k, struct five f) { f.a += k; f.e *= k; f.c = f.b - f.d; return f; }

int main(int argc, char **argv)
{
    struct pt p = { argc, 2 }, q = { 3, argc };
    struct pt r = add(p, q);
    struct fpt f = { argc, 1.5 };
    struct big b = make(argc);
    struct five v = { 1, argc, 3, 4, 5 };
    struct five w = fill(argc + 1, v);
    printf("%ld %ld %f %ld %d %d %d %d %d\n", r.x, r.y, norm(f), total(b), w.a, w.b, w.c, w.d, w.e);
    return 0;
}
