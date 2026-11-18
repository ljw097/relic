/* Pointer arithmetic C only allows on integers (tests/test_emit_validc.py). */
#include <stddef.h>
#include <stdint.h>
typedef struct { uint32_t tab[64]; } table_t;
typedef struct { int a; int b; long c; } rec_t;
__attribute__((noinline)) uint32_t tget(table_t *t, unsigned i) { return t->tab[i & 63] + t->tab[(i + 1) & 63]; }
__attribute__((noinline)) void tset(table_t *t, unsigned n) { for (unsigned i = 0; i < n && i < 64; i++) t->tab[i] = i * 3; }
__attribute__((noinline)) long rdist(const char *base, rec_t *r) { return (const char *)r - base; }
__attribute__((noinline)) long ldist(const char *base, const long *p) { return (const char *)p - base; }
__attribute__((noinline)) unsigned bucket(const void *p) { return (unsigned)((uintptr_t)p >> 3) & 255; }
__attribute__((noinline)) int misal(const long *p) { return ((uintptr_t)p & 7) != 0; }
__attribute__((noinline)) long run(long (*cb)(void *, long), void *ctx, long n) { long s = 0; for (long i = 0; i < n; i++) s += cb(ctx, i); return s; }
__attribute__((noinline)) const char *skip(const char *s, const char *end) { while (s < end && *s == ' ') s++; return s + ((end - s) & 1); }
struct node { long a, b, c; long d; };
__attribute__((noinline)) void setd(long *ctx, long v) { ((struct node *)ctx[3])->d = v; }
__attribute__((noinline)) int posd(long *ctx) { return ((struct node *)ctx[3])->d > 0; }
int main(void) { return 0; }
