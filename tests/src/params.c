/* Parameters only some code reads (tests/test_params.py). */
#define F __attribute__((noinline, noclone))
static const char *names[] = {"nil", "bool", "num", "str"};
F const char *type_name(void *state, int t) { (void)state; return names[t + 1]; }      /* first one unused */
F long scale(long v, long k) { return v * k + 1; }
F long forward(long a, long b, long c) { return scale(c, b) + a; }                     /* b, c moved on */
F long second(void *state, long x) { (void)state; return scale(x, 3); }                 /* unused, then moved on */
/* types from what callees do with a parameter: s only passed on to one that calls strlen */
#include <stdarg.h>
#include <string.h>
F long measure(void *ctx, const char *s) { (void)ctx; return (long)strlen(s) * 2; }
F long push_string(void *ctx, const char *s) { return measure(ctx, s) + 1; }
/* variadic: the fixed parameters, then `...`; callers pass what follows */
F int sum(int n, ...) { va_list ap; va_start(ap, n); int s = 0; for (int i = 0; i < n; i++) s += va_arg(ap, int); va_end(ap); return s; }
F int sum3(int x) { return sum(3, x, 2, 3); }
int main(int argc, char **argv) { return (int)(type_name(0, argc - 1)[0] + forward(argc, 2, 3) + second(argv, argc)
    + push_string(argv, argv[0]) + sum3(argc)); }
