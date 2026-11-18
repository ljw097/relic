/* Parameters only some code reads (tests/test_params.py). */
#define F __attribute__((noinline, noclone))
static const char *names[] = {"nil", "bool", "num", "str"};
F const char *type_name(void *state, int t) { (void)state; return names[t + 1]; }      /* first one unused */
F long scale(long v, long k) { return v * k + 1; }
F long forward(long a, long b, long c) { return scale(c, b) + a; }                     /* b, c moved on */
F long second(void *state, long x) { (void)state; return scale(x, 3); }                 /* unused, then moved on */
int main(int argc, char **argv) { return (int)(type_name(0, argc - 1)[0] + forward(argc, 2, 3) + second(argv, argc)); }
