/* long double: the x87's 80-bit format on x86 and x86-64 (tests/test_ldouble.py). */
#include <stdio.h>

long double g_ld = 1.5L;
long double table[4] = {0.5L, -2.25L, 8.0L, 0.125L};

__attribute__((noinline)) long double ld_scale(long double x, int k) { return x * k + g_ld; }
__attribute__((noinline)) double ld_to_d(long double x) { return (double)x * 2; }
__attribute__((noinline)) long double ld_from_d(double x) { return x / 4; }
__attribute__((noinline)) long double ld_half(long double x) { return x * 0.5L - 0.25L; }
__attribute__((noinline)) long double ld_abs(long double x) { return __builtin_fabsl(x) + 1; }
__attribute__((noinline)) int ld_cmp(long double a, long double b) { return a < b ? -1 : a > b; }
__attribute__((noinline)) long double ld_mix(int a, long double b, double c) { return a + b * c; }
__attribute__((noinline)) long double ld_call(long double x) { return ld_scale(x, 3) - ld_from_d(1.5); }

__attribute__((noinline)) long double ld_sum(int n)
{
    long double s = 0;
    for (int i = 0; i < n && i < 4; i++)
        s += table[i];
    return s;
}

__attribute__((noinline)) void ld_store(long double *out, double x) { *out = x + g_ld; }

int main(int argc, char **argv)
{
    long double r;
    ld_store(&r, argc);
    printf("%Lf %f %d\n", ld_call(r), ld_to_d(ld_mix(argc, r, 0.5)), ld_cmp(r, ld_half(r)));
    printf("%Lf\n", ld_sum(argc + 2));
    return 0;
}
