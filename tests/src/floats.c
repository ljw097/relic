/* Floating point for the decompiler (tests/test_floats.py): SSE scalar arithmetic, conversions,
   comparisons, float / double arguments and results, constants from .rodata. */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>

#define NI __attribute__((noinline))

NI double avg(const int *a, int n)
{
    double s = 0;
    for (int i = 0; i < n; i++)
        s += a[i];
    return n ? s / n : 0.0;
}

NI float scale(float x, float k) { return x * k + 1.5f; }

NI int cmpd(double a, double b)
{
    if (a < b)
        return -1;
    if (a > b)
        return 1;
    return 0;
}

NI double poly(double x) { return 3.0 * x * x - 2.0 * x + 0.5; }

NI long to_long(double x) { return (long)x; }

NI int to_int(float x) { return (int)x; }

NI double mix(int i, double x, float f, long l) { return i * x + f - l / 4.0; }

NI double clampd(double x, double lo, double hi)
{
    if (x < lo)
        return lo;
    if (x > hi)
        return hi;
    return x;
}

NI float narrow(double x) { return (float)x * 0.5f; }

NI double absneg(double x) { return x < 0 ? -x : x * 2; }

NI int count_above(const double *v, int n, double t)
{
    int c = 0;
    for (int i = 0; i < n; i++)
        if (v[i] >= t)
            c++;
    return c;
}

NI double sum_f(const float *v, int n)
{
    double s = 0;
    for (int i = 0; i < n; i++)
        s += v[i];
    return s;
}

NI int is_equal(double a, double b) { return a == b; }

NI double hyp(double a, double b) { return sqrt(a * a + b * b); }

NI double twice(double x) { return poly(x) + poly(-x); }

/* more arguments than registers: the rest go on the stack */
NI long many(int a, int b, int c, int d, int e, int f, int g, int h, double x)
{
    return a + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f + 7 * g + 8 * h + (long)x;
}

NI double many_f(double a, double b, double c, double d, double e, double f, double g, double h, double i,
                 double j)
{
    return a + b * 2 + c * 3 + d * 4 + e * 5 + f * 6 + g * 7 + h * 8 + i * 9 - j;
}

int main(int argc, char **argv)
{
    int v[4] = {1, 2, 3, argc};
    double d[3] = {0.5, 2.5, -1.0};
    float f[2] = {1.25f, 2.0f};
    printf("%f %f %d %f %ld %d %f %f %f %f %d %f %d %f %f\n", avg(v, 4), scale(2.0f, 3.0f), cmpd(1.0, 2.0),
           poly(2.0), to_long(3.7), to_int(-2.5f), mix(3, 1.5, 0.25f, 10), clampd(argc, 0, 1), narrow(3.0),
           absneg(-argc), count_above(d, 3, 0.5), sum_f(f, 2), is_equal(argc, 1.0), hyp(3, 4), twice(argc));
    printf("%ld %f\n", many(1, 2, 3, 4, 5, 6, 7, argc, 2.5),
           many_f(1, 2, 3, 4, 5, 6, 7, 8, argc, 0.5));
    return argv[0] == 0;
}
