/* Conversions between unsigned integers and floats (gcc -O2 turns the 64-bit ones into two-way code). */
#include <stdio.h>
#include <stdlib.h>
__attribute__((noinline)) double u2d(unsigned long x) { return (double)x; }
__attribute__((noinline)) unsigned long d2u(double x) { return (unsigned long)x; }
__attribute__((noinline)) float u2f(unsigned long x) { return (float)x; }
__attribute__((noinline)) unsigned long f2u(float x) { return (unsigned long)x; }
__attribute__((noinline)) double u32d(unsigned int x) { return (double)x; }
int main(int argc, char **argv) { unsigned long v = strtoul(argv[1], 0, 0); printf("%f %lu %f %lu %f\n", u2d(v), d2u(u2d(v)), u2f(v), f2u(u2f(v)), u32d((unsigned)v)); return 0; }
