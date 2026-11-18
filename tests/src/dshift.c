/* x86 double-precision shifts (shrd / shld): 128-bit shifts on x86-64 -- tests/test_dshift.py */
#include <stdio.h>
#include <stdlib.h>
typedef unsigned __int128 u128;
__attribute__((noinline)) unsigned long long hi_shift(unsigned long long hi, unsigned long long lo, unsigned n)
{ u128 x = ((u128)hi << 64) | lo; return (unsigned long long)(x >> (n & 63)); }
__attribute__((noinline)) unsigned long long lo_shift(unsigned long long hi, unsigned long long lo, unsigned n)
{ u128 x = ((u128)hi << 64) | lo; return (unsigned long long)((x << (n & 63)) >> 64); }
__attribute__((noinline)) unsigned long long fixed(unsigned long long hi, unsigned long long lo)
{ u128 x = ((u128)hi << 64) | lo; return (unsigned long long)(x >> 12) ^ (unsigned long long)((x << 20) >> 64); }
int main(int c, char **v) { unsigned long long h = 0x0123456789abcdefULL * c, l = 0xfedcba9876543210ULL ^ c;
  for (unsigned n = 0; n < 64; n += 7) printf("%llx %llx ", hi_shift(h, l, n), lo_shift(h, l, n));
  printf("%llx\n", fixed(h, l)); return 0; }
