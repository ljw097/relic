/* structs by value on AArch64 (tests/test_structval.py): core registers, an HFA of doubles in
   SIMD registers, bigger ones by reference, a big result through x8 */
struct pt { long x; long y; };
struct fpt { double x; double y; };
struct big { long a; long b; long c; };
struct five { int a; int b; int c; int d; int e; };
struct pt add(struct pt a, struct pt b);
double norm(struct fpt p);
struct big make(long n);
long total(struct big b);
struct five fill(int k, struct five f);
