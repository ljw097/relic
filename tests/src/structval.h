/* structs passed and returned by value (tests/test_structval.py) */
struct pt { long x; long y; };
struct fpt { double x; double y; };
struct mix { int tag; double v; };
struct big { long a; long b; long c; };
struct q { long a; long b; };
struct wide { long w[4]; };
struct dq { double d; long n; };
struct five { int a; int b; int c; int d; int e; };

struct pt add(struct pt a, struct pt b);
double norm(struct fpt p);
double scale(struct mix m, int k);
struct big make(long n);
long total(struct big b);
long late(long a, long b, long c, long d, long e, struct q x, struct q y);
struct wide build(struct q a, struct dq p);
struct five fill(int k, struct five f);
