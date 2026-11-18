/* Functions for the behavioural-equivalence benchmark (tools/decomp_quality.py): each tool's
 * pseudocode of one of these, compiled again, must compute what the original computes on the
 * same inputs. Self-contained (libc only), no globals, no undefined behaviour on the inputs
 * tools/decomp_quality.py gives them. Built at -O0 and -O2 and stripped before decompiling. */
#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define F __attribute__((noinline, noclone))

struct pt { int x, y; };
struct rect { int x0, y0, x1, y1; };
struct node { int v; struct node *next; };
struct acc { long sum; int count; int max; };

/* ---- arithmetic */
F long gcd(long a, long b) { while (b) { long t = a % b; a = b; b = t; } return a < 0 ? -a : a; }
F int popcount(uint64_t x) { int n = 0; while (x) { x &= x - 1; n++; } return n; }
F uint32_t isqrt(uint32_t n) { uint32_t r = 0, b = 1u << 30; while (b > n) b >>= 2;
    while (b) { if (n >= r + b) { n -= r + b; r = (r >> 1) + b; } else r >>= 1; b >>= 2; } return r; }
F int collatz(uint32_t n) { int s = 0; uint64_t x = n ? n : 1; while (x != 1) { x = x & 1 ? 3 * x + 1 : x / 2; s++; } return s; }
F uint64_t powmod(uint64_t b, uint64_t e, uint64_t m) { uint64_t r = 1 % m; b %= m;
    while (e) { if (e & 1) r = (unsigned __int128)r * b % m; b = (unsigned __int128)b * b % m; e >>= 1; } return r; }
F int clamp(int v, int lo, int hi) { return v < lo ? lo : v > hi ? hi : v; }
F long fib(int n) { long a = 0, b = 1; for (int i = 0; i < n; i++) { long t = a + b; a = b; b = t; } return a; }
F uint32_t bitrev(uint32_t x) { uint32_t r = 0; for (int i = 0; i < 32; i++) { r = r << 1 | (x & 1); x >>= 1; } return r; }
F int32_t sat_add(int32_t a, int32_t b) { int64_t s = (int64_t)a + b; return s > INT32_MAX ? INT32_MAX : s < INT32_MIN ? INT32_MIN : (int32_t)s; }
F int digit_sum(long n) { int s = 0; if (n < 0) n = -n; do { s += n % 10; n /= 10; } while (n); return s; }
F int is_prime(uint32_t n) { if (n < 2) return 0; for (uint32_t d = 2; d <= n / d; d++) if (n % d == 0) return 0; return 1; }
F long div_round(long a, long b) { return (a >= 0) == (b > 0) ? (a + b / 2) / b : (a - b / 2) / b; }
F uint64_t rotl(uint64_t x, unsigned k) { k &= 63; return k ? x << k | x >> (64 - k) : x; }

/* ---- switches */
F int day_kind(int d) { switch (d) { case 0: case 6: return 2; case 1: case 2: case 3: case 4: return 1;
    case 5: return 3; default: return -1; } }
F int char_class(int c) { switch (c) { case ' ': case '\t': case '\n': return 1; case '(': case ')': return 2;
    case '+': case '-': case '*': case '/': return 3; case '0': return 4; case 'x': return 5; default: return 0; } }
F long calc(int op, long a, long b) { switch (op) { case '+': return a + b; case '-': return a - b;
    case '*': return a * b; case '/': return b ? a / b : 0; case '%': return b ? a % b : 0;
    case '&': return a & b; case '|': return a | b; case '^': return a ^ b; default: return -1; } }

/* ---- arrays */
F long sum_array(const int *a, int n) { long s = 0; for (int i = 0; i < n; i++) s += a[i]; return s; }
F int max_index(const int *a, int n) { int m = 0; for (int i = 1; i < n; i++) if (a[i] > a[m]) m = i; return n ? m : -1; }
F void reverse(int *a, int n) { for (int i = 0, j = n - 1; i < j; i++, j--) { int t = a[i]; a[i] = a[j]; a[j] = t; } }
F void bubble_sort(int *a, int n) { for (int i = 0; i < n; i++) for (int j = 0; j + 1 < n - i; j++)
    if (a[j] > a[j + 1]) { int t = a[j]; a[j] = a[j + 1]; a[j + 1] = t; } }
F int count_gt(const int *a, int n, int k) { int c = 0; while (n-- > 0) c += *a++ > k; return c; }
F void prefix_sum(int *a, int n) { for (int i = 1; i < n; i++) a[i] += a[i - 1]; }
F long dot(const int *a, const int *b, int n) { long s = 0; for (int i = 0; i < n; i++) s += (long)a[i] * b[i]; return s; }
F int bsearch_int(const int *a, int n, int key) { int lo = 0, hi = n - 1;
    while (lo <= hi) { int mid = lo + (hi - lo) / 2; if (a[mid] == key) return mid; if (a[mid] < key) lo = mid + 1; else hi = mid - 1; }
    return -1; }

/* ---- strings */
F size_t my_strlen(const char *s) { const char *p = s; while (*p) p++; return p - s; }
F int count_char(const char *s, int c) { int n = 0; for (; *s; s++) if (*s == c) n++; return n; }
F void to_upper(char *s) { for (; *s; s++) *s = toupper((unsigned char)*s); }
F uint32_t djb2(const char *s) { uint32_t h = 5381; int c; while ((c = (unsigned char)*s++)) h = h * 33 + c; return h; }
F long atoi_simple(const char *s) { long v = 0; int neg = 0; while (*s == ' ') s++;
    if (*s == '-' || *s == '+') neg = *s++ == '-'; while (*s >= '0' && *s <= '9') v = v * 10 + (*s++ - '0'); return neg ? -v : v; }
F int is_palindrome(const char *s) { size_t n = strlen(s); for (size_t i = 0; i < n / 2; i++) if (s[i] != s[n - 1 - i]) return 0; return 1; }
F int word_count(const char *s) { int n = 0, in = 0; for (; *s; s++) { if (*s == ' ') in = 0; else if (!in) { in = 1; n++; } } return n; }

/* ---- structs */
F int manhattan(const struct pt *a, const struct pt *b) { int dx = a->x - b->x, dy = a->y - b->y; return (dx < 0 ? -dx : dx) + (dy < 0 ? -dy : dy); }
F long rect_area(const struct rect *r) { long w = r->x1 - r->x0, h = r->y1 - r->y0; return w > 0 && h > 0 ? w * h : 0; }
F long list_sum(const struct node *n) { long s = 0; for (; n; n = n->next) s += n->v; return s; }
F void acc_add(struct acc *a, int v) { a->sum += v; a->count++; if (a->count == 1 || v > a->max) a->max = v; }
F int pt_cross(struct pt a, struct pt b) { return a.x * b.y - a.y * b.x; }

/* ---- floating point */
F double poly(double x) { return ((2.5 * x - 1.0) * x + 0.25) * x - 3.0; }
F double mean(const double *a, int n) { double s = 0; for (int i = 0; i < n; i++) s += a[i]; return n ? s / n : 0.0; }
F double lerp(double a, double b, double t) { return a + (b - a) * t; }
F int sign_d(double x) { return x > 0 ? 1 : x < 0 ? -1 : 0; }

/* ---- recursion */
F long fib_rec(int n) { return n < 2 ? n : fib_rec(n - 1) + fib_rec(n - 2); }
F long ackermann(long m, long n) { return m == 0 ? n + 1 : n == 0 ? ackermann(m - 1, 1) : ackermann(m - 1, ackermann(m, n - 1)); }

int main(int argc, char **argv)
{
    /* keeps every function (and its callers' view of it) in the program */
    volatile long sink = 0;
    if (argc > 99) {
        int a[4] = {argc, 2, 3, 4}; double d[2] = {1.0, argc}; char s[8] = "ab ba"; struct pt p = {argc, 1};
        struct rect r = {0, 0, argc, 2}; struct node n = {argc, 0}; struct acc ac = {0, 0, 0};
        sink += gcd(argc, 6) + popcount(argc) + isqrt(argc) + collatz(argc) + powmod(argc, 3, 7) + clamp(argc, 0, 9)
            + fib(argc) + bitrev(argc) + sat_add(argc, 1) + digit_sum(argc) + is_prime(argc) + div_round(argc, 3)
            + rotl(argc, 3) + day_kind(argc) + char_class(argc) + calc(argc, 1, 2) + sum_array(a, 4) + max_index(a, 4)
            + count_gt(a, 4, 2) + dot(a, a, 4) + bsearch_int(a, 4, 3) + my_strlen(argv[0]) + count_char(s, 'a')
            + djb2(s) + atoi_simple(s) + is_palindrome(s) + word_count(s) + manhattan(&p, &p) + rect_area(&r)
            + list_sum(&n) + pt_cross(p, p) + (long)poly(argc) + (long)mean(d, 2) + (long)lerp(0, 1, 0.5)
            + sign_d(argc) + fib_rec(argc) + ackermann(1, argc);
        reverse(a, 4); bubble_sort(a, 4); prefix_sum(a, 4); to_upper(s); acc_add(&ac, argc);
        sink += a[0] + s[0] + ac.sum;
    }
    return (int)sink & 0;
}
