/* structs by value in a more everyday program: vector math, a (pointer, length) span, a result
   with a flag (tests/test_structval.py) */
#include <stdio.h>
#include <string.h>
#include "structval2.h"
__attribute__((noinline)) struct vec2 v2add(struct vec2 a, struct vec2 b) { return (struct vec2){ a.x + b.x, a.y + b.y }; }
__attribute__((noinline)) double v2dot(struct vec2 a, struct vec2 b) { return a.x * b.x + a.y * b.y; }
__attribute__((noinline)) struct vec3 v3cross(struct vec3 a, struct vec3 b) {
    return (struct vec3){ a.y * b.z - a.z * b.y, a.z * b.x - a.x * b.z, a.x * b.y - a.y * b.x }; }
__attribute__((noinline)) struct vec3 v3scale(struct vec3 a, double k) { return (struct vec3){ a.x * k, a.y * k, a.z * k }; }
__attribute__((noinline)) struct span span_from(const char *s) { return (struct span){ s, strlen(s) }; }
__attribute__((noinline)) struct span span_skip(struct span s, size_t k) { if (k > s.n) k = s.n; return (struct span){ s.p + k, s.n - k }; }
__attribute__((noinline)) size_t span_count(struct span s, char c) { size_t n = 0; for (size_t i = 0; i < s.n; i++) n += s.p[i] == c; return n; }
__attribute__((noinline)) struct res parse(struct span s) {
    long v = 0; size_t i = 0;
    for (; i < s.n && s.p[i] >= '0' && s.p[i] <= '9'; i++) v = v * 10 + (s.p[i] - '0');
    return (struct res){ i > 0, v }; }
__attribute__((noinline)) unsigned rgba_sum(struct rgba c) { return c.r + c.g + c.b + c.a; }
int main(int argc, char **argv) {
    struct vec2 a = { argc, 0.5 }, b = { 2, argc };
    struct vec2 s = v2add(a, b);
    struct vec3 x = { 1, argc, 3 }, y = { argc, 5, 6 };
    struct vec3 c = v3scale(v3cross(x, y), 0.5);
    struct span sp = span_from(argc > 1 ? argv[1] : "1234,5,6");
    struct span t = span_skip(sp, 1);
    struct res r = parse(t);
    struct rgba col = { 1, 2, (unsigned char)argc, 4 };
    printf("%g %g %g | %g %g %g | %zu %zu | %d %ld | %u\n", s.x, s.y, v2dot(a, b), c.x, c.y, c.z,
           span_count(sp, ','), t.n, r.ok, r.val, rgba_sum(col));
    return 0;
}
