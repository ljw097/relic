#include <stddef.h>
struct vec2 { double x; double y; };
struct vec3 { double x; double y; double z; };
struct span { const char *p; size_t n; };
struct res { int ok; long val; };
struct rgba { unsigned char r; unsigned char g; unsigned char b; unsigned char a; };
struct vec2 v2add(struct vec2 a, struct vec2 b);
double v2dot(struct vec2 a, struct vec2 b);
struct vec3 v3cross(struct vec3 a, struct vec3 b);
struct vec3 v3scale(struct vec3 a, double k);
struct span span_from(const char *s);
struct span span_skip(struct span s, size_t k);
size_t span_count(struct span s, char c);
struct res parse(struct span s);
