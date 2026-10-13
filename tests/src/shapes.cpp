// C++ sample: namespaces, classes, overloads and a template, for demangling.
#include <cstdio>

namespace geo {
struct Rect {
    int w, h;
    int area() const { return w * h; }
    void scale(int k) { w *= k; h *= k; }
};

__attribute__((noinline)) int total(const Rect *r, int n) {
    int s = 0;
    for (int i = 0; i < n; i++)
        s += r[i].area();
    return s;
}
}  // namespace geo

__attribute__((noinline)) int twice(int x) { return 2 * x; }
__attribute__((noinline)) double twice(double x) { return 2 * x; }

template <typename T> __attribute__((noinline)) T biggest(T a, T b) { return a > b ? a : b; }

int main(int argc, char **) {
    geo::Rect rs[2] = {{2, 3}, {argc, 4}};
    rs[1].scale(2);
    std::printf("%d %d %d\n", geo::total(rs, 2), twice(argc), biggest(argc, 3));
    return (int)twice(1.5);
}
