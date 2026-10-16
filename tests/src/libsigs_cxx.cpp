#include <string>
#include <vector>
#include <stdexcept>
#include <cstdio>
#include <algorithm>
static std::string build(int n) { std::string s; for (int i = 0; i < n; i++) s += char('a' + i % 26); return s; }
int main(int argc, char **argv) {
    std::vector<std::string> v;
    for (int i = 1; i < argc; i++) v.push_back(argv[i]);
    std::sort(v.begin(), v.end());
    try {
        if (argc > 3) throw std::runtime_error("too many");
        std::string s = build(argc * 3);
        std::printf("%s %zu %s\n", s.c_str(), v.size(), s.substr(argc, 2).c_str());
    } catch (const std::exception &e) { std::printf("error: %s\n", e.what()); return 1; }
    return 0;
}
