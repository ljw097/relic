// Control-flow sample for the decompiler: pure functions (no libc), so the
// decompiled pseudocode can be compiled again and compared with this source.
#define F __attribute__((noinline))

F int sc_or(int a, int b) {
    if (a > 3 || b < 2)
        return a * b;
    return a - b;
}

F int sc_and3(int a, int b, int c) {
    if (a && b > 1 && c != 7)
        return a + b + c;
    return 2;
}

F int find(const int *v, int n, int key) {
    for (int i = 0; i < n; i++)
        if (v[i] == key)
            return i;
    return -1;
}

F int collatz(unsigned n) {
    int steps = 0;
    while (n > 1) {
        if (n & 1)
            n = 3 * n + 1;
        else
            n >>= 1;
        if (++steps > 500)
            break;
    }
    return steps;
}

F int nested(int x, int y) {
    int r = 0;
    for (int i = 0; i < x; i++) {
        for (int j = 0; j < y; j++) {
            if ((i * j) % 7 == 3)
                continue;
            if (i + j > 20)
                goto out;
            r += i ^ j;
        }
    }
out:
    return r;
}

F int sw_fall(int x) {
    int r = 0;
    switch (x) {
    case 0: r += 1; /* fall through */
    case 1: r += 2; break;
    case 2:
    case 3: r = 5; break;
    case 4: r = x * 3; break;
    case 7: return 9;
    default: r = -1;
    }
    return r + 1;
}

F int dowhile(int n) {
    int s = 0;
    do {
        s += n;
        n -= 3;
    } while (n > 0);
    return s;
}

F int clamp(int v, int lo, int hi) {
    return v < lo ? lo : v > hi ? hi : v;
}

F int gcd(int a, int b) {
    while (b) {
        int t = a % b;
        a = b;
        b = t;
    }
    return a;
}

F int classify2(int a, int b) {
    if (a < 0) {
        if (b < 0)
            return 1;
        return 2;
    } else if (a == 0 || b == 0) {
        return 3;
    } else if (a > 100 && b > 100) {
        return 4;
    }
    return a > b ? 5 : 6;
}

F int scan(const char *s) {
    int words = 0, in = 0;
    for (; *s; s++) {
        if (*s == ' ' || *s == '\t') {
            in = 0;
        } else if (!in) {
            in = 1;
            words++;
        }
    }
    return words;
}

int main(void) { return 0; }
