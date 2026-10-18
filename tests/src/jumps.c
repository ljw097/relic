/* Indirect jumps auto-analysis must resolve: a switch over negative cases (indexed by `x + 5`,
   bounded by `cmp x, -5; jb`), switches inside a loop whose table base gcc loads once ahead of
   it, and a tail call through a function pointer after the frame is torn down. */
#define NI __attribute__((noinline))
int printf(const char *, ...);

NI int neg(int x)
{
    switch (x) {
    case -5: return printf("a");
    case -4: return printf("bb");
    case -3: return printf("ccc") + 1;
    case -2: return printf("dddd") * 2;
    case -1: return printf("e") - 7;
    default: return 0;
    }
}

NI int loop(const char *s, int *out)
{
    int a = 0, b = 0, c = 0, d = 0, e = 0, f = 0;
    for (; *s; s++) {
        switch (*s) {
        case 'a': a += out[0]; break;
        case 'b': b ^= out[1]; break;
        case 'c': c -= out[2]; break;
        case 'd': d = d * 3 + out[3]; break;
        case 'e': e |= out[4]; break;
        case 'f': f += 2; break;
        case 'g': a = b; break;
        default: out[5]++;
        }
        switch (*s & 7) {
        case 0: out[0] += a; break;
        case 1: out[1] += b; break;
        case 2: out[2] -= c; break;
        case 3: out[3] ^= d; break;
        case 4: out[4] += e; break;
        case 5: out[5] += f; break;
        default: break;
        }
    }
    return a + b + c + d + e + f;
}

struct ops { int (*fn)(int); int k; };

NI int via(struct ops *o, int x, int y, int z)
{
    int t = printf("%d %d", x, y) + z;
    return o->fn(t + o->k);
}

int main(int argc, char **argv)
{
    int out[6] = {1, 2, 3, 4, 5, 6};
    struct ops o = {neg, -3};
    return loop(argv[0], out) + via(&o, argc, 2, 3);
}
