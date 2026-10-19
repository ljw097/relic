// The classes of classes.cpp for MSVC's ABI (clang --target=*-windows-msvc, no CRT: a bump
// allocator, the entry point and the CRT symbols RTTI refers to are here).
struct Animal {
    virtual ~Animal() {}
    virtual const char *sound() const = 0;
    virtual int legs() const { return 4; }
    virtual int speak() const { return sound()[0]; }
};
struct Dog : Animal { const char *sound() const override { return "woof"; } };
struct Bird : Animal {
    const char *sound() const override { return "tweet"; }
    int legs() const override { return 2; }
};
struct Named { virtual const char *name() const { return "?"; } virtual ~Named() {} };
struct Parrot : Bird, Named {
    const char *sound() const override { return "hello"; }
    const char *name() const override { return "polly"; }
};
static char heap[4096]; static unsigned used;
void *operator new(__SIZE_TYPE__ n) { void *p = heap + used; used += (unsigned)((n + 15) & ~(__SIZE_TYPE__)15); return p; }
void operator delete(void *, __SIZE_TYPE__) {}
void operator delete(void *) {}
__declspec(noinline) Animal *make(int k) { if (k == 0) return new Dog; if (k == 1) return new Bird; return new Parrot; }
extern "C" int __cdecl _purecall() { return 0; }
extern "C" int mainCRTStartup() { Animal *a = make((int)(__SIZE_TYPE__)&used & 3); int r = a->speak() + a->legs(); delete a; return r; }
