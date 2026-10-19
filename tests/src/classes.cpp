// C++ classes for RTTI recovery: single inheritance, multiple inheritance, an abstract base with a
// pure virtual method, a virtual destructor, a class nobody constructs outside its factory.
// (no headers: builds for other processors with only the C++ runtime library at hand)
extern "C" int printf(const char *, ...);
extern "C" int atoi(const char *);
namespace std { using ::printf; using ::atoi; }

struct Animal {
    virtual ~Animal() {}
    virtual const char *sound() const = 0;
    virtual int legs() const { return 4; }
    virtual void speak() const { std::printf("says %s\n", sound()); }    // (a virtual call through `this`)
};

struct Dog : Animal {
    const char *sound() const override { return "woof"; }
};

struct Bird : Animal {
    const char *sound() const override { return "tweet"; }
    int legs() const override { return 2; }
};

struct Named {
    virtual const char *name() const { return "?"; }
    virtual ~Named() {}
};

struct Parrot : Bird, Named {
    const char *sound() const override { return "hello"; }
    const char *name() const override { return "polly"; }
};

__attribute__((noinline)) Animal *make(int k)
{
    switch (k) {
    case 0: return new Dog;
    case 1: return new Bird;
    default: return new Parrot;
    }
}

__attribute__((noinline)) void show(const Animal *a)
{
    std::printf("%s %d\n", a->sound(), a->legs());
}

int main(int argc, char **argv)
{
    Animal *a = make(argc > 1 ? std::atoi(argv[1]) : 0);
    show(a);
    a->speak();
    if (const Named *n = dynamic_cast<const Named *>(a))
        std::printf("%s\n", n->name());
    delete a;
    return 0;
}
