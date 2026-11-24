/* GNU C computed goto, an interpreter loop like Lua's (tests/test_cgoto.py): the labels in its
 * dispatch table are not functions. */
#include <stdio.h>
#define F __attribute__((noinline))
F long run(const unsigned char *code, long acc)
{
    static void *const disptab[] = { &&op_halt, &&op_inc, &&op_dbl, &&op_neg, &&op_sub3, &&op_sq, &&op_jmp0, &&op_nop };
    const unsigned char *pc = code;
#define NEXT goto *disptab[*pc++ & 7]
    NEXT;
op_inc:  acc++; NEXT;
op_dbl:  acc *= 2; NEXT;
op_neg:  acc = -acc; NEXT;
op_sub3: acc -= 3; NEXT;
op_sq:   acc *= acc; NEXT;
op_jmp0: if (acc == 0) pc = code; NEXT;
op_nop:  NEXT;
op_halt: return acc;
}
F long twice(long x) { return run((const unsigned char *)"\2\0", x); }
int main(int argc, char **argv) { (void)argv; printf("%ld\n", run((const unsigned char *)"\1\2\3\4\5\7\0", argc) + twice(argc)); return 0; }
