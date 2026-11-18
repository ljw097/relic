/* structs whose integer fields share a register (tests/test_structval.py) */
struct pair { int a; int b; };
struct tri { int x; int y; int z; };
struct name { char s[8]; long n; };
struct pair swap(struct pair p);
long tsum(struct tri t);
long first(struct name n);
struct tri mk(int k);
