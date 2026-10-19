/* the smallest program: where `main` is in a stripped binary (tests/test_autoanalysis.py) */
#include <stdio.h>

int main(int argc, char **argv) { puts(argv[0]); return argc * 7; }
