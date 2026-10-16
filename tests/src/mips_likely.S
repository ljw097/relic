    .text
    .set noreorder
    .globl cnt
    .ent cnt
# int cnt(const char *s, int c): how many chars of s equal c
cnt:
    move  $v0, $zero
1:  lb    $t0, 0($a0)
    beqz  $t0, 2f
    nop
    bnel  $t0, $a1, 1b
    addiu $a0, $a0, 1          # only when taken (a char other than c): next char
    addiu $v0, $v0, 1          # the char is c: count it (the slot was annulled)
    b     1b
    addiu $a0, $a0, 1
2:  jr    $ra
    nop
    .end cnt
