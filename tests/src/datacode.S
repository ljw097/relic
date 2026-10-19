/* Data among code (hand-written assembly): a string, a table of numbers, a table of function
   pointers between `main` and the functions only that table points at. */
    .intel_syntax noprefix
    .text
    .globl main
main:
    push rbx
    lea rdi, [rip + msg]
    call puts@PLT
    mov eax, dword ptr [rip + table + 4]
    lea rbx, [rip + table]
    add eax, dword ptr [rbx + 8]
    mov rcx, qword ptr [rip + fptrs]
    call rcx
    pop rbx
    ret
msg:
    .asciz "hello from text"
    .p2align 3
table:
    .long 1, 2, 3, 4, 0x55e58948, 0xc3
fptrs:
    .quad helper
    .quad helper2
    .p2align 4
helper:
    mov eax, 7
    ret
helper2:
    xor eax, eax
    ret
    .section .note.GNU-stack,"",@progbits
