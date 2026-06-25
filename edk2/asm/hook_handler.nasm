BITS 64
DEFAULT REL

MAGIC EQU 0x12E7A12D
RUNTIME_CPP_HANDLER EQU 0x78

start:
    push    r12
    push    r13
    sub     rsp, 0x28

    mov     r12, r9               ; cmd_t*
    test    r12, r12
    jz      .invalid

    cmp     qword [r12 + 0x20], MAGIC
    jne     .invalid

    ; Load runtime data pointer (patched into shellcode)
    mov     r10, 0xDEADBEEFDEADBEEF
runtime_ptr_slot EQU $ - 8

    test    r10, r10
    jz      .invalid

    mov     rcx, r12              ; arg1 = cmd_t*
    mov     rdx, r10              ; arg2 = runtime_t*

    mov     r11, [r10 + RUNTIME_CPP_HANDLER]
    test    r11, r11
    jz      .invalid

    call    r11

    add     rsp, 0x28
    pop     r13
    pop     r12
    ret

.invalid:
    mov     eax, 0xC000000D
    add     rsp, 0x28
    pop     r13
    pop     r12
    ret
