    .section .text
#ifndef PORTAL_UID1000_HELPER_PATH
#define PORTAL_UID1000_HELPER_PATH "/data/portal-uid1000/portal-camera-led-watch"
#endif
    .balign 4
    .global portal_uid1000_boot_hook
    .type portal_uid1000_boot_hook, %function
portal_uid1000_boot_hook:
    // Preserve the managed quick ABI state before making raw syscalls.
    sub     sp, sp, #112
    stp     x0, x1, [sp, #0]
    stp     x2, x3, [sp, #16]
    stp     x4, x5, [sp, #32]
    stp     x6, x7, [sp, #48]
    stp     x8, x9, [sp, #64]
    stp     x10, x11, [sp, #80]
    str     x30, [sp, #96]
    mrs     x30, nzcv
    str     x30, [sp, #104]

    // clone(SIGCHLD, NULL, NULL, NULL, NULL)
    mov     x0, #17
    mov     x1, xzr
    mov     x2, xzr
    mov     x3, xzr
    mov     x4, xzr
    mov     x8, #220
    svc     #0
    cbz     x0, child

    ldr     x30, [sp, #104]
    msr     nzcv, x30
    ldr     x30, [sp, #96]
    ldp     x10, x11, [sp, #80]
    ldp     x8, x9, [sp, #64]
    ldp     x6, x7, [sp, #48]
    ldp     x4, x5, [sp, #32]
    ldp     x2, x3, [sp, #16]
    ldp     x0, x1, [sp, #0]
    add     sp, sp, #112

    // Re-run the displaced UID-1000 host method's first instruction.
    sub     x16, sp, #0x2000
    // The installer replaces this with a branch to onCreate + 4.
    .word   0x14000000

child:
    // execve(helper_path, { helper_path, NULL }, NULL)
    sub     sp, sp, #16
    adr     x0, helper_path
    str     x0, [sp]
    str     xzr, [sp, #8]
    mov     x1, sp
    mov     x2, xzr
    mov     x8, #221
    svc     #0

    // Exit the child if execve fails.
    mov     x0, #127
    mov     x8, #93
    svc     #0
    brk     #0

helper_path:
    .asciz  PORTAL_UID1000_HELPER_PATH
    .size portal_uid1000_boot_hook, .-portal_uid1000_boot_hook
