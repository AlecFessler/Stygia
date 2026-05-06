/* Freestanding setjmp.h. The 8-slot jmp_buf holds rbx, rbp, r12, r13,
 * r14, r15, rsp, rip — enough to resume an x86-64 call. The matching
 * setjmp/longjmp routines live in libc_shim.zig as naked-asm functions. */
#ifndef _DESKTOPOS_DOOM_SETJMP_H
#define _DESKTOPOS_DOOM_SETJMP_H

typedef long jmp_buf[8];
typedef jmp_buf sigjmp_buf;

int  setjmp(jmp_buf env);
void longjmp(jmp_buf env, int val) __attribute__((noreturn));

int  sigsetjmp(sigjmp_buf env, int savesigs);
void siglongjmp(sigjmp_buf env, int val) __attribute__((noreturn));

#define _setjmp setjmp
#define _longjmp longjmp

#endif
