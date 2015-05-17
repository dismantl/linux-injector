;//=====================================================//
;// Copyright (c) 2015, Dan Staples (https://disman.tl) //
;//=====================================================//

use64
; function paramater registers: RDI, RSI, RDX, RCX, R8, R9
; syscall parameter regsiters: rdi, rsi, rdx, r10, r8, r9

SYS_CLONE	= 0x38				; syscall 56: clone
SYS_MUNMAP	= 0x0b				; syscall 11: munmap
SYS_EXIT	= 0x3c				; syscall 60: exit

; initial values in registers:
; RAX: size of memory mmap'd for this shellcode
; RDI: clone flags
; RSI: stack address
; RDX: stack size
; RCX: payload address
; R8 : size of memory mmap's for payload
; R9 : payload parameter

start:
  mov		rsp,rsi			; start using new stack
  push		rax			; shellcode size
  call		@f
@@:
  sub		qword[rsp],@b-start	; shellcode addr
  push		rdx			; stack size
  push		rsi			; stack addr
  push		r8			; payload size
  push		rcx			; payload addr
  push		rcx			; payload addr
  push		r9			; payload param
  mov		rsi,rsp			; update stack pointer for clone
clone:
  ; long clone(unsigned long flags, void *child_stack, void *ptid, void *ctid, struct pt_regs *regs);
  ; flags and stack address are already in proper registers (rdi,rsi)
  xor 		rax,rax
  mov		al,SYS_CLONE
  xor		rdx,rdx			; ptid
  xor		r10,r10			; ctid
  xor		r8,r8			; regs
  syscall
  test		rax,rax
  je		child
  int		0x3			; interrupt to be trapped by parent
child:
  pop		rdi			; payload parameter
  pop		rax			; payload address
  call		rax			; call payload
cleanup:
  xor		rax,rax
  mov		al,SYS_MUNMAP
  xor		rdx,rdx			; what we'll use for our counter register for the loop, since RCX seems to get clobbered during syscall
  mov		dl,3			; munmap each of: payload, stack, shellcode
munmap:
  pop		rdi			; allocated memory address
  pop		rsi			; size of allocation
  syscall
  dec		dl
  jnz		munmap
exit:
  xor		rax,rax
  mov		al,SYS_EXIT
  xor		rdi,rdi			; exit code 0
  syscall