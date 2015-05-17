;//=====================================================//
;// Copyright (c) 2015, Dan Staples (https://disman.tl) //
;//=====================================================//

use32
; syscall parameter regsiters: ebx,ecx,edx,esi,edi,ebp

SYS_CLONE	= 0x78				; syscall 120: clone
SYS_MUNMAP	= 0x5b				; syscall  91: munmap
SYS_EXIT	= 0x01				; syscall   1: exit

; initial values in registers:
; EAX: size of memory mmap'd for this shellcode
; EBX: clone flags
; ECX: stack address
; EDX: stack size
; ESI: payload address
; EDI: size of memory mmap's for payload
; EBP: payload parameter

start:
  mov		esp,ecx			; start using new stack
  push		eax			; shellcode size
  call		@f
@@:
  sub		dword[esp],@b-start	; shellcode addr
  push		edx			; stack size
  push		ecx			; stack addr
  push		edi			; payload size
  push		esi			; payload addr
  push		ebp			; payload param
  push		esi			; payload addr
  mov		ecx,esp			; update stack pointer for clone
clone:
  ; long clone(unsigned long flags, void *child_stack, void *ptid, void *ctid, struct pt_regs *regs);
  ; flags and stack address are already in proper registers (ebx,ecx)
  xor 		eax,eax
  mov		al,SYS_CLONE
  xor		edx,edx			; ptid
  xor		esi,esi			; ctid
  xor		edi,edi			; regs
  int		0x80			; syscall
  test		eax,eax
  je		child
  int		0x3			; interrupt to be trapped by parent
child:
  pop		eax			; payload address
  call		eax			; call payload (parameter will be on stack below return address, which we'll clean up a la cdecl)
  add		esp,4			; clean payload parameter from stack
cleanup:
  xor		eax,eax
  mov		al,SYS_MUNMAP		; int munmap(void *addr, size_t length);
  xor		edx,edx			; our counter register for the loop, since ECX is used for the syscall
  mov		dl,3			; munmap each of: payload, stack, shellcode
munmap:
  pop		ebx			; allocated memory address
  pop		ecx			; size of allocation
  int		0x80			; syscall
  dec		dl
  jnz		munmap
exit:
  xor		eax,eax
  mov		al,SYS_EXIT
  xor		ebx,ebx			; exit code 0
  int		0x80			; syscall