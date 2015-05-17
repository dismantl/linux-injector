;//=====================================================//
;// Copyright (c) 2015, Dan Staples (https://disman.tl) //
;//=====================================================//

use64
; syscall parameter regsiters: rdi, rsi, rdx, r10, r8, r9

SYS_WRITE	= 0x01
SYS_EXIT	= 0x3c

start:
  jmp		mystring_addr
@@:
  xor		rax,rax
  mov		al,SYS_WRITE
  mov		rdi,rax
  pop		rsi
  xor		rdx,rdx
  mov		dl,mystring_len
  syscall
  ret
  
  ; NOTE: when running the `print` program, comment out the `ret` above, and uncomment the exit instructions below
;   xor		rax,rax
;   mov		al,SYS_EXIT
;   xor		rdi,rdi
;   syscall

mystring_addr:
  call @b
mystring: db "hello from shellcode land!",0xa
mystring_len = $-mystring