;//=====================================================//
;// Copyright (c) 2015, Dan Staples (https://disman.tl) //
;//=====================================================//

use32
; syscall parameter regsiters: ebx,ecx,edx,esi,edi,ebp

SYS_WRITE	= 0x04
SYS_EXIT	= 0x01

start:
  xor		eax,eax
  mov		al,SYS_WRITE
  xor		ebx,ebx
  mov		bl,1			; fd = 1
  jmp		mystring_addr
@@:
  pop		ecx			; string address
  xor		edx,edx
  mov		dl,mystring_len		; strlen(mystring)
  int		0x80
  ret
  
  ; NOTE: when running the `print` program, comment out the `ret` above, and uncomment the exit instructions below
;   xor		eax,eax
;   mov		al,SYS_EXIT
;   xor		ebx,ebx
;   int		0x80

mystring_addr:
  call @b
mystring: db "hello from shellcode land!",0xa
mystring_len = $-mystring
