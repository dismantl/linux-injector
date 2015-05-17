;//=====================================================//
;// Copyright (c) 2015, Dan Staples (https://disman.tl) //
;//=====================================================//

use64
; function paramater registers: RDI, RSI, RDX, RCX, R8, R9
; syscall parameter regsiters: rdi, rsi, rdx, r10, r8, r9

SYS_MMAP	= 0x09				; syscall 09: mmap

; initial values in registers:
; RDI: requested base address (0 for anonymous mappings)
; RSI: size of mapping
; RDX: protections bitmask
; R10: flags bitmask

xor		rax,rax
mov		al,SYS_MMAP
; syscall parameters already in proper registers
xor		r8,r8		; fd
xor		r9,r9		; offset
syscall
int		0x3		; interrupt for caller to trap