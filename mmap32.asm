use32
; syscall parameter regsiters: ebx,ecx,edx,esi,edi,ebp

SYS_MMAP	= 0xc0				; syscall 192: mmap

; initial values in registers:
; EBX: requested base address (0 for anonymous mappings)
; ECX: size of mapping
; EDX: protections bitmask
; ESI: flags bitmask

xor		eax,eax
mov		al,SYS_MMAP
; syscall parameters already in proper registers
xor		edi,edi		; fd
xor		ebp,ebp		; offset
int		0x80		; syscall
int		0x3		; interrupt for caller to trap