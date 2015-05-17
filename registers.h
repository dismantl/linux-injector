#ifndef __INJECTOR_REGISTERS_H__
#define __INJECTOR_REGISTERS_H__

#ifdef __i386__

#define EIP(R) (R)->eip
#define EAX(R) (R)->eax
#define USER_EAX offsetof(struct user, regs.eax)
#define ADDR2INT(R) (long)(R)

#elif defined(__x86_64__)

#define EIP(R) (R)->rip
#define EAX(R) (R)->rax
#define USER_EAX offsetof(struct user, regs.rax)
#define ADDR2INT(R) (unsigned long long)(R)

#else
#error Unsupported architecture
#endif

#endif