//=====================================================//
// Copyright (c) 2015, Dan Staples (https://disman.tl) //
//=====================================================//

#include <sys/user.h>

int ptrace_attach(int pid);
int ptrace_detach(int pid);
int ptrace_getregs(int pid, struct user_regs_struct *regs);
int ptrace_setregs(int pid, struct user_regs_struct *regs);
int ptrace_continue(int pid, void *stop_addr);
int ptrace_next_syscall(int pid);
int ptrace_readmem(int pid, void *addr, unsigned char *buf, size_t len);
int ptrace_writemem(int pid, void *addr, unsigned char *buf, size_t len);

int wait_stopped(int pid);