#include "ptrace.h"
#include "debug.h"
#include "registers.h"
#include <sys/user.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

int
ptrace_attach(int pid)
{
  CHECK(ptrace(PTRACE_ATTACH, (pid_t)pid, NULL, NULL) == 0,
	"Failed to attach to target process %d", pid);
  return 1;
error:
  return 0;
}

int
ptrace_detach(int pid)
{
  CHECK(ptrace(PTRACE_DETACH, (pid_t)pid, NULL, NULL) == 0,
	"Failed to detach to target process %d", pid);
  return 1;
error:
  return 0;
}

int
ptrace_getregs(int pid, struct user_regs_struct *regs)
{
  CHECK(ptrace(PTRACE_GETREGS, (pid_t)pid, NULL, regs) == 0,
	"Failed to get registers of target process %d", pid);
  return 1;
error:
  return 0;
}

int
ptrace_setregs(int pid, struct user_regs_struct *regs)
{
  CHECK(ptrace(PTRACE_SETREGS, (pid_t)pid, NULL, regs) == 0,
	"Failed to set registers of target process %d", pid);
  return 1;
error:
  return 0;
}

static int
_askstep(void)
{
  char ans[10] = {0};
  printf("Single step or wait until target address?[Y/n/w]: ");
  fgets(ans, 9, stdin);
  if (ans[0] == 'n' || ans[0] == 'N') {
    dprintf("Continuing...");
    return 0;
  } else if (ans[0] == 'w' || ans[0] == 'W') {
    dprintf("Waiting until we reach stop address...");
    return 2;
  } else {
    dprintf("Stepping...");
    return 1;
  }
}

int
wait_stopped(int pid)
{
  int status = 0;
  while(1) {
    CHECK(waitpid(pid, &status, 0) != -1,
	  "waitpid error");
    
    if (WIFSTOPPED(status)) {
      dprintf("Process stopped with signal %d", WSTOPSIG(status));
    }
    if (WIFEXITED(status)) {
      dprintf("Process exited with signal %d", WEXITSTATUS(status));
    }
    if (WIFSIGNALED(status)) {
      dprintf("Process terminated with signal %d", WTERMSIG(status));
      if (WCOREDUMP(status))
	dprintf("Process core dumped");
    }
    if (WIFCONTINUED(status)) {
      dprintf("Process was resumed by delivery of SIGCONT");
    }
    
    CHECK(!WIFEXITED(status), "Target process has exited");
    if (WIFSTOPPED(status))
      break;
  }
  return 1;
error:
  return 0;
}

int
ptrace_next_syscall(int pid)
{
  struct user_regs_struct regs = {0};
  long eax;
  do {
    CHECK(ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == 0,
	  "Failed to continue execution until next syscall enter/exit");
    CHECK(wait_stopped(pid), "Failed to wait until target process in stopped state");
    errno = 0;
    eax = ptrace(PTRACE_PEEKUSER, pid, USER_EAX, NULL);
    CHECK(errno == 0, "Failed to read EAX of target process");
    dprintf("EAX after syscall: %ld", eax);
  } while (eax == -ENOSYS); // RAX/EAX == -ENOSYS means just entered a syscall, != -ENOSYS means just exited syscall (offsetof(struct user, regs.orig_eax) can be used to see syscall number if you want)
  return 1;
error:
  return 0;
}

int
ptrace_continue(int pid, void *stop_addr)
{
#ifndef DEBUG
    dprintf("Continuing execution of target process %d", pid);
    CHECK(ptrace(PTRACE_CONT, (pid_t)pid, NULL, NULL) == 0,
	  "Failed to continue execution of target process %d", pid);
#else
    dprintf("Stepping execution of target process %d", pid);
    if (stop_addr)
      dprintf("Stop address: %p", stop_addr);
    int choice = _askstep();
    if (choice == 0) {
      dprintf("Continuing execution of target process %d", pid);
      CHECK(ptrace(PTRACE_CONT, (pid_t)pid, NULL, NULL) == 0,
	    "Failed to continue execution of target process %d", pid);
      return 1;
    }
    while(1) {
      struct user_regs_struct regs = {0};
      CHECK(ptrace_getregs(pid, &regs), "ptrace_getregs() error");
#ifdef __i386__
      unsigned char eip[8] = {0};
      CHECK(ptrace_readmem(pid, (void*)regs.eip, (void*)eip, sizeof(eip)),
	    "Failed to read 8 bytes at EIP 0x%lx", regs.eip);
      if (choice != 2 || (void*)regs.eip == stop_addr) {
	printf("eax     0x%lx\n" \
	"ebx     0x%lx\n" \
	"ecx     0x%lx\n" \
	"edx     0x%lx\n" \
	"esi     0x%lx\n" \
	"edi     0x%lx\n" \
	"ebp     0x%lx\n" \
	"eip     0x%lx\n" \
	"0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x\n",
	regs.eax,
	regs.ebx,
	regs.ecx,
	regs.edx,
	regs.esi,
	regs.edi,
	regs.ebp,
	regs.eip,
	eip[0],
	eip[1],
	eip[2],
	eip[3],
	eip[4],
	eip[5],
	eip[6],
	eip[7]);
	choice = _askstep();
      }
#elif defined(__x86_64__)
      unsigned char rip[16] = {0};
      CHECK(ptrace_readmem(pid, (void*)regs.rip, (void*)rip, sizeof(rip)),
	    "Failed to read 16 bytes at RIP 0x%llx", regs.rip);
      if (choice != 2 || (void*)regs.rip == stop_addr) {
	printf("rax     0x%llx\n" \
	      "rdi     0x%llx\n" \
	      "rsi     0x%llx\n" \
	      "rdx     0x%llx\n" \
	      "r10     0x%llx\n" \
	      "r8      0x%llx\n" \
	      "r9      0x%llx\n" \
	      "rbx     0x%llx\n" \
	      "rip     0x%llx\n" \
	      "0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x\n" \
	      "0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x\n",
	      regs.rax,
	      regs.rdi,
	      regs.rsi,
	      regs.rdx,
	      regs.r10,
	      regs.r8,
	      regs.r9,
	      regs.rbx,
	      regs.rip,
	      rip[0],
	      rip[1],
	      rip[2],
	      rip[3],
	      rip[4],
	      rip[5],
	      rip[6],
	      rip[7],
	      rip[8],
	      rip[9],
	      rip[10],
	      rip[11],
	      rip[12],
	      rip[13],
	      rip[14],
	      rip[15]);
	choice = _askstep();
      }
#endif
      CHECK(ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == 0,
	    "Failed to step execution");
      int status = 0;
      CHECK(waitpid(pid, &status, 0) != -1,
	    "waitpid error");
      if (choice == 0) {
	dprintf("Continuing execution of target process %d", pid);
	CHECK(ptrace(PTRACE_CONT, (pid_t)pid, NULL, NULL) == 0,
	      "Failed to continue execution of target process %d", pid);
	return 1;
      }
    }
#endif
  return 1;
error:
  return 1;
}

int
ptrace_readmem(int pid, void *addr, unsigned char *buf, size_t len)
{
  CHECK(len % sizeof(void*) == 0, "Length of memory to read must be word-aligned");
  
  size_t wordlen = len / sizeof(void*);
  void **wordbuf = (void**)buf;
  
  errno = 0;
  for (size_t i = 0; i < wordlen; i++) {
    wordbuf[i] = (void*)ptrace(PTRACE_PEEKDATA, (pid_t)pid, addr + (i * sizeof(void*)), NULL);
    CHECK(errno == 0, 
	  "Failed to read memory of target process %d at location %p", 
	  pid, 
	  addr + (i * sizeof(void*)));
  }
  return 1;
error:
  return 0;
}

int
ptrace_writemem(int pid, void *addr, unsigned char *buf, size_t len)
{
  int ret = 0;
  size_t wordlen = len / sizeof(void*) + (len % sizeof(void*) > 0 ? 1 : 0);
//   void **wordbuf = (void**)buf;
  void **wordbuf = calloc(sizeof(void*),wordlen);
  memcpy(wordbuf,buf,len);
  
  for (size_t i = 0; i < wordlen; i++) {
    long result = ptrace(PTRACE_POKEDATA, (pid_t)pid, addr + (i * sizeof(void*)), wordbuf[i]);
    CHECK(result == 0, 
	  "Failed to write memory to target process %d at location %p", 
	  pid, 
	  addr + (i * sizeof(void*)));
  }
  ret = 1;
error:
  if (wordbuf)
    free(wordbuf);
  return ret;
}