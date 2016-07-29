//=====================================================//
// Copyright (c) 2015, Dan Staples (https://disman.tl) //
//=====================================================//

#include "inject.h"
#include "registers.h"
#include "ptrace.h"
#include "debug.h"
#include <string.h>
#include <malloc.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <stdio.h>

struct pstate {
  struct user_regs_struct regs;
  size_t mem_len;
  unsigned char mem[1];
};

static struct pstate *target_state = NULL;

static int
_save_state(int pid)
{
  if (!target_state) {
    CHECK((target_state = calloc(1, sizeof(struct pstate) + MAX_CODE_SIZE - 1)),
	  "Memory allocation error");
    target_state->mem_len = MAX_CODE_SIZE;
  }
  CHECK(ptrace_getregs(pid, &target_state->regs),
	"Failed to get registers of target process");
  dprintf("Saved registers");
  CHECK(ptrace_readmem(pid, (void*)EIP(&target_state->regs), target_state->mem, target_state->mem_len),
	"Failed to read %ld bytes of memory at target process instruction pointer",
	target_state->mem_len);
  dprintf("Saved %ld bytes from EIP %p", target_state->mem_len, target_state->mem);
  return 1;
error:
  return 0;
}

static int
_restore_state(int pid)
{
  if (!target_state) return 1;
  CHECK(ptrace_setregs(pid, &target_state->regs),
	"Failed to set registers of target process");
  dprintf("Restored registers");
  CHECK(ptrace_writemem(pid, (void*)EIP(&target_state->regs), target_state->mem, target_state->mem_len),
	"Failed to write %ld bytes of memory to target process instruction pointer",
	target_state->mem_len);
  dprintf("Restored %ld bytes to EIP %p", target_state->mem_len, target_state->mem);
  free(target_state);
  target_state = NULL;
  return 1;
error:
  return 0;
}

static int
_wait_trap(int pid)
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
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
      return 1;
  }
error:
  return 0;
}

static int
_mmap_data(int pid, size_t len, void *base_address, int protections, int flags, void **out)
{
  int ret = 0;
  unsigned char *shellcode = NULL;
  
  FILE *f = fopen(MMAP_ASM, "rb");
  CHECK(f, "Error opening " MMAP_ASM);
  CHECK(fseek(f, 0, SEEK_END) == 0, "fseek error");
  long shellcode_len = ftell(f);
  CHECK(shellcode_len > 0, "ftell error");
  // align shellcode size to 32/64-bit boundary
  long shellcode_len_aligned = shellcode_len;
  if (shellcode_len % sizeof(void*) != 0) {
    shellcode_len_aligned += sizeof(void*) - shellcode_len % sizeof(void*);
  }
  CHECK(fseek(f, 0, SEEK_SET) == 0, "fseek error");
  shellcode = malloc(shellcode_len_aligned);
  memset(shellcode, 0x90, shellcode_len_aligned); // fill with NOPs
  CHECK(shellcode, "malloc error");
  size_t r = fread(shellcode, 1, shellcode_len, f);
  CHECK(r == (size_t)shellcode_len, "fread error: %ld %ld", r, shellcode_len);
  fclose(f);
  
  // get current registers
  struct user_regs_struct orig_regs, regs = {0};
  CHECK(ptrace_getregs(pid, &regs),
	"Failed to get registers of target process");
  orig_regs = regs;
  
  // put our arguments in the proper registers (see mmap{64,32}.asm)
#ifdef __i386__
  regs.ebx = (long)base_address;
  regs.ecx = (long)len;
  regs.edx = (long)((protections) ? protections : MMAP_PROTS);
  regs.esi = (long)((flags) ? flags : MMAP_FLAGS);
#elif defined(__x86_64__)
  regs.rdi = (unsigned long long)base_address;
  regs.rsi = (unsigned long long)len;
  regs.rdx = (unsigned long long)((protections) ? protections : MMAP_PROTS);
  regs.r10 = (unsigned long long)((flags) ? flags : MMAP_FLAGS);
#endif
  CHECK(ptrace_setregs(pid, &regs),
	"Failed to set registers of target process");
  dprintf("Wrote our shellcode parameters into process registers");
  
  // write mmap code to target process EIP
  CHECK(ptrace_writemem(pid, (void*)EIP(&regs), shellcode, shellcode_len_aligned),
	"Failed to write mmap code to target process");
  dprintf("Wrote mmap code to EIP %p", (void*)EIP(&regs));
  
  // run mmap code and check return value
  CHECK(ptrace_continue(pid, 0), "Failed to execute mmap code");
  CHECK(_wait_trap(pid), "Error waiting for interrupt");
  dprintf("Mmap() finished execution");
  
  // get return value from mmap()
  CHECK(ptrace_getregs(pid, &regs),
	"Failed to get registers of target process");
  *out = (void*)EAX(&regs);
  dprintf("Mmap() returned %p", *out);
  CHECK(*out != MAP_FAILED, "Mmap() returned error");
  
  // restore registers
  CHECK(ptrace_setregs(pid, &orig_regs),
	"Failed to restore registers of target process");
  dprintf("Restored registers of target process");
  
  ret = 1;
error:
  if (shellcode)
    free(shellcode);
  return ret;
}

static int
_launch_payload(int pid, void *code_cave, size_t code_cave_size, void *stack_address, size_t stack_size, void *payload_address, size_t payload_len, void *payload_param, int flags)
{
  int ret = 0;
  unsigned char *shellcode = NULL;
  FILE *f = fopen(CLONE_ASM, "rb");
  CHECK(f, "Error opening " CLONE_ASM);
  CHECK(fseek(f, 0, SEEK_END) == 0, "fseek error");
  long shellcode_len = ftell(f);
  CHECK(shellcode_len > 0, "ftell error");
  CHECK(shellcode_len <= code_cave_size, "Shellcode is too big (%ld) for allocated code cave", shellcode_len);
  CHECK(fseek(f, 0, SEEK_SET) == 0, "fseek error");
  shellcode = malloc(code_cave_size);
  CHECK(shellcode, "malloc error");
  memset(shellcode, 0x90, code_cave_size); // fill with NOPs
  size_t r = fread(shellcode, 1, shellcode_len, f);
  CHECK(r == (size_t)shellcode_len, "fread error: %ld %ld", r, shellcode_len);
  fclose(f);
  
  // get current registers
  struct user_regs_struct regs = {0};
  CHECK(ptrace_getregs(pid, &regs),
	"Failed to get registers of target process");
  
  // put our arguments in the proper registers (see clone{64,32}.asm)
#ifdef __i386__
  regs.eax = (long)code_cave_size;
  regs.ebx = (long)((flags) ? flags : CLONE_FLAGS);
  regs.ecx = (long)stack_address;
  regs.edx = (long)stack_size;
  regs.esi = (long)payload_address;
  regs.edi = (long)payload_len;
  regs.ebp = (long)payload_param;
#elif defined(__x86_64__)
  regs.rax = (unsigned long long)code_cave_size;
  regs.rdi = (unsigned long long)((flags) ? flags : CLONE_FLAGS);
  regs.rsi = (unsigned long long)stack_address;
  regs.rdx = (unsigned long long)stack_size;
  regs.rcx = (unsigned long long)payload_address;
  regs.r8  = (unsigned long long)payload_len;
  regs.r9  = (unsigned long long)payload_param;
#endif
  // move EIP to our code cave
  EIP(&regs) = ADDR2INT(code_cave);
  CHECK(ptrace_setregs(pid, &regs),
	"Failed to set registers of target process");
  dprintf("Wrote our shellcode parameters into process registers. EIP: %p", code_cave);
  
  // write shellcode to target process code cave
  CHECK(ptrace_writemem(pid, code_cave, shellcode, code_cave_size),
	"Failed to write clone trampoline code to target process");
  dprintf("Wrote clone trampoline code to address %p", code_cave);
  
  // run shellcode and check return value
  CHECK(ptrace_continue(pid, code_cave), "Failed to execute clone trampoline code");
  CHECK(_wait_trap(pid), "Error waiting for interrupt");
  dprintf("Clone() finished execution");
  CHECK(ptrace_getregs(pid, &regs),
	"Failed to get registers of target process");
  dprintf("New thread ID: %lld", EAX(&regs));
  CHECK((int)EAX(&regs) != -1, "Clone() returned error");
  
  // no need to restore registers, as we're about to call _restore_state()
  
  dprintf("Successfully launched payload");
  
  ret = 1;
error:
  if (ret == 0)
    dprintf("Failed to launch payload");
  if (shellcode)
    free(shellcode);
  return ret;
}

int
inject_code(int pid, unsigned char *payload, size_t payload_len)
{
  int ret = 0;
  void *payload_addr = NULL,
       *stack = NULL,
       *code_cave = NULL,
       *payload_aligned = NULL;
  size_t payload_size;
  
  // align shellcode size to 32/64-bit boundary
  payload_size = payload_len + (sizeof(void*) - (payload_len % sizeof(void*)));
  payload_aligned = malloc(payload_size);
  CHECK(payload_aligned, "malloc() error");
  memset(payload_aligned, 0x90, payload_size); // fill with NOPs
  memcpy(payload_aligned, payload, payload_len);
  
  printf("Injecting into target process %d\n", pid);
  
  // attach to process
  CHECK(ptrace_attach(pid), "Error attaching to target process %d", pid);
  dprintf("Attached to process");
  
  // wait to make sure process is in ptrace-stop state before continuing, 
  // otherwise we may inadvertently kill the process
  CHECK(wait_stopped(pid), "Failed to wait until target process in stopped state");
  dprintf("Process is in stopped state");
  
  // Wait until process has just returned from a system call before proceeding
  CHECK(ptrace_next_syscall(pid), "Failed to wait until after next syscall");
  dprintf("Process exited from syscall");
  
  // save state
  CHECK(_save_state(pid), "Failed to state target process state");
  dprintf("Saved state of target process");
  
  // allocate payload space
  CHECK(_mmap_data(pid, payload_size, NULL, 0, 0, &payload_addr),
	"Failed to allocate space for payload");
  dprintf("Allocated space for payload at location %p", payload_addr);

  // copy payload
  CHECK(ptrace_writemem(pid, payload_addr, payload_aligned, payload_size),
	"Failed to copy payload to target process");
  dprintf("Wrote payload to target process at address %p", payload_addr);
  
  // allocate new stack
  CHECK(_mmap_data(pid, STACK_SIZE, NULL, 0, 0, &stack),
	"Failed to allocate space for new stack");
  stack += STACK_SIZE; // use top address as stack base, since stack grows downward
  dprintf("Allocated new stack at location %p", stack);
  
  // allocate space for code cave
  CHECK(_mmap_data(pid, MAX_CODE_SIZE, NULL, 0, 0, &code_cave),
	"Failed to allocate space for code cave");
  dprintf("Allocated space for code cave at location %p", code_cave);
  
  // launch payload via clone(2)
  dprintf("Launching payload in new thread");
  CHECK(_launch_payload(pid, code_cave, MAX_CODE_SIZE, stack, STACK_SIZE, payload_addr, payload_size, NULL, 0),
	"Failed to launch payload");
  
  ret = 1;
error:
  if (payload_aligned)
    free(payload_aligned);
  _restore_state(pid);
  ptrace_detach(pid);
  return ret;
}