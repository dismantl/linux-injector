#include <string.h>
#include <sched.h>
#include <sys/mman.h>

#define MAX_CODE_SIZE		128
#define STACK_SIZE		0x1000
#define CLONE_FLAGS		CLONE_THREAD | CLONE_SIGHAND | CLONE_UNTRACED | CLONE_VM
#define MMAP_PROTS		PROT_READ | PROT_WRITE | PROT_EXEC
#define MMAP_FLAGS		MAP_PRIVATE | MAP_ANONYMOUS

#ifdef __i386__

#define MMAP_ASM "mmap32.bin"
#define CLONE_ASM "clone32.bin"

#elif defined(__x86_64__)

#define MMAP_ASM "mmap64.bin"
#define CLONE_ASM "clone64.bin"

#else
#error Unsupported architecture
#endif


int inject_code(int pid, unsigned char *payload, size_t len);