#include "inject.h"
#include "debug.h"
#include <stdio.h>
#include <stdlib.h>

static void
_print_usage(void)
{
  printf("Usage: injector <target PID> <payload file>\n");
}

int
main(int argc, char *argv[])
{
  if (argc != 3) {
    _print_usage();
    return 1;
  }
  
  int pid = atoi(argv[1]);
  
  FILE *f = fopen(argv[2], "rb");
  CHECK(f, "Error opening file %s", argv[2]);
  CHECK(fseek(f, 0, SEEK_END) == 0, "fseek error");
  long fsize = ftell(f);
  CHECK(fsize > 0, "ftell error");
  CHECK(fseek(f, 0, SEEK_SET) == 0, "fseek error");
  unsigned char *payload = malloc(fsize);
  CHECK(payload, "malloc error");
  size_t r = fread(payload, 1, fsize, f);
  CHECK(r == (size_t)fsize, "fread error: %ld %ld", r, fsize);
  fclose(f);
  
  CHECK(inject_code(pid, payload, fsize), "Failed to inject code into target process %d", pid);
  
  printf("Code injection successful\n\n");
  
  return 0;
error:
  return 1;
}