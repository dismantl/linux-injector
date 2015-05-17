//=====================================================//
// Copyright (c) 2015, Dan Staples (https://disman.tl) //
//=====================================================//

#include <stdio.h>
#include <errno.h>
#include <string.h>

#define CHECK(A,M,...) \
  do { \
    if (!(A)) { \
      fprintf(stderr, \
	      "(%s:%d: error: %d [%s]) " M "\n", \
	      __FILE__, \
	      __LINE__, \
	      errno, \
	      errno == 0 ? "None" : strerror(errno), \
	      ##__VA_ARGS__); \
      errno = 0; \
      goto error; \
    } \
  } while(0)

#define dprintf(M,...) printf("[*] [%s] " M "\n", __FUNCTION__, ##__VA_ARGS__)