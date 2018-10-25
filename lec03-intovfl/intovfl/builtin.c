#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <err.h>

void *
calloc (size_t x, size_t y) {
  size_t sz;
  if (__builtin_mul_overflow (x, y, &sz))
    return NULL;
  void *ret = malloc (sz);
  if (ret) memset (ret, 0, sz);
  return ret;
}

int main(int argc, char *argv[]) {
  calloc(argc, argc);
  return 0;
}