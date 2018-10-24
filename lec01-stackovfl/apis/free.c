#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>

int main(int argc, char *argv[]) {
  printf("malloc(0) = %p\n", malloc(0));
  free(NULL);
  printf("free(NULL)\n");
  return 0;
}