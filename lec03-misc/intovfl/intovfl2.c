#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <err.h>

int main(int argc, char *argv[]) {
  int a = 0x7fffffff;
  printf("0x%08x ->\n", a);

  printf("  (unsigned int)(unsigned char): %x\n", (unsigned int)(unsigned char)a);
  printf("  (unsigned int)(char)         : %x\n", (unsigned int)(char)a);
  return a;
}