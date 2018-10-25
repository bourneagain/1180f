#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>

int main(int argc, char *argv[]) {
  int base;

  printf("INT_MAX = %d\n", INT_MAX);
  scanf("%d", &base);

  if (base < base + 1)
    printf("base < base + 1 (%d < %d) is true!\n", base, base + 1);

  return 0;
}
