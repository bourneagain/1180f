#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <err.h>

int cmp(unsigned int a, unsigned int b) {
  printf("%u < %u = %d?\n", a, b, (int)(a - b) <= 0);
  printf("  (int)(%u - %u) == %d <= 0? -> %d\n",
         a, b, (int)(a - b), (int)(a - b) <= 0);
}

int main(int argc, char *argv[]) {
  cmp(0, 1);
  cmp(1, 0);
  cmp((unsigned int)(-100), 200);

  while (1) {
    unsigned int a;
    unsigned int b;

    printf("unsigned int a = ?\n");
    scanf("%u", &a);
    printf("unsigned int b = ?\n");
    scanf("%u", &b);

    cmp(a, b);
  }

  return 0;
}