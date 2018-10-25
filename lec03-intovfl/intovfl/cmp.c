#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <limits.h>

int cmp_long_uint(long a, unsigned int b) {
  return a > b;
}

int main(int argc, char *argv[]) {
  int n = 0;

  printf("%d-byte long\n", sizeof(long));
  printf("(long) %d > (uint) %d = %d\n", -1, 1, cmp_long_uint(-1, 1));
  
  n = INT_MAX;
  printf("INT_MAX + 1 = %d\n", n + 1);
  n = UINT_MAX;
  printf("UINT_MAX + 1 = %u\n",  + 1);
  n = INT_MIN;
  printf("abs(INT_MIN) = %d\n", abs(n));

  n = 32;
  printf("1L << 32 = %d\n", 1L << n);
  printf("1U << 32 = %u\n", 1U << n);

  n = 64;
  printf("1L << 64 = %d\n", 1L << n);
  printf("1U << 64 = %u\n", 1U << n);

  n = 64;
  printf("1LL << 64 = %d\n", 1LL << n);
  printf("1UL << 64 = %u\n", 1UL << n);

  return 0;
}