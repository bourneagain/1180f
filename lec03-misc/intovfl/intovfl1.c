#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <err.h>
#include <limits.h>

int main(int argc, char *argv[]) {
  int ints[] = {INT_MIN, SHRT_MIN, CHAR_MIN, -1,
                0,
                1, CHAR_MAX, UCHAR_MAX, SHRT_MAX, USHRT_MAX, INT_MAX};

  /* widthness/precision */
  for (int i = 0; i < sizeof(ints)/sizeof(ints[0]); i ++) {
    printf("%d (%#x) is casted to:\n", ints[i], (unsigned int)(ints[i]));
#define S(n) printf("  %-20s: %d\n", #n, (n)ints[i])
#define U(n) printf("  %-20s: %u\n", #n, (n)ints[i])
#define LLS(n) printf("  %-20s: %lld\n", #n, (n)ints[i])
#define LLU(n) printf("  %-20s: %llu\n", #n, (n)ints[i])
    S(char);
    U(unsigned char);
    S(short);
    U(unsigned short);
    S(int);
    U(unsigned int);
    LLS(long long);
    LLU(unsigned long long);
  }
  return 0;
}