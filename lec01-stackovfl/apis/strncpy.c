#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <err.h>

void vuln(char *src) {
  unsigned int a = 0xdeadbeef;
  unsigned char buf[16];
  unsigned int b = 0xdeadbeef;

  // BUG!
  strncpy(buf, src, sizeof(buf));

  printf("%s\n", buf);

  for (int i = 0; i < strlen(buf); i ++) {
    printf("%02x: %02X (%c)\n", i + 1, buf[i], buf[i]);
  }
}

int main(int argc, char *argv[]) {
  if (argv[1])
    vuln(argv[1]);
  return 0;
}