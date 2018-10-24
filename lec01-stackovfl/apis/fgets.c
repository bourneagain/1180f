#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <err.h>

void vuln() {
  unsigned int a = 0xdeadbeef;
  unsigned char buf[16];
  unsigned int b = 0xdeadbeef;

  memset(buf, '0', sizeof(buf));

  fgets(buf, sizeof(buf), stdin);
  printf("%s\n", buf);

  for (int i = 0; i < sizeof(buf); i ++) {
    printf("%02x: %02X (%c)\n", i + 1, buf[i], buf[i]);
  }
}

int main(int argc, char *argv[]) {
  vuln();
  return 0;
}