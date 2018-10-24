#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <alloca.h>

int vuln(char *src) {
  unsigned char buf[16];
  strcpy(buf, src);
  return 0;
}

int main(int argc, char *argv[]) {
  vuln("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  return 0;
}