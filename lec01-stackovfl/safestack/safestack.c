#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

void vuln(char *arg) {
  char buf[32];
  strcpy(buf, arg);
}

int main(int argc, char *argv[]) {
  if (argv[1])
    vuln(argv[1]);
  return 0;
}