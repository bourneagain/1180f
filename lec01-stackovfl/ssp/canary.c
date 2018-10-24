#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <alloca.h>

int func(unsigned long arg) {
  for (int i = 0; i < 5; i ++)
    printf("%p: %#llx\n", &arg + i, *(&arg + i));
  return arg;
}

int main(int argc, char *argv[]) {
  func(10);
  return 0;
}