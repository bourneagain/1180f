#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <alloca.h>

int func1_benign(int arg) {
  return arg;
}

int func2_alloca(int arg) {
  int *buf = (int *)alloca(100);
  return arg;
}

__attribute__((stack_protect))
int func3_explicit(int arg) {
  return arg;
}

int func4_buf(int arg) {
  int buf[100];
  memset(buf, 0, sizeof(buf));
  return buf[0];
}

int main(int argc, char *argv[]) {
  func1_benign(argc);
  func2_alloca(argc);
  func3_explicit(argc);
}