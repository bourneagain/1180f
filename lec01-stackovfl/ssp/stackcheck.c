#define _GNU_SOURCE

#include <stdio.h>

int func(int argc) {
  return argc;
}

int main(int argc, char *argv[]) {
  return func(argc);
}