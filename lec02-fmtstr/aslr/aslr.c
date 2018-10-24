#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <err.h>

int global = 1;

int main(int argc, char *argv[]) {
  printf("stack     : %p\n", &argc);
  printf("main()    : %p\n", main);
  printf("global var: %p\n", &global);
  printf("heap      : %p\n", malloc(100));
  printf("system()  : %p\n", system);
  printf("printf()  : %p\n", printf);
  
  printf("> offset (&global-&main)   : %p\n", (void *)&global - (void*)main);
  printf("> offset (&printf-&system) : %p\n", (void *)printf - (void *)system);
  
  return 0;
}