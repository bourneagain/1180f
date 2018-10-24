#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <alloca.h>

int func1_benign(long arg) {
  long var1 = 1;
  long var2 = 2;
  long var3 = 3;

  printf("%s():\n", __func__);
  printf("  %p: %#x (var1)\n", &var1, var1);
  printf("  %p: %#x (var2)\n", &var2, var2);
  printf("  %p: %#x (var3)\n", &var3, var3);
  
  return arg;
}

int func2_buf(long arg) {
  long var1 = 1;
  long var2[32] = {2,};
  long var3 = 3;

  printf("%s():\n", __func__);
  printf("  %p: %#x (var1)\n", &var1, var1);
  printf("  %p: %#x (var2)\n", &var2, var2[0]);
  printf("  %p: %#x (var3)\n", &var3, var3);
  
  return arg;
}

int func3_alloca(long arg) {
  long var1 = 1;
  long *var2 = alloca(32*sizeof(long));
  long var3 = 3;

  var2[0] = 2;
  
  printf("%s():\n", __func__);
  printf("  %p: %#x (var1)\n", &var1, var1);
  printf("  %p: %#x (var2)\n", &var2, var2[0]);
  printf("  %p: %#x (var3)\n", &var3, var3);
  
  return arg;
}

int func4_funcptr(long arg) {
  long var1 = 1;
  int (*var2)(const char *) = system;
  long var3 = 3;

  printf("%s():\n", __func__);
  printf("  %p: %#x (var1)\n", &var1, var1);
  printf("  %p: %p (var2)\n", &var2, var2);
  printf("  %p: %#x (var3)\n", &var3, var3);
  
  return arg;
}

int func5_buf_and_funcptr(long arg) {
  long var1[32] = {1, };
  int (*var2)(const char *) = system;
  long var3 = 3;

  printf("%s():\n", __func__);
  printf("  %p: %#x (var1)\n", &var1, var1[0]);
  printf("  %p: %p (var2)\n", &var2, var2);
  printf("  %p: %#x (var3)\n", &var3, var3);
  
  return arg;
}

int main(int argc, char *argv[]) {
  func1_benign(argc);
  func2_buf(argc);
  func3_alloca(argc);
  func4_funcptr(argc);
  func5_buf_and_funcptr(argc);
  return 0;
}