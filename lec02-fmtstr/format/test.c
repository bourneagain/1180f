#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <err.h>
#include <stdarg.h>

__attribute__((format(printf, 2, 3)))
int dev_set_name(int fd, const char *fmt, ...) {
  va_list vargs;
  int err;

  va_start(vargs, fmt);
  err = vprintf(fmt, vargs);
  va_end(vargs);
  return err;
}


int main(int argc, char *argv[]) {
  dev_set_name(1, "test1");                   /* OK */
  dev_set_name(2, "test2: %d\n", 1);          /* OK */
  dev_set_name(3, "test3: %d %d\n", 1);       /* YES */
  dev_set_name(3, "test4: %d %d\n", 1, 2, 3); /* YES */
  dev_set_name(3, argv[0]);                   /* MISS */
  
  dev_set_name(3, "test4: %2$d %d %d\n", 1, 2); /* FALSE */
  dev_set_name(3, "test4: %d %1$d", 1);         /* FALSE */

  return 0;
}