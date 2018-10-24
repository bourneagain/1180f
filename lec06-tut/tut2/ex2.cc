#include <stdint.h>
#include <stddef.h>

int strncmp(const char *s1, const char *s2, size_t n) {
  size_t i;
  int diff;

  for (i = 0; i < n; i++) {
    diff = ((unsigned char *) s1)[i] - ((unsigned char *) s2)[i];
    if (diff != 0 || s1[i] == '\0')
      return diff;
  }
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > 3 && !strncmp((char *)data, "HI!", size))
    __builtin_trap();
  return 0;
}