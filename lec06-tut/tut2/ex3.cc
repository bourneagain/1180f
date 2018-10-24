#include <stdint.h>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > 3 && *(unsigned int *)data == 0xdeadbeef)
    __builtin_trap();
  return 0;
}