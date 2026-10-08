#include <stdio.h>
#include <valgrind/memcheck.h>
#include "cases.h"

extern void curvy_leakage_set_declassifier(void (*callback)(uint8_t *, size_t));
extern void curvy_leakage_check_poseidon_arities(const uint8_t *input);
static void public_bytes(uint8_t *bytes, size_t len) {
  VALGRIND_MAKE_MEM_DEFINED(bytes, len);
}

int main(int argc, char **argv) {
  if (argc != 2 || !RUNNING_ON_VALGRIND) return 2;
  int operation = find_case(argv[1]);
  if (operation < 0) return 2;
  curvy_leakage_set_declassifier(public_bytes);
  uint8_t input[96], output[96];
  memset(input, 0x42, sizeof(input));
  constrain_input(operation, input);
  curvy_leakage_run(operation, input, output);
  if (operation == 8) curvy_leakage_check_poseidon_arities(input);
  for (unsigned pattern = 0; pattern < 3; pattern++) {
    memset(input, pattern == 0 ? 0 : pattern == 1 ? 0xff : 0x42, sizeof(input));
    constrain_input(operation, input);
    VALGRIND_MAKE_MEM_UNDEFINED(input, operation == 9 || operation == 10 ? 78 : operation >= 2 && operation <= 4 ? 64 : operation == 7 ? 64 : 32);
    curvy_leakage_run(operation, input, output);
    if (operation == 8) curvy_leakage_check_poseidon_arities(input);
    VALGRIND_MAKE_MEM_DEFINED(input, sizeof(input));
    VALGRIND_MAKE_MEM_DEFINED(output, sizeof(output));
  }
  return 0;
}
