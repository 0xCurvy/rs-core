#include <stdint.h>
#include <string.h>

static const char *case_names[] = {
  "control", "base_mul", "reduce_wide", "nonce_candidate", "response",
  "sign_seed", "sign_scalar", "blake512", "poseidon_secret", "decimal",
  "owner_hash_decimal", "poseidon_vartime"
};
extern void curvy_leakage_run(uint32_t operation, const uint8_t *input, uint8_t *output);

static void constrain_input(unsigned operation, uint8_t input[96]) {
  /* Both scalar classes have the same bit length and are nonzero/canonical. */
  input[31] = (input[31] & 1) | 2;
  input[63] &= 0x7f;
  if (operation == 8 || operation == 11) input[0] &= 0x1f; /* Big-endian BN254 element. */
  if (operation == 9 || operation == 10) {
    for (unsigned j = 0; j < 78; j++) input[j] = '0' + input[j] % 10;
    input[0] = '0'; input[1] = '0'; /* Always below 2^256. */
  }
}

static int find_case(const char *name) {
  for (unsigned i = 0; i < sizeof(case_names)/sizeof(*case_names); i++)
    if (!strcmp(name, case_names[i])) return (int)i;
  return -1;
}
