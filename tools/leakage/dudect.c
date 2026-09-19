#define DUDECT_IMPLEMENTATION
#include "vendor/dudect.h"
#include "cases.h"

static unsigned operation;
static int sparse_dense;
static uint64_t seed = UINT64_C(0x9e3779b97f4a7c15);
static uint64_t random_word(void) {
  seed ^= seed >> 12; seed ^= seed << 25; seed ^= seed >> 27;
  return seed * UINT64_C(2685821657736338717);
}

void prepare_inputs(dudect_config_t *config, uint8_t *inputs, uint8_t *classes) {
  for (size_t i = 0; i < config->number_measurements; i++) {
    uint8_t *input = inputs + i * 96;
    classes[i] = random_word() & 1;
    for (unsigned j = 0; j < 96; j += 8) {
      uint64_t word = random_word();
      memcpy(input + j, &word, 8);
    }
    if (sparse_dense) memset(input, classes[i] ? 0xff : 0, 96);
    else if (!classes[i]) memset(input, 0x42, 96);
    constrain_input(operation, input);
  }
}

uint8_t do_one_computation(uint8_t *input) {
  uint8_t output[96];
  curvy_leakage_run(operation, input, output);
  return output[0];
}

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IOLBF, 0);
  if (argc != 4) return 2;
  int found = find_case(argv[1]);
  if (found < 0) return 2;
  operation = (unsigned)found;
  sparse_dense = !strcmp(argv[2], "sparse-dense");
  if (!sparse_dense && strcmp(argv[2], "fixed-random")) return 2;
  char *end;
  unsigned long requested = strtoul(argv[3], &end, 10);
  if (*end || requested < 30000 || requested > 100000000) return 2;
  dudect_config_t config = { .chunk_size = 96, .number_measurements = 32768 };
  dudect_ctx_t ctx;
  dudect_init(&ctx, &config);
  uint8_t warm[96] = {0};
  constrain_input(operation, warm);
  for (unsigned i = 0; i < 100; i++) do_one_computation(warm);
  dudect_main(&ctx); /* calibration samples are excluded from the result */
  dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
  unsigned long batches = 0;
  while (ctx.ttest_ctxs[0]->n[0] + ctx.ttest_ctxs[0]->n[1] < requested) {
    state = dudect_main(&ctx);
    batches++;
    if (state == DUDECT_LEAKAGE_FOUND) break;
  }
  ttest_ctx_t *test = max_test(&ctx);
  double max_t = fabs(t_compute(test));
  int sufficient = isfinite(max_t) && ctx.ttest_ctxs[0]->n[0] > 10000 && ctx.ttest_ctxs[0]->n[1] > 10000;
  const char *result = !sufficient ? "inconclusive" :
    state == DUDECT_LEAKAGE_FOUND ? "leakage_detected" : "no_leakage_detected";
  printf("RESULT {\"case\":\"%s\",\"family\":\"%s\",\"status\":\"%s\",", argv[1], argv[2], result);
  printf("\"requested_samples\":%lu,\"executed_samples\":%lu,\"class_samples\":[%.0f,%.0f],",
    requested, (batches + 1) * config.number_measurements, ctx.ttest_ctxs[0]->n[0], ctx.ttest_ctxs[0]->n[1]);
  if (isfinite(max_t)) printf("\"max_abs_t\":%.12g,", max_t);
  else printf("\"max_abs_t\":null,");
  printf("\"threshold\":10,\"statistical_tests\":%d}\n", DUDECT_TESTS);
  dudect_free(&ctx);
  return !sufficient ? 2 : 0;
}
