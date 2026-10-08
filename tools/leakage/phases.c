#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include "cases.h"

enum { PHASES = 8 };
static const char *phase_names[] = {
  "point_arithmetic", "point_encoding", "seed_expansion", "nonce_derivation",
  "challenge", "response", "signature_encoding", "public_verification"
};
static double started[PHASES], elapsed[PHASES];
static unsigned calls[PHASES];
extern void curvy_leakage_set_observer(void (*callback)(uint32_t, bool));

static double now(void) {
  struct timespec time;
  if (clock_gettime(CLOCK_MONOTONIC_RAW, &time)) abort();
  return (double)time.tv_sec * 1e9 + time.tv_nsec;
}

static void observe(uint32_t phase, bool start) {
  if (phase >= PHASES) abort();
  if (start) started[phase] = now();
  else { elapsed[phase] += now() - started[phase]; calls[phase]++; }
}

struct moments { unsigned long n; double mean, m2; };
static void push(struct moments *group, double value) {
  group->n++;
  double delta = value - group->mean;
  group->mean += delta / group->n;
  group->m2 += delta * (value - group->mean);
}
static uint64_t seed = UINT64_C(0x9e3779b97f4a7c15);
static uint64_t random_word(void) {
  seed ^= seed >> 12; seed ^= seed << 25; seed ^= seed >> 27;
  return seed * UINT64_C(2685821657736338717);
}

int main(int argc, char **argv) {
  if (argc != 4) return 2;
  int operation = find_case(argv[1]);
  if (operation != 5 && operation != 6) return 2;
  bool sparse = !strcmp(argv[2], "sparse-dense");
  if (!sparse && strcmp(argv[2], "fixed-random")) return 2;
  char *end;
  unsigned long samples = strtoul(argv[3], &end, 10);
  if (*end || samples < 30000 || samples > 100000000) return 2;
  curvy_leakage_set_observer(observe);
  uint8_t input[96] = {0}, output[96];
  constrain_input(operation, input);
  for (unsigned i = 0; i < 100; i++) curvy_leakage_run(operation, input, output);
  struct moments measurements[PHASES + 1][2] = {0};
  for (unsigned long i = 0; i < samples; i++) {
    unsigned group = random_word() & 1;
    for (unsigned j = 0; j < 96; j += 8) {
      uint64_t word = random_word();
      memcpy(input + j, &word, 8);
    }
    if (sparse) memset(input, group ? 0xff : 0, sizeof(input));
    else if (!group) memset(input, 0x42, sizeof(input));
    constrain_input(operation, input);
    memset(elapsed, 0, sizeof(elapsed));
    memset(calls, 0, sizeof(calls));
    double start = now();
    curvy_leakage_run(operation, input, output);
    push(&measurements[PHASES][group], now() - start);
    for (unsigned phase = 0; phase < PHASES; phase++) {
      if (calls[phase]) push(&measurements[phase][group], elapsed[phase]);
    }
  }
  printf("RESULT {\"case\":\"%s\",\"family\":\"%s\",\"status\":\"profiled\",\"samples\":%lu,\"phases\":[",
    argv[1], argv[2], samples);
  bool comma = false;
  for (unsigned phase = 0; phase <= PHASES; phase++) {
    struct moments a = measurements[phase][0], b = measurements[phase][1];
    if (!a.n && !b.n) continue;
    if (a.n < 10000 || b.n < 10000) return 2;
    double t = (a.mean - b.mean) / sqrt(a.m2 / (a.n - 1) / a.n + b.m2 / (b.n - 1) / b.n);
    printf("%s{\"phase\":\"%s\",\"class_samples\":[%lu,%lu],\"mean_ns\":[%.6f,%.6f],\"t\":",
      comma ? "," : "", phase == PHASES ? "total" : phase_names[phase], a.n, b.n, a.mean, b.mean);
    if (isfinite(t)) printf("%.8f}", t); else printf("null}");
    comma = true;
  }
  puts("]}");
  return 0;
}
