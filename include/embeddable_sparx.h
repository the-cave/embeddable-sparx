// Copyright (c) 2020 Sarun Rattanasiri
// under the 3-Clause BSD License
// https://opensource.org/licenses/BSD-3-Clause

#ifndef __EMBEDDABLE_SPARX_H
#define __EMBEDDABLE_SPARX_H

#include <stdbool.h>
#include <stdint.h>

#define EMBEDDABLE_SPARX__BLOCK_SIZE 16
#define EMBEDDABLE_SPARX__WORD_SIZE 4
#define EMBEDDABLE_SPARX__STEP 8
#define EMBEDDABLE_SPARX__BRANCH                                               \
  (EMBEDDABLE_SPARX__BLOCK_SIZE / EMBEDDABLE_SPARX__WORD_SIZE)
// (round per step = 4; total round = 8 * 4 = 32)
#define EMBEDDABLE_SPARX__ROUND 4
#define EMBEDDABLE_SPARX__KEY_SCHEDULE_SIZE                                    \
  ((EMBEDDABLE_SPARX__STEP * EMBEDDABLE_SPARX__BRANCH + 1) *                   \
   EMBEDDABLE_SPARX__ROUND)

typedef struct _embeddable_sparx__config {
  uint32_t *key_schedule;
  void (*finished)(uint8_t *result);
} EmbeddableSparx_Config;

typedef struct _embeddable_sparx__state {
  uint8_t step;
  uint32_t scratch_pad[EMBEDDABLE_SPARX__BRANCH];
  uint8_t output[EMBEDDABLE_SPARX__BLOCK_SIZE];
} EmbeddableSparx_State;

#define embeddable_sparx__init(state)                                          \
  do {                                                                         \
    (state)->step = 0;                                                         \
  } while (0)

bool embeddable_sparx__start(EmbeddableSparx_State *state, uint8_t *data);

void embeddable_sparx__encryption_poll(
    const EmbeddableSparx_Config *config,
    EmbeddableSparx_State *state);

void embeddable_sparx__decryption_poll(
    const EmbeddableSparx_Config *config,
    EmbeddableSparx_State *state);

void embeddable_sparx__schedule_key(
    uint8_t input_key[16],
    uint32_t output_schedule[]);

#endif
