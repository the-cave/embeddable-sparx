// Copyright (c) 2020 Sarun Rattanasiri
// under the 3-Clause BSD License
// https://opensource.org/licenses/BSD-3-Clause

#include "embeddable_sparx.h"

#define ROTL16(x, r) (((x) << (r)) | (x >> (16 - (r))))
#define ROTR16(x, r) (((x) >> (r)) | ((x) << (16 - (r))))
#define SWAP(x, y, temp)                                                       \
  temp = x;                                                                    \
  x = y;                                                                       \
  y = temp

#define SPARX_A(left, right)                                                   \
  do {                                                                         \
    (*(left)) = ROTL16((*(left)), 9);                                          \
    (*(left)) += (*(right));                                                   \
    (*(right)) = ROTL16((*(right)), 2);                                        \
    (*(right)) ^= (*(left));                                                   \
  } while (0)

#define SPARX_A_inv(left, right)                                               \
  do {                                                                         \
    (*(right)) ^= (*(left));                                                   \
    (*(right)) = ROTL16((*(right)), 14);                                       \
    (*(left)) -= (*(right));                                                   \
    (*(left)) = ROTL16((*(left)), 7);                                          \
  } while (0)

#define SPARX_L(buffer, temp)                                                  \
  do {                                                                         \
    temp = buffer[0] ^ buffer[1] ^ buffer[2] ^ buffer[3];                      \
    temp = ROTL16(temp, 8);                                                    \
    buffer[4] ^= buffer[2] ^ temp;                                             \
    buffer[5] ^= buffer[1] ^ temp;                                             \
    buffer[6] ^= buffer[0] ^ temp;                                             \
    buffer[7] ^= buffer[3] ^ temp;                                             \
    SWAP(buffer[0], buffer[4], temp);                                          \
    SWAP(buffer[1], buffer[5], temp);                                          \
    SWAP(buffer[2], buffer[6], temp);                                          \
    SWAP(buffer[3], buffer[7], temp);                                          \
  } while (0)

#define SPARX_L_inv(buffer, temp)                                              \
  do {                                                                         \
    SWAP(buffer[0], buffer[4], temp);                                          \
    SWAP(buffer[1], buffer[5], temp);                                          \
    SWAP(buffer[2], buffer[6], temp);                                          \
    SWAP(buffer[3], buffer[7], temp);                                          \
    temp = buffer[0] ^ buffer[1] ^ buffer[2] ^ buffer[3];                      \
    temp = ROTL16(temp, 8);                                                    \
    buffer[4] ^= buffer[2] ^ temp;                                             \
    buffer[5] ^= buffer[1] ^ temp;                                             \
    buffer[6] ^= buffer[0] ^ temp;                                             \
    buffer[7] ^= buffer[3] ^ temp;                                             \
  } while (0)

bool embeddable_sparx__start(EmbeddableSparx_State *state, uint8_t *data) {
  if (state->step != 0)
    return false; // rejected
  state->scratch_pad[0] = ((uint32_t *)data)[0];
  state->scratch_pad[1] = ((uint32_t *)data)[1];
  state->scratch_pad[2] = ((uint32_t *)data)[2];
  state->scratch_pad[3] = ((uint32_t *)data)[3];
  state->step++;
  return true; // accepted
}

void embeddable_sparx__encryption_poll(
    const EmbeddableSparx_Config *config,
    EmbeddableSparx_State *state) {
  uint8_t step = state->step;
  // nothing to do
  if (step < 1)
    return;
  // perform cryptographic round
  if (step < (1 + (EMBEDDABLE_SPARX__STEP * EMBEDDABLE_SPARX__BRANCH *
                   EMBEDDABLE_SPARX__ROUND))) {
    uint8_t operation_number = step - 1;
    uint8_t branch = ((operation_number >> 2) & 0x3);
    volatile uint32_t *operating_word = state->scratch_pad + branch;
    (*operating_word) ^= config->key_schedule[operation_number];
    uint16_t *lower_half = (uint16_t *)operating_word;
    uint16_t *upper_half = lower_half + 1;
    SPARX_A(lower_half, upper_half);
    if ((operation_number & 0xf) == 0xf) {
      uint16_t *linear_mixing = (uint16_t *)state->scratch_pad;
      uint16_t temp;
      SPARX_L(linear_mixing, temp);
    }
    state->step++;
    return;
  }
  // finalization
  if (step < (1 +
              (EMBEDDABLE_SPARX__STEP * EMBEDDABLE_SPARX__BRANCH *
               EMBEDDABLE_SPARX__ROUND) +
              EMBEDDABLE_SPARX__BRANCH)) {
    uint8_t operation_number =
        step - (1 + (EMBEDDABLE_SPARX__STEP * EMBEDDABLE_SPARX__BRANCH *
                     EMBEDDABLE_SPARX__ROUND));
    state->scratch_pad[operation_number] ^=
        config->key_schedule
            [(EMBEDDABLE_SPARX__STEP * EMBEDDABLE_SPARX__BRANCH *
              EMBEDDABLE_SPARX__ROUND) +
             operation_number];
    state->step++;
    return;
  }
  // normalize output
  if (step < (1 +
              (EMBEDDABLE_SPARX__STEP * EMBEDDABLE_SPARX__BRANCH *
               EMBEDDABLE_SPARX__ROUND) +
              EMBEDDABLE_SPARX__BRANCH + 1)) {
    uint32_t *output = (uint32_t *)state->output;
    uint32_t *raw = state->scratch_pad;
    output[0] = ((uint32_t *)raw)[0];
    output[1] = ((uint32_t *)raw)[1];
    output[2] = ((uint32_t *)raw)[2];
    output[3] = ((uint32_t *)raw)[3];
    state->step++;
    return;
  }
  // emit and reset
  state->step = 0;
  if (config->finished)
    config->finished(state->output);
}

void embeddable_sparx__decryption_poll(
    const EmbeddableSparx_Config *config,
    EmbeddableSparx_State *state) {
  uint8_t step = state->step;
  // nothing to do
  if (step < 1)
    return;
  // definalization
  if (step < (1 + EMBEDDABLE_SPARX__BRANCH)) {
    uint8_t operation_number = step - 1;
    state->scratch_pad[operation_number] ^=
        config->key_schedule
            [(EMBEDDABLE_SPARX__STEP * EMBEDDABLE_SPARX__BRANCH *
              EMBEDDABLE_SPARX__ROUND) +
             operation_number];
    state->step++;
    return;
  }
  // perform cryptographic round
  if (step < (1 + EMBEDDABLE_SPARX__BRANCH +
              (EMBEDDABLE_SPARX__STEP * EMBEDDABLE_SPARX__BRANCH *
               EMBEDDABLE_SPARX__ROUND))) {
    uint8_t operation_number =
        (EMBEDDABLE_SPARX__STEP * EMBEDDABLE_SPARX__BRANCH *
             EMBEDDABLE_SPARX__ROUND -
         1) -
        (step - (1 + EMBEDDABLE_SPARX__BRANCH));
    if ((operation_number & 0xf) == 0xf) {
      uint16_t *linear_mixing = (uint16_t *)state->scratch_pad;
      uint16_t temp;
      SPARX_L_inv(linear_mixing, temp);
    }
    uint8_t branch = ((operation_number >> 2) & 0x3);
    uint32_t *operating_word = state->scratch_pad + branch;
    volatile uint16_t *lower_half = (uint16_t *)operating_word;
    volatile uint16_t *upper_half = lower_half + 1;
    SPARX_A_inv(lower_half, upper_half);
    (*operating_word) ^= config->key_schedule[operation_number];
    state->step++;
    return;
  }
  // normalize output
  if (step < (1 + EMBEDDABLE_SPARX__BRANCH +
              (EMBEDDABLE_SPARX__STEP * EMBEDDABLE_SPARX__BRANCH *
               EMBEDDABLE_SPARX__ROUND) +
              1)) {
    uint32_t *output = (uint32_t *)state->output;
    uint32_t *raw = state->scratch_pad;
    output[0] = ((uint32_t *)raw)[0];
    output[1] = ((uint32_t *)raw)[1];
    output[2] = ((uint32_t *)raw)[2];
    output[3] = ((uint32_t *)raw)[3];
    state->step++;
    return;
  }
  // emit and reset
  state->step = 0;
  if (config->finished)
    config->finished(state->output);
}
