#include "embeddable_sparx.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

static const uint32_t key_schedule[EMBEDDABLE_SPARX__KEY_SCHEDULE_SIZE] = {
    0x22330011, 0x66774455, 0xaabb8899, 0xeeffccdd, 0x6622aaa9, 0xccff4433,
    0x33768888, 0x7722ddcc, 0x00832253, 0x21feb977, 0xeefdfdaa, 0x895f4487,
    0x8871897f, 0xa4cba6c7, 0xc6c9603e, 0xff0f44f8, 0x57c18881, 0xa6458783,
    0x4b102e4a, 0x58ae4389, 0x4be022f5, 0x05d75ad2, 0xac1ce255, 0xf32ddf6c,
    0xdac5374c, 0x19a43625, 0x1f7b90f7, 0xe79257e0, 0x5b09667c, 0x18247333,
    0x31c8a958, 0x73700e9c, 0x97b2f1b6, 0x3ff053d5, 0x5814c708, 0x243ae31a,
    0x2e364cbc, 0x5b5f0595, 0x9b4f596a, 0x09f369a2, 0x273cd9a3, 0x1e17a6cf,
    0x7976ac64, 0x1d3f7001, 0xc461b2cf, 0xf21f6eef, 0x103615be, 0xa71742ce,
    0x73dccf2f, 0x724163c6, 0x6460d2b5, 0xccb98c61, 0x0e4a5c66, 0x1c0bd37a,
    0x8e4c3740, 0x4184d005, 0x791adebf, 0xe22adb02, 0xfe35ae7c, 0x37880eba,
    0x46dd064b, 0x1cbef8d7, 0xfee8d3d9, 0x0f46f791, 0x5882aa20, 0xc79cdce9,
    0xe45ad5c0, 0x492cb28f, 0x40ab1894, 0xfbdf99d6, 0xc37b76bf, 0xf76e6605,
    0x4707a86d, 0x6a7168dc, 0x665002b2, 0x4f874268, 0xa2ae0cbd, 0x3e4a2257,
    0xa8bb8b33, 0x5314ca55, 0x0067da26, 0x967d1cc7, 0xd4c73f1e, 0xad3f0fd1,
    0xefae2116, 0x4f874e1b, 0xe6046ae2, 0x425a1145, 0x753abc1e, 0xa54b1bf0,
    0xf4d26a0b, 0x32caaad9, 0x0bceb67f, 0x665bb2b2, 0x0ba6cea2, 0xd8ed0ba6,
    0x58e05ce9, 0x24020b3a, 0x8a5dbdec, 0x7fdb5143, 0xcaa2b51b, 0x48182b99,
    0x6c1a36d3, 0x4aae63d8, 0xedb6765f, 0x2887020c, 0x709f2da5, 0xa2ee1287,
    0x1b90cd81, 0x1a79aca2, 0x4300aeae, 0x7887bafa, 0x24ff5b57, 0x716b1f2b,
    0x8be4cbcd, 0xac5ca05d, 0xb562c7d8, 0x4049d3b5, 0xb1b4f2e0, 0x08e9277b,
    0xbe529b14, 0xb37b66f1, 0xf3c43aa6, 0xb54b7399, 0x4494b3d2, 0x1ec2e788,
    0xd23d4e79, 0x8f2a4039, 0x1b780512, 0xfbaae9fb, 0x1a6cd183, 0x8c2ec4d9,
};

// the test vector was obtained from
// https://github.com/cryptolu/SPARX/blob/master/ref-c/sparx.c

static const uint8_t plain_text[EMBEDDABLE_SPARX__BLOCK_SIZE] = {
    0x23,
    0x01,
    0x67,
    0x45,
    0xab,
    0x89,
    0xef,
    0xcd,
    0xdc,
    0xfe,
    0x98,
    0xba,
    0x54,
    0x76,
    0x10,
    0x32,
};

static const uint8_t cipher_text[EMBEDDABLE_SPARX__BLOCK_SIZE] = {
    0xee,
    0x1c,
    0x40,
    0x75,
    0xbf,
    0x7d,
    0xd8,
    0x23,
    0xee,
    0xe0,
    0x97,
    0x15,
    0x28,
    0xf4,
    0xd8,
    0x52,
};

static void encrypted_handler(uint8_t *result);
static const EmbeddableSparx_Config encryption_config = {
    .key_schedule = (uint32_t *)key_schedule,
    .finished = &encrypted_handler,
};
static EmbeddableSparx_State encryption_state;

static void decrypted_handler(uint8_t *result);
static const EmbeddableSparx_Config decryption_config = {
    .key_schedule = (uint32_t *)key_schedule,
    .finished = &decrypted_handler,
};
static EmbeddableSparx_State decryption_state;

int main(void) {
  embeddable_sparx__init(&encryption_state);
  embeddable_sparx__init(&decryption_state);
  embeddable_sparx__start(&encryption_state, (uint8_t *)plain_text);
  for (uint16_t i = 0; i < 1024; i++) {
    embeddable_sparx__encryption_poll(&encryption_config, &encryption_state);
    embeddable_sparx__decryption_poll(&decryption_config, &decryption_state);
  }
  puts("Done!");
  return 0;
}

static bool encryption_check(uint8_t *result);
static void encrypted_handler(uint8_t *result) {
  if (encryption_check(result)) {
    puts("Encryption test PASSED");
  } else {
    puts("Encryption test FAILED");
  }
  embeddable_sparx__start(&decryption_state, result);
}

static bool encryption_check(uint8_t *result) {
  for (uint8_t i = 0; i < EMBEDDABLE_SPARX__BLOCK_SIZE; i++)
    if (cipher_text[i] != result[i])
      return false;
  return true;
}

static bool decryption_check(uint8_t *result);
static void decrypted_handler(uint8_t *result) {
  if (decryption_check(result)) {
    puts("Decryption test PASSED");
  } else {
    puts("Decryption test FAILED");
  }
}

static bool decryption_check(uint8_t *result) {
  for (uint8_t i = 0; i < EMBEDDABLE_SPARX__BLOCK_SIZE; i++)
    if (plain_text[i] != result[i])
      return false;
  return true;
}
