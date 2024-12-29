/**
 * This file is derived from an original implementation titled
 * sha2-with-c-intrinsic written by Nir Drucker and Shay Gueron,
 * AWS Cryptographic Algorithms Group.
 *
 * See https://github.com/aws-samples/sha2-with-c-intrinsic for original code.
 *
 * Modified by vibhav950 [github.com/vibhav950] for experimentation purposes.
 *
 * NOTICE
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 */

#ifndef __SHA512_X64_INTERNAL_H__
#define __SHA512_X64_INTERNAL_H__

#include "common/defines.h"

#include <stdint.h>

#define SHA512_DIGEST_LENGTH 64

typedef uint64_t sha512_word_t;

#define SHA512_N_ROUNDS 80
#define SHA512_BLOCK_SIZE_BYTES 128
#define SHA512_BLOCK_SIZE_WORDS                                                \
  (SHA512_BLOCK_SIZE_BYTES / sizeof(sha512_word_t))
#define SHA512_N_HASH_WORDS (SHA512_DIGEST_LENGTH / sizeof(sha512_word_t))
#define SHA512_N_BLOCK_WORDS (SHA512_BLOCK_SIZE_BYTES / sizeof(sha512_word_t))

#define SHA512_FINAL_ROUND_START_IDX 64

typedef struct sha512_state_st {
  ALIGN(64) sha512_word_t w[SHA512_N_HASH_WORDS];
} sha512_state_t;

typedef struct sha512_msg_schedule_st {
  ALIGN(64) sha512_word_t w[SHA512_N_BLOCK_WORDS];
} sha512_msg_schedule_t;

#define Sigma0_0 28
#define Sigma0_1 34
#define Sigma0_2 39
#define Sigma1_0 14
#define Sigma1_1 18
#define Sigma1_2 41

#define sigma0_0 1
#define sigma0_1 8
#define sigma0_2 7
#define sigma1_0 19
#define sigma1_1 61
#define sigma1_2 6

#define DUP2(x, y) x, y, x, y
#define DUP4(x, y) x, y, x, y, x, y, x, y

#define ROTR(x, s) ROTR64(x, s)

/* 4.1.3 */
#define Sigma0(x) (ROTR(x, Sigma0_0) ^ ROTR(x, Sigma0_1) ^ ROTR(x, Sigma0_2))
#define Sigma1(x) (ROTR(x, Sigma1_0) ^ ROTR(x, Sigma1_1) ^ ROTR(x, Sigma1_2))
#define sigma0(x) (ROTR(x, sigma0_0) ^ ROTR(x, sigma0_1) ^ ((x) >> sigma0_2))
#define sigma1(x) (ROTR(x, sigma1_0) ^ ROTR(x, sigma1_1) ^ ((x) >> sigma1_2))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Ch(x, y, z) (((x) & (y)) ^ ((~(x)) & (z)))

#define ROTATE_STATE(s)                                                        \
  do {                                                                         \
    const sha512_word_t tmp = (s)->w[7];                                       \
    (s)->w[7] = (s)->w[6];                                                     \
    (s)->w[6] = (s)->w[5];                                                     \
    (s)->w[5] = (s)->w[4];                                                     \
    (s)->w[4] = (s)->w[3];                                                     \
    (s)->w[3] = (s)->w[2];                                                     \
    (s)->w[2] = (s)->w[1];                                                     \
    (s)->w[1] = (s)->w[0];                                                     \
    (s)->w[0] = tmp;                                                           \
  } while (0)

static inline __attribute__((always_inline)) void
sha_round(sha512_state_t *s, const sha512_word_t x, const sha512_word_t k) {
  sha512_word_t t = x + s->w[7] + Sigma1(s->w[4]);

  t += Ch(s->w[4], s->w[5], s->w[6]) + k;
  s->w[7] = t + Sigma0(s->w[0]) + Maj(s->w[0], s->w[1], s->w[2]);
  s->w[3] += t;
  ROTATE_STATE(s);
}

static inline __attribute__((always_inline)) void
accumulate_state(sha512_state_t *dst, const sha512_state_t *src) {
  for (size_t i = 0; i < SHA512_N_HASH_WORDS; i++) {
    dst->w[i] += src->w[i];
  }
}

void sha512_compress_x86_64_avx(sha512_state_t *state, const uint8_t *data,
                                size_t n_blocks);
void sha512_compress_x86_64_avx2(sha512_state_t *state, const uint8_t *data,
                                 size_t n_blocks);
void sha512_compress_x86_64_avx512(sha512_state_t *state, const uint8_t *data,
                                   size_t n_blocks);

#define sha512_compress(x, y, z) sha512_compress_x86_64_avx512(x, y, z)

#endif // __SHA512_X64_INTERNAL_H__