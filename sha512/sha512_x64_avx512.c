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

#include "avx512_defs.h"
#include "common/defines.h"
#include "sha512_constants.h"
#include "sha512_x64_internal.h"

#include "sha512_compress_hlp.c"

#include <immintrin.h>

// Processing 4 blocks in parallel
#define MS_VEC_NUM ((4 * SHA512_BLOCK_SIZE_BYTES) / sizeof(__m512i))
#define WORDS_IN_128_BIT_VEC (16 / sizeof(sha512_word_t))
#define WORDS_IN_VEC (sizeof(__m512i) / sizeof(sha512_word_t))

static inline __attribute__((always_inline)) void
load_data(__m512i x[MS_VEC_NUM], sha512_msg_schedule_t *ms,
          sha512_word_t x2_4[3][SHA512_N_ROUNDS], const uint8_t *data) {
  const __m512i shuf_mask =
      _mm512_set_epi64(DUP4(0x08090a0b0c0d0e0f, 0x0001020304050607));

  PRAGMA_UNROLL_8

  for (size_t i = 0; i < MS_VEC_NUM; i++) {
    const size_t pos0 = (sizeof(__m512i) / 4) * i;
    const size_t pos1 = pos0 + SHA512_BLOCK_SIZE_BYTES;
    const size_t pos2 = pos1 + SHA512_BLOCK_SIZE_BYTES;
    const size_t pos3 = pos2 + SHA512_BLOCK_SIZE_BYTES;
    LOADU4(&data[pos3], &data[pos2], &data[pos1], &data[pos0], x[i]);

    x[i] = SHUF8(x[i], shuf_mask);
    __m512i y = ADD64(x[i], LOAD(&K512x4[8 * i]));

    STOREU4(&x2_4[2][2 * i], &x2_4[1][2 * i], &x2_4[0][2 * i], &ms->w[2 * i],
            y);
  }
}

static inline __attribute__((always_inline)) void
rounds_0_63(sha512_state_t *cur_state, __m512i x[MS_VEC_NUM],
            sha512_msg_schedule_t *ms, sha512_word_t x2_4[][SHA512_N_ROUNDS]) {
  // The first SHA512_BLOCK_WORDS_NUM entries of K512 were loaded in
  // load_data(...).
  size_t k512_idx = 4 * SHA512_N_BLOCK_WORDS;

  // Rounds 0-63 (0-15, 16-31, 32-47, 48-63)
  for (size_t i = 1; i < 5; i++) {

    PRAGMA_UNROLL_8

    for (size_t j = 0; j < MS_VEC_NUM; j++) {
      const size_t pos = WORDS_IN_128_BIT_VEC * j;
      const __m512i y = sha512_update_x_avx(x, &K512x4[k512_idx]);

      sha_round(cur_state, ms->w[pos], 0);
      sha_round(cur_state, ms->w[pos + 1], 0);
      const size_t idx = k512_idx >> 2;

      STOREU4(&x2_4[2][idx], &x2_4[1][idx], &x2_4[0][idx], &ms->w[pos], y);
      k512_idx += WORDS_IN_VEC;
    }
  }
}

static inline __attribute__((always_inline)) void
rounds_64_79(sha512_state_t *cur_state, const sha512_msg_schedule_t *ms) {
  PRAGMA_UNROLL_16

  for (size_t i = SHA512_FINAL_ROUND_START_IDX; i < SHA512_N_ROUNDS; i++) {
    sha_round(cur_state, ms->w[LSB4(i)], 0);
  }
}

static inline __attribute__((always_inline)) void
process_extra_block(sha512_state_t *cur_state,
                    const sha512_word_t t[SHA512_N_ROUNDS]) {
  PRAGMA_UNROLL_80

  for (size_t i = 0; i < SHA512_N_ROUNDS; i++) {
    sha_round(cur_state, t[i], 0);
  }
}

void sha512_compress_x86_64_avx512(sha512_state_t *state, const uint8_t *data,
                                   size_t blocks_num) {
  ALIGN(64) sha512_msg_schedule_t ms;
  ALIGN(64) sha512_word_t x2_4[3][SHA512_N_ROUNDS];
  sha512_state_t cur_state;
  __m512i x[MS_VEC_NUM];

  const size_t rem = LSB2(blocks_num);
  if (rem != 0) {
    sha512_compress_x86_64_avx2(state, data, rem);
    data += rem * SHA512_BLOCK_SIZE_BYTES;
    blocks_num -= rem;
  }

  // Process four blocks in parallel
  // Here blocks_num is divided by 4
  for (size_t b = blocks_num; b != 0; b -= 4) {
    crypt_memcpy(cur_state.w, state->w, sizeof(cur_state.w));

    load_data(x, &ms, x2_4, data);
    data += 4 * SHA512_BLOCK_SIZE_BYTES;

    // First block
    rounds_0_63(&cur_state, x, &ms, x2_4);
    rounds_64_79(&cur_state, &ms);
    accumulate_state(state, &cur_state);

    for (size_t i = 0; i <= 2; i++) {
      crypt_memcpy(cur_state.w, state->w, sizeof(cur_state.w));
      process_extra_block(&cur_state, x2_4[i]);
      accumulate_state(state, &cur_state);
    }
  }

  memzero(&cur_state, sizeof(cur_state));
  memzero(&ms, sizeof(ms));
  memzero(x2_4, sizeof(x2_4));
}
