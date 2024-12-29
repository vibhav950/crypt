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

#include "avx2_defs.h"
#include "common/defines.h"
#include "sha512_constants.h"
#include "sha512_x64_internal.h"

#include "sha512_compress_hlp.c"

// Processing 2 blocks in parallel
#define MS_VEC_NUM ((2 * SHA512_BLOCK_SIZE_BYTES) / sizeof(__m256i))
#define WORDS_IN_128_BIT_VEC (16 / sizeof(sha512_word_t))
#define WORDS_IN_VEC (sizeof(__m256i) / sizeof(sha512_word_t))

static inline __attribute__((always_inline)) void
load_data(__m256i x[MS_VEC_NUM], sha512_msg_schedule_t *ms,
          sha512_word_t t2[SHA512_N_ROUNDS], const uint8_t *data) {
  // 64 bits (8 bytes) swap masks
  const __m256i shuf_mask =
      _mm256_set_epi64x(DUP2(0x08090a0b0c0d0e0f, 0x0001020304050607));

  PRAGMA_UNROLL_8

  for (size_t i = 0; i < MS_VEC_NUM; i++) {
    const size_t pos0 = (sizeof(__m256i) / 2) * i;
    const size_t pos1 = pos0 + SHA512_BLOCK_SIZE_BYTES;

    LOADU2(&data[pos1], &data[pos0], x[i]);
    x[i] = SHUF8(x[i], shuf_mask);
    __m256i y = ADD64(x[i], LOAD(&K512x2[4 * i]));
    STOREU2(&t2[2 * i], &ms->w[2 * i], y);
  }
}

static inline __attribute__((always_inline)) void
rounds_0_63(sha512_state_t *cur_state, __m256i x[MS_VEC_NUM],
            sha512_msg_schedule_t *ms, sha512_word_t t2[SHA512_N_ROUNDS]) {
  // The first SHA512_N_BLOCK_WORDS entries of K512 were loaded in
  // load_data(...).
  size_t k512_idx = 2 * SHA512_N_BLOCK_WORDS;

  // Rounds 0-63 (0-15, 16-31, 32-47, 48-63)
  for (size_t i = 1; i < 5; i++) {

    PRAGMA_UNROLL_8

    for (size_t j = 0; j < 8; j++) {
      const size_t pos = WORDS_IN_128_BIT_VEC * j;

      const __m256i y = sha512_update_x_avx(x, &K512x2[k512_idx]);

      sha_round(cur_state, ms->w[pos], 0);
      sha_round(cur_state, ms->w[pos + 1], 0);
      STOREU2(&t2[(16 * i) + pos], &ms->w[pos], y);
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
process_second_block(sha512_state_t *cur_state,
                     const sha512_word_t t2[SHA512_N_ROUNDS]) {
  PRAGMA_UNROLL_80

  for (size_t i = 0; i < SHA512_N_ROUNDS; i++) {
    sha_round(cur_state, t2[i], 0);
  }
}

void sha512_compress_x86_64_avx2(sha512_state_t *state, const uint8_t *data,
                                 size_t blocks_num) {
  ALIGN(64) sha512_msg_schedule_t ms;
  ALIGN(64) sha512_word_t t2[SHA512_N_ROUNDS];
  sha512_state_t cur_state;
  __m256i x[MS_VEC_NUM];

  if (LSB1(blocks_num)) {
    sha512_compress_x86_64_avx(state, data, 1);
    data += SHA512_BLOCK_SIZE_BYTES;
    blocks_num--;
  }

  // Process two blocks in parallel
  // Here blocks_num is even
  for (size_t b = blocks_num; b != 0; b -= 2) {
    crypt_memcpy(cur_state.w, state->w, sizeof(cur_state.w));

    load_data(x, &ms, t2, data);
    data += 2 * SHA512_BLOCK_SIZE_BYTES;

    // First block
    rounds_0_63(&cur_state, x, &ms, t2);
    rounds_64_79(&cur_state, &ms);
    accumulate_state(state, &cur_state);

    // Second block
    crypt_memcpy(cur_state.w, state->w, sizeof(cur_state.w));
    process_second_block(&cur_state, t2);
    accumulate_state(state, &cur_state);
  }

  memzero(&cur_state, sizeof(cur_state));
  memzero(&ms, sizeof(ms));
  memzero(t2, sizeof(t2));
}
