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

#include "avx_defs.h"
#include "common/defines.h"
#include "sha512_constants.h"
#include "sha512_x64_internal.h"

#include "sha512_compress_hlp.c"

#define MS_VEC_NUM (SHA512_BLOCK_SIZE_BYTES / sizeof(vec_t))
#define WORDS_IN_VEC (16 / sizeof(sha512_word_t))

static inline __attribute__((always_inline)) void
load_data(vec_t x[MS_VEC_NUM], sha512_msg_schedule_t *ms, const uint8_t *data) {
  // 64 bits (8 bytes) swap masks
  vec_t shuf_mask =
      _mm_setr_epi32(0x04050607, 0x00010203, 0x0c0d0e0f, 0x08090a0b);

  PRAGMA_UNROLL_8

  for (size_t i = 0; i < MS_VEC_NUM; i++) {
    const size_t pos = WORDS_IN_VEC * i;

    x[i] = LOAD(&data[sizeof(vec_t) * i]);
    x[i] = SHUF8(x[i], shuf_mask);
    STORE(&ms->w[pos], ADD64(x[i], LOAD(&K512[pos])));
  }
}

static inline __attribute__((always_inline)) void
rounds_0_63(sha512_state_t *cur_state, vec_t x[MS_VEC_NUM],
            sha512_msg_schedule_t *ms) {
  // The first SHA512_BLOCK_WORDS_NUM entries of K512 were loaded in
  // load_data(...).
  size_t k512_idx = SHA512_N_BLOCK_WORDS;

  // Rounds 0-63 (0-15, 16-31, 32-47, 48-63)
  for (size_t i = 0; i < 4; i++) {

    PRAGMA_UNROLL_8

    for (size_t j = 0; j < MS_VEC_NUM; j++) {
      const size_t pos = WORDS_IN_VEC * j;

      const vec_t y = sha512_update_x_avx(x, &K512[k512_idx]);

      sha_round(cur_state, ms->w[pos], 0);
      sha_round(cur_state, ms->w[pos + 1], 0);

      STORE(&ms->w[pos], y);
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

void sha512_compress_x86_64_avx(sha512_state_t *state, const uint8_t *data,
                                size_t blocks_num) {
  sha512_state_t cur_state;
  sha512_msg_schedule_t ms;
  vec_t x[MS_VEC_NUM];

  while (blocks_num--) {
    crypt_memcpy(cur_state.w, state->w, sizeof(cur_state.w));

    load_data(x, &ms, data);
    data += SHA512_BLOCK_SIZE_BYTES;

    rounds_0_63(&cur_state, x, &ms);
    rounds_64_79(&cur_state, &ms);
    accumulate_state(state, &cur_state);
  }

  memzero(&cur_state, sizeof(cur_state));
  memzero(&ms, sizeof(ms));
}
