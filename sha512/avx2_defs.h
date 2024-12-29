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

#ifndef __AVX2_DEFS_H__
#define __AVX2_DEFS_H__

#include "avx_common.h"

#include <immintrin.h>

typedef __m256i vec_t;

#define LOAD(x) (_mm256_loadu_si256((const __m256i *)x))
#define STORE(x, v) (_mm256_store_si256((__m256i *)(x), v))
#define ADD64(x, y) (_mm256_add_epi64(x, y))
#define SHUF8(x, mask) (_mm256_shuffle_epi8(x, mask))
#define ALIGNR8(x, y, n) (_mm256_alignr_epi8(x, y, n))
#define SRL64(x, n) (_mm256_srli_epi64(x, n))
#define SLL64(x, n) (_mm256_slli_epi64(x, n))
#define ROR64(x, n) (_mm256_ror_epi64(x, n))

#define STOREU2(hi_mem, lo_mem, reg)                                           \
  do {                                                                         \
    STORE128(lo_mem, _mm256_extracti128_si256(reg, 0));                        \
    STORE128(hi_mem, _mm256_extracti128_si256(reg, 1));                        \
  } while (0)

#define LOADU2(hi_mem, lo_mem, reg)                                            \
  do {                                                                         \
    reg = _mm256_insertf128_si256(reg, LOAD128(hi_mem), 1);                    \
    reg = _mm256_insertf128_si256(x[i], LOAD128(lo_mem), 0);                   \
  } while (0)

#endif // __AVX2_DEFS_H__
