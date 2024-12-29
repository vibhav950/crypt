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

#ifndef __AVX512_DEFS_H__
#define __AVX512_DEFS_H__

#include "avx_common.h"

#include <immintrin.h>

typedef __m512i vec_t;

#define LOAD(x) (_mm512_loadu_si512((const __m512i *)x))
#define STORE(x, v) (_mm512_store_si512((__m512i *)(x), v))
#define ADD64(x, y) (_mm512_add_epi64(x, y))
#define SHUF8(x, mask) (_mm512_shuffle_epi8(x, mask))
#define ALIGNR8(x, y, n) (_mm512_alignr_epi8(x, y, n))
#define SRL64(x, n) (_mm512_srli_epi64(x, n))
#define SLL64(x, n) (_mm512_slli_epi64(x, n))
#define ROR64(x, n) (_mm512_ror_epi64(x, n))

#define STOREU4(mem3, mem2, mem1, mem0, reg)                                   \
  do {                                                                         \
    STORE128(mem0, _mm512_extracti32x4_epi32(reg, 0));                         \
    STORE128(mem1, _mm512_extracti32x4_epi32(reg, 1));                         \
    STORE128(mem2, _mm512_extracti32x4_epi32(reg, 2));                         \
    STORE128(mem3, _mm512_extracti32x4_epi32(reg, 3));                         \
  } while (0)

#define LOADU4(mem3, mem2, mem1, mem0, reg)                                    \
  do {                                                                         \
    (reg) = _mm512_inserti32x4(reg, LOAD128(mem0), 0);                         \
    (reg) = _mm512_inserti32x4(reg, LOAD128(mem1), 1);                         \
    (reg) = _mm512_inserti32x4(reg, LOAD128(mem2), 2);                         \
    (reg) = _mm512_inserti32x4(reg, LOAD128(mem3), 3);                         \
  } while (0)

#endif // __AVX512_DEFS_H__
