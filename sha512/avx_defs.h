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

#ifndef __AVX_DEFS_H__
#define __AVX_DEFS_H__

#include "avx_common.h"

#include <immintrin.h>

typedef __m128i vec_t;

#define LOAD(x) (_mm_loadu_si128((const __m128i *)x))
#define STORE(x, v) (_mm_store_si128((__m128i *)(x), v))
#define ADD64(x, y) (_mm_add_epi64(x, y))
#define SHUF8(x, mask) (_mm_shuffle_epi8(x, mask))
#define ALIGNR8(x, y, n) (_mm_alignr_epi8(x, y, n))
#define SRL64(x, n) (_mm_srli_epi64(x, n))
#define SLL64(x, n) (_mm_slli_epi64(x, n))
#define ROR64(x, n) (_mm_ror_epi64(x, n))

#endif // __AVX_DEFS_H__
