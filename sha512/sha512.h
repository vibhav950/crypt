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

#ifndef __SHA512_H__
#define __SHA512_H__

#include "common/defines.h"
#include "sha512_x64_internal.h"

#define SHA512_DIGEST_LEN 64

typedef struct sha512_digest_t {
  ALIGN(64) sha512_state_t state;
  size_t len;
  ALIGN(64) uint8_t rem_data[SHA512_BLOCK_SIZE_BYTES];
  size_t rem_len;
} sha512_digest_t;

int sha512_init(sha512_digest_t *digest);

int sha512_update(sha512_digest_t *digest, uint8_t *data, size_t len);

int sha512_final(sha512_digest_t *digest, uint8_t *out);

int sha512_reset(sha512_digest_t *digest);

#endif // __SHA512_H__