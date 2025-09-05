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

#include "sha512.h"
#include "common/defines.h"
#include "sha512_x64_internal.h"

#define U64(x) x##ULL

int sha512_init(sha512_digest_t *ctx) {
  if (!ctx)
    return -1;

  ctx->len = ctx->rem_len = 0;

  ctx->state.w[0] = U64(0x6a09e667f3bcc908);
  ctx->state.w[1] = U64(0xbb67ae8584caa73b);
  ctx->state.w[2] = U64(0x3c6ef372fe94f82b);
  ctx->state.w[3] = U64(0xa54ff53a5f1d36f1);
  ctx->state.w[4] = U64(0x510e527fade682d1);
  ctx->state.w[5] = U64(0x9b05688c2b3e6c1f);
  ctx->state.w[6] = U64(0x1f83d9abfb41bd6b);
  ctx->state.w[7] = U64(0x5be0cd19137e2179);

  return 0;
}

int sha512_update(sha512_digest_t *ctx, uint8_t *data, size_t len) {
  if (!ctx)
    return -1;

  if (len && !data)
    return -1;
  else if (!len)
    return 0;

  // Accumulate the overall size
  ctx->len += len;

  // Less than a block. Store the data in a temporary buffer
  if ((ctx->rem_len != 0) && (ctx->rem_len + len < SHA512_BLOCK_SIZE_BYTES)) {
    crypt_memcpy(&ctx->rem_data[ctx->rem_len], data, len);
    ctx->rem_len += len;
    return 0;
  }

  // Complete and compress a previously stored block
  if (ctx->rem_len != 0) {
    const size_t clen = SHA512_BLOCK_SIZE_BYTES - ctx->rem_len;
    crypt_memcpy(&ctx->rem_data[ctx->rem_len], data, clen);
    sha512_compress(&ctx->state, ctx->rem_data, 1);

    data += clen;
    len -= clen;

    ctx->rem_len = 0;
    memzero(ctx->rem_data, SHA512_BLOCK_SIZE_BYTES);
  }

  // Compress full blocks
  if (len >= SHA512_BLOCK_SIZE_BYTES) {
    const size_t blocks_num = (len >> 7);
    const size_t full_blocks_byte_len = (blocks_num << 7);

    sha512_compress(&ctx->state, data, blocks_num);

    data += full_blocks_byte_len;
    len -= full_blocks_byte_len;
  }

  // Store the reminder
  crypt_memcpy(ctx->rem_data, data, len);
  ctx->rem_len = len;
  return 0;
}

int sha512_final(sha512_digest_t *ctx, uint8_t *out) {
  if (!ctx || !out)
    return -1;

  // Sanity check
  if (ctx->rem_len >= SHA512_BLOCK_SIZE_BYTES)
    return -1;

  // Length of the message in bits as a 64-bit big-endian number
  uint64_t len_bits = BSWAP64(ctx->len << 3);

  // Append bit '1' to the message
  ctx->rem_data[ctx->rem_len++] = 0x80;

  if (ctx->rem_len > SHA512_BLOCK_SIZE_BYTES - 16) {
    crypt_memset(&ctx->rem_data[ctx->rem_len], 0,
                 SHA512_BLOCK_SIZE_BYTES - ctx->rem_len);

    sha512_compress(&ctx->state, ctx->rem_data, 1);

    crypt_memset(ctx->rem_data, 0, SHA512_BLOCK_SIZE_BYTES);
  } else {
    crypt_memset(&ctx->rem_data[ctx->rem_len], 0,
                 SHA512_BLOCK_SIZE_BYTES - ctx->rem_len - 16);
  }

  // Append the length in bits as a 128-bit big-endian number
  crypt_memset(&ctx->rem_data[SHA512_BLOCK_SIZE_BYTES - 16], 0, 8);
  crypt_memcpy(&ctx->rem_data[SHA512_BLOCK_SIZE_BYTES - 8], PTR8(&len_bits), 8);

  sha512_compress(&ctx->state, ctx->rem_data, 1);

  // Little-endian to big-endian
  ctx->state.w[0] = BSWAP64(ctx->state.w[0]);
  ctx->state.w[1] = BSWAP64(ctx->state.w[1]);
  ctx->state.w[2] = BSWAP64(ctx->state.w[2]);
  ctx->state.w[3] = BSWAP64(ctx->state.w[3]);
  ctx->state.w[4] = BSWAP64(ctx->state.w[4]);
  ctx->state.w[5] = BSWAP64(ctx->state.w[5]);
  ctx->state.w[6] = BSWAP64(ctx->state.w[6]);
  ctx->state.w[7] = BSWAP64(ctx->state.w[7]);
  crypt_memcpy(out, &ctx->state, SHA512_DIGEST_LEN);
  return 0;
}

int sha512_reset(sha512_digest_t *ctx) {
  if (!ctx)
    return -1;

  memzero(ctx, sizeof(sha512_digest_t));
  return sha512_init(ctx);
}
