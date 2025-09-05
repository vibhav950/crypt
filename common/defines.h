#pragma once

#include "memzero.h"

#include <stddef.h>
#include <stdint.h>

#undef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))

#undef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define COUNTOF(x) (sizeof(x) / sizeof((x)[0]))

void *crypt_memset(void *mem, int ch, size_t len);
void *crypt_memzero(void *mem, size_t len);
void *crypt_memcpy(void *dst, const void *src, size_t len);
void *crypt_memmove(void *dst, const void *src, size_t len);
int crypt_memcmp(const void *a, const void *b, size_t len);
int crypt_strcmp(const char *str, const char *x);

#if defined(__GNUC__)
#define ALIGN(N) __attribute__((aligned(N)))
#elif defined(_MSC_VER)
#define ALIGN(N) __declspec(align(N))
#else
#define ALIGN(N)
#endif

#define PTRV(ptr) ((void *)(ptr))
#define PTR8(ptr) ((uint8_t *)(ptr))
#define PTR16(ptr) ((uint16_t *)(ptr))
#define PTR32(ptr) ((uint32_t *)(ptr))
#define PTR64(ptr) ((uint64_t *)(ptr))

#if defined(__GNUC__) && !defined(__clang__)
#define PRAGMA_UNROLL_8 _Pragma("GCC unroll 8")
#define PRAGMA_UNROLL_16 _Pragma("GCC unroll 16")
#define PRAGMA_UNROLL_24 _Pragma("GCC unroll 24")
#define PRAGMA_UNROLL_32 _Pragma("GCC unroll 32")
#define PRAGMA_UNROLL_48 _Pragma("GCC unroll 48")
#define PRAGMA_UNROLL_64 _Pragma("GCC unroll 64")
#define PRAGMA_UNROLL_80 _Pragma("GCC unroll 80")
#elif defined(__clang__)
#define PRAGMA_UNROLL_8 _Pragma("unroll")
#define PRAGMA_UNROLL_16 _Pragma("unroll")
#define PRAGMA_UNROLL_24 _Pragma("unroll")
#define PRAGMA_UNROLL_32 _Pragma("unroll")
#define PRAGMA_UNROLL_48 _Pragma("unroll")
#define PRAGMA_UNROLL_64 _Pragma("unroll")
#define PRAGMA_UNROLL_80 _Pragma("unroll")
#else
#define PRAGMA_UNROLL_8
#define PRAGMA_UNROLL_16
#define PRAGMA_UNROLL_24
#define PRAGMA_UNROLL_32
#define PRAGMA_UNROLL_48
#define PRAGMA_UNROLL_64
#define PRAGMA_UNROLL_80
#endif

#include "endianness.h"

#define BSWAP16(x) bswap16(x)
#define BSWAP32(x) bswap32(x)
#define BSWAP64(x) bswap64(x)

#if defined(_MSC_VER)
#include <intrin.h>
#include <stdlib.h>
#define ROTL8(x, s) _rotl8((x), (s))
#define ROTL16(x, s) _rotl16((x), (s))
#define ROTL32(x, s) _rotl((x), (s))
#define ROTL64(x, s) _rotl64((x), (s))
#define ROTR8(x, s) _rotr8((x), (s))
#define ROTR16(x, s) _rotr16((x), (s))
#define ROTR32(x, s) _rotr((x), (s))
#define ROTR64(x, s) _rotr64((x), (s))
#else
#define ROTL8(x, s) (((uint8_t)(x) << (s)) | ((uint8_t)(x) >> (8 - (s))))
#define ROTL16(x, s) (((uint16_t)(x) << (s)) | ((uint16_t)(x) >> (16 - (s))))
#define ROTL32(x, s) (((uint32_t)(x) << (s)) | ((uint32_t)(x) >> (32 - (s))))
#define ROTL64(x, s) (((uint64_t)(x) << (s)) | ((uint64_t)(x) >> (64 - (s))))
#define ROTR8(x, s) (((uint8_t)(x) >> (s)) | ((uint8_t)(x) << (8 - (s))))
#define ROTR16(x, s) (((uint16_t)(x) >> (s)) | ((uint16_t)(x) << (16 - (s))))
#define ROTR32(x, s) (((uint32_t)(x) >> (s)) | ((uint32_t)(x) << (32 - (s))))
#define ROTR64(x, s) (((uint64_t)(x) >> (s)) | ((uint64_t)(x) << (64 - (s))))
#endif

typedef enum {
  DIGEST_SHA224 = 0,
  DIGEST_SHA256,
  DIGEST_SHA384,
  DIGEST_SHA512,
  DIGEST_SHA512_224,
  DIGEST_SHA512_256,
  DIGEST_SHA3_224,
  DIGEST_SHA3_256,
  DIGEST_SHA3_384,
  DIGEST_SHA3_512
} digest_type_t;

typedef int (*digest_init_t)(void *ctx);
typedef int (*digest_update_t)(void *ctx, const uint8_t *data, size_t len);
typedef int (*digest_final_t)(void *ctx, uint8_t *digest);
typedef int (*digest_reset_t)(void *ctx);

typedef struct {
  digest_type_t type;
  size_t digest_len;
  void *ctx;
  digest_init_t init;
  digest_update_t update;
  digest_final_t final;
  digest_reset_t reset;
} digest_method_t;
