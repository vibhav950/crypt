/**
 * \file aes_core.h
 * \brief Function prototypes and defines for core AES operations.
 *
 * \author vibhav950 on GitHub
 */

#ifndef __AES_CORE_H__
#define __AES_CORE_H__

#include <stdint.h>

#if !defined(ALIGN16)
#if defined(__GNUC__)
#define ALIGN16 __attribute__((aligned(16)))
#else
#define ALIGN16 __declspec(align(16))
#endif
#endif

/** Supported key sizes */
#define AES128
#define AES192
#define AES256

/** AES key sizes */
#define AES128_KEY_SIZE 16U
#define AES192_KEY_SIZE 24U
#define AES256_KEY_SIZE 32U

#define AES_MAX_KEY_SIZE 32U

/** AES cipher block size */
#define AES_BLOCK_SIZE 16U

/** AES rounds per key size */
#define AES128_ROUNDS 10U
#define AES192_ROUNDS 12U
#define AES256_ROUNDS 14U

#define AES_MAX_ROUNDS 14U

typedef struct _aes_key_st {
  ALIGN16 uint32_t k[AES_MAX_KEY_SIZE / 4];
  int bits;
} aes_key;

typedef struct _aes_ks_st {
  ALIGN16 uint32_t rk[4 * (AES_MAX_ROUNDS + 1)];
  int nr;
} aes_ks;

int aesni_set_encrypt_ks(const aes_key *key, aes_ks *ks, int bits);

int aesni_set_decrypt_ks(const aes_key *key, aes_ks *ks, int bits);

/** To avoid wasting a copy, we allow \p in and \p out to overlap. */
void aesni_block_encr(uint8_t *in, uint8_t *out, const aes_ks *ks);

/** To avoid wasting a copy, we allow \p in and \p out to overlap. */
void aesni_block_decr(uint8_t *in, uint8_t *out, const aes_ks *ks);

void aesni_ecb_encr(const uint8_t *in, uint8_t *out, unsigned int len,
                    const aes_ks *ks);

void aesni_ecb_decr(const uint8_t *in, uint8_t *out, unsigned int len,
                    const aes_ks *ks);

void aesni_cbc_decr(const uint8_t *in, uint8_t *out, unsigned int len,
                    const aes_ks *ks, const uint8_t ivec[AES_BLOCK_SIZE]);

void aesni_cbc_decr(const uint8_t *in, uint8_t *out, unsigned int len,
                    const aes_ks *ks, const uint8_t ivec[AES_BLOCK_SIZE]);

void __aesni_ctr128_encr(const uint8_t *in, uint8_t *out, unsigned int len,
                         const aes_ks *ks, const uint8_t ctr[AES_BLOCK_SIZE]);

#define aesni_ctr_encr(in, out, len, ks, ctr)                                  \
  __aesni_ctr128_encr(in, out, len, ks, ivec, nonce)

#define aesni_ctr_decr(in, out, len, ks, ctr)                                  \
  __aesni_ctr128_encr(in, out, len, ks, ctr)

#endif /* __AES_CORE_H__ */
