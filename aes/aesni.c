/**
 * aesni.c
 *
 * AES encryption using Intel AES-NI instruction set.
 *
 * Based on the White Paper by Shay Gueron titled
 * 'Intel Advanced Encryption Standard (AES) Instruction Set'.
 *
 * Modified by vibhav950 on GitHub.
 */

#include "aes_core.h"

#include <immintrin.h>

static inline __m128i __attribute__((always_inline))
KEY_128_ASSIST(__m128i temp1, __m128i temp2) {
  __m128i temp3;
  temp2 = _mm_shuffle_epi32(temp2, 0xff);
  temp3 = _mm_slli_si128(temp1, 0x04);
  temp1 = _mm_xor_si128(temp1, temp3);
  temp3 = _mm_slli_si128(temp3, 0x04);
  temp1 = _mm_xor_si128(temp1, temp3);
  temp3 = _mm_slli_si128(temp3, 0x04);
  temp1 = _mm_xor_si128(temp1, temp3);
  temp1 = _mm_xor_si128(temp1, temp2);
  return temp1;
}

static inline void __attribute__((always_inline))
KEY_192_ASSIST(__m128i *temp1, __m128i *temp2, __m128i *temp3) {
  __m128i temp4;
  *temp2 = _mm_shuffle_epi32(*temp2, 0x55);
  temp4 = _mm_slli_si128(*temp1, 0x04);
  *temp1 = _mm_xor_si128(*temp1, temp4);
  temp4 = _mm_slli_si128(temp4, 0x04);
  *temp1 = _mm_xor_si128(*temp1, temp4);
  temp4 = _mm_slli_si128(temp4, 0x04);
  *temp1 = _mm_xor_si128(*temp1, temp4);
  *temp1 = _mm_xor_si128(*temp1, *temp2);
  *temp2 = _mm_shuffle_epi32(*temp1, 0xff);
  temp4 = _mm_slli_si128(*temp3, 0x04);
  *temp3 = _mm_xor_si128(*temp3, temp4);
  *temp3 = _mm_xor_si128(*temp3, *temp2);
}

static inline void __attribute__((always_inline))
KEY_256_ASSIST_1(__m128i *temp1, __m128i *temp2) {
  __m128i temp4;
  *temp2 = _mm_shuffle_epi32(*temp2, 0xff);
  temp4 = _mm_slli_si128(*temp1, 0x04);
  *temp1 = _mm_xor_si128(*temp1, temp4);
  temp4 = _mm_slli_si128(temp4, 0x04);
  *temp1 = _mm_xor_si128(*temp1, temp4);
  temp4 = _mm_slli_si128(temp4, 0x04);
  *temp1 = _mm_xor_si128(*temp1, temp4);
  *temp1 = _mm_xor_si128(*temp1, *temp2);
}

static inline void __attribute__((always_inline))
KEY_256_ASSIST_2(__m128i *temp1, __m128i *temp3) {
  __m128i temp2, temp4;
  temp4 = _mm_aeskeygenassist_si128(*temp1, 0x0);
  temp2 = _mm_shuffle_epi32(temp4, 0xaa);
  temp4 = _mm_slli_si128(*temp3, 0x04);
  *temp3 = _mm_xor_si128(*temp3, temp4);
  temp4 = _mm_slli_si128(temp4, 0x04);
  *temp3 = _mm_xor_si128(*temp3, temp4);
  temp4 = _mm_slli_si128(temp4, 0x04);
  *temp3 = _mm_xor_si128(*temp3, temp4);
  *temp3 = _mm_xor_si128(*temp3, temp2);
}

static void aes128_expand_key(const aes_key *key, aes_ks *ks) {
  const __m128i *k = (const __m128i *)key->k;
  __m128i temp1, temp2;
  __m128i *Key_Schedule = (__m128i *)ks->rk;
  temp1 = _mm_loadu_si128(k);
  Key_Schedule[0] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x01);
  temp1 = KEY_128_ASSIST(temp1, temp2);
  Key_Schedule[1] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x02);
  temp1 = KEY_128_ASSIST(temp1, temp2);
  Key_Schedule[2] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x04);
  temp1 = KEY_128_ASSIST(temp1, temp2);
  Key_Schedule[3] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x08);
  temp1 = KEY_128_ASSIST(temp1, temp2);
  Key_Schedule[4] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x10);
  temp1 = KEY_128_ASSIST(temp1, temp2);
  Key_Schedule[5] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x20);
  temp1 = KEY_128_ASSIST(temp1, temp2);
  Key_Schedule[6] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x40);
  temp1 = KEY_128_ASSIST(temp1, temp2);
  Key_Schedule[7] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x80);
  temp1 = KEY_128_ASSIST(temp1, temp2);
  Key_Schedule[8] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x1b);
  temp1 = KEY_128_ASSIST(temp1, temp2);
  Key_Schedule[9] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x36);
  temp1 = KEY_128_ASSIST(temp1, temp2);
  Key_Schedule[10] = temp1;
  _mm256_zeroall();
}

static void aes192_expand_key(const aes_key *key, aes_ks *ks) {
  const uint8_t *k = (const uint8_t *)key->k;
  __m128i temp1, temp2, temp3, temp4;
  __m128i *Key_Schedule = (__m128i *)ks->rk;
  temp1 = _mm_loadu_si128((const __m128i *)k);
  temp3 = _mm_loadu_si128((const __m128i *)(k + 16));
  Key_Schedule[0] = temp1;
  Key_Schedule[1] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x01);
  KEY_192_ASSIST(&temp1, &temp2, &temp3);
  Key_Schedule[1] =
      (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[1], (__m128d)temp1, 0);
  Key_Schedule[2] = (__m128i)_mm_shuffle_pd((__m128d)temp1, (__m128d)temp3, 1);
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x02);
  KEY_192_ASSIST(&temp1, &temp2, &temp3);
  Key_Schedule[3] = temp1;
  Key_Schedule[4] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x04);
  KEY_192_ASSIST(&temp1, &temp2, &temp3);
  Key_Schedule[4] =
      (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[4], (__m128d)temp1, 0);
  Key_Schedule[5] = (__m128i)_mm_shuffle_pd((__m128d)temp1, (__m128d)temp3, 1);
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x08);
  KEY_192_ASSIST(&temp1, &temp2, &temp3);
  Key_Schedule[6] = temp1;
  Key_Schedule[7] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
  KEY_192_ASSIST(&temp1, &temp2, &temp3);
  Key_Schedule[7] =
      (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[7], (__m128d)temp1, 0);
  Key_Schedule[8] = (__m128i)_mm_shuffle_pd((__m128d)temp1, (__m128d)temp3, 1);
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
  KEY_192_ASSIST(&temp1, &temp2, &temp3);
  Key_Schedule[9] = temp1;
  Key_Schedule[10] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
  KEY_192_ASSIST(&temp1, &temp2, &temp3);
  Key_Schedule[10] =
      (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[10], (__m128d)temp1, 0);
  Key_Schedule[11] = (__m128i)_mm_shuffle_pd((__m128d)temp1, (__m128d)temp3, 1);
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x80);
  KEY_192_ASSIST(&temp1, &temp2, &temp3);
  Key_Schedule[12] = temp1;
}

static void aes256_expand_key(const aes_key *key, aes_ks *ks) {
  const uint8_t *k = (const uint8_t *)key->k;
  __m128i temp1, temp2, temp3;
  __m128i *Key_Schedule = (__m128i *)ks->rk;
  temp1 = _mm_loadu_si128((const __m128i *)k);
  temp3 = _mm_loadu_si128((const __m128i *)(k + 16));
  Key_Schedule[0] = temp1;
  Key_Schedule[1] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x01);
  KEY_256_ASSIST_1(&temp1, &temp2);
  Key_Schedule[2] = temp1;
  KEY_256_ASSIST_2(&temp1, &temp3);
  Key_Schedule[3] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x02);
  KEY_256_ASSIST_1(&temp1, &temp2);
  Key_Schedule[4] = temp1;
  KEY_256_ASSIST_2(&temp1, &temp3);
  Key_Schedule[5] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x04);
  KEY_256_ASSIST_1(&temp1, &temp2);
  Key_Schedule[6] = temp1;
  KEY_256_ASSIST_2(&temp1, &temp3);
  Key_Schedule[7] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x08);
  KEY_256_ASSIST_1(&temp1, &temp2);
  Key_Schedule[8] = temp1;
  KEY_256_ASSIST_2(&temp1, &temp3);
  Key_Schedule[9] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
  KEY_256_ASSIST_1(&temp1, &temp2);
  Key_Schedule[10] = temp1;
  KEY_256_ASSIST_2(&temp1, &temp3);
  Key_Schedule[11] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
  KEY_256_ASSIST_1(&temp1, &temp2);
  Key_Schedule[12] = temp1;
  KEY_256_ASSIST_2(&temp1, &temp3);
  Key_Schedule[13] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
  KEY_256_ASSIST_1(&temp1, &temp2);
  Key_Schedule[14] = temp1;
  _mm256_zeroall();
}

int aesni_set_encrypt_ks(const aes_key *key, aes_ks *ks, int bits) {
  if (!key || !ks)
    return -1;
  switch (bits) {
  case 128:
    aes128_expand_key(key, ks);
    ks->nr = 10;
    return 0;
  case 192:
    aes192_expand_key(key, ks);
    ks->nr = 12;
    return 0;
  case 256:
    aes256_expand_key(key, ks);
    ks->nr = 14;
    return 0;
  }
  return -2;
}

int aesni_set_decrypt_ks(const aes_key *key, aes_ks *ks, int bits) {
  int i, nr;
  aes_ks temp_ks;
  __m128i *Key_Schedule = (__m128i *)ks->rk;
  __m128i *Temp_Key_Schedule = (__m128i *)temp_ks.rk;
  if (!key || !ks)
    return -1;
  if (aesni_set_encrypt_ks(key, &temp_ks, bits) == -2)
    return -2;
  nr = temp_ks.nr;
  ks->nr = nr;
  Key_Schedule[nr] = Temp_Key_Schedule[0];
  Key_Schedule[nr - 1] = _mm_aesimc_si128(Temp_Key_Schedule[1]);
  Key_Schedule[nr - 2] = _mm_aesimc_si128(Temp_Key_Schedule[2]);
  Key_Schedule[nr - 3] = _mm_aesimc_si128(Temp_Key_Schedule[3]);
  Key_Schedule[nr - 4] = _mm_aesimc_si128(Temp_Key_Schedule[4]);
  Key_Schedule[nr - 5] = _mm_aesimc_si128(Temp_Key_Schedule[5]);
  Key_Schedule[nr - 6] = _mm_aesimc_si128(Temp_Key_Schedule[6]);
  Key_Schedule[nr - 7] = _mm_aesimc_si128(Temp_Key_Schedule[7]);
  Key_Schedule[nr - 8] = _mm_aesimc_si128(Temp_Key_Schedule[8]);
  Key_Schedule[nr - 9] = _mm_aesimc_si128(Temp_Key_Schedule[9]);
  if (nr > 10) {
    Key_Schedule[nr - 10] = _mm_aesimc_si128(Temp_Key_Schedule[10]);
    Key_Schedule[nr - 11] = _mm_aesimc_si128(Temp_Key_Schedule[11]);
  }
  if (nr > 12) {
    Key_Schedule[nr - 12] = _mm_aesimc_si128(Temp_Key_Schedule[12]);
    Key_Schedule[nr - 13] = _mm_aesimc_si128(Temp_Key_Schedule[13]);
  }
  Key_Schedule[0] = Temp_Key_Schedule[nr];
  _mm256_zeroall();
  return 0;
}

#define LOAD128(x) _mm_loadu_si128(x)
#define STORE128(x, y) _mm_storeu_si128(x, y)
#define SET32(a, b, c, d) _mm_set_epi32(a, b, c, d)
#define SHUF8(a, mask) _mm_shuffle_epi8(a, mask)
#define XOR128(x, y) _mm_xor_si128(x, y)
#define ADD32(a, b) _mm_add_epi32(a, b)
#define ZEROALL256 _mm256_zeroall

#define AESENC(x, y) _mm_aesenc_si128(x, y)
#define AESENCLAST(x, y) _mm_aesenclast_si128(x, y)
#define AESDEC(x, y) _mm_aesdec_si128(x, y)
#define AESDECLAST(x, y) _mm_aesdeclast_si128(x, y)

void aesni_ecb_encr(const uint8_t *in, uint8_t *out, unsigned int len,
                    const aes_ks *ks) {
  const __m128i *rk = (const __m128i *)ks->rk;
  const __m128i *invec = (const __m128i *)in;
  __m128i *outvec = (__m128i *)out;
  __m128i tmp;
  int i, j;
  if (len % 16)
    len = len / 16 + 1;
  else
    len = len / 16;
  for (i = 0; i < len; i++) {
    tmp = LOAD128(invec + i);
    tmp = XOR128(tmp, rk[0]);
    for (j = 1; j < ks->nr; j++) {
      tmp = AESENC(tmp, rk[j]);
    }
    tmp = AESENCLAST(tmp, rk[j]);
    STORE128(outvec + i, tmp);
  }
  ZEROALL256();
}

void aesni_ecb_decr(const uint8_t *in, uint8_t *out, unsigned int len,
                    const aes_ks *ks) {
  const __m128i *rk = (const __m128i *)ks->rk;
  const __m128i *invec = (const __m128i *)in;
  __m128i *outvec = (__m128i *)out;
  __m128i tmp;
  int i, j;
  if (len % 16)
    len = len / 16 + 1;
  else
    len = len / 16;
  for (i = 0; i < len; i++) {
    tmp = LOAD128(invec + i);
    tmp = XOR128(tmp, rk[0]);
    for (j = 1; j < ks->nr; j++) {
      tmp = AESDEC(tmp, rk[j]);
    }
    tmp = AESDECLAST(tmp, rk[j]);
    STORE128(outvec + i, tmp);
  }
  ZEROALL256();
}

void aes_cbc_encr(const uint8_t *in, uint8_t *out, unsigned int len,
                  const aes_ks *ks, const uint8_t ivec[AES_BLOCK_SIZE]) {
  const __m128i *rk = (const __m128i *)ks->rk;
  const __m128i *invec = (const __m128i *)in;
  __m128i *outvec = (__m128i *)out;
  __m128i feedback, data;
  int i, j;
  if (len % 16)
    len = len / 16 + 1;
  else
    len /= 16;
  feedback = LOAD128((const __m128i *)ivec);
  for (i = 0; i < len; i++) {
    data = LOAD128(invec + i);
    feedback = XOR128(data, feedback);
    feedback = XOR128(feedback, rk[0]);
    for (j = 1; j < ks->nr; j++)
      feedback = AESENC(feedback, rk[j]);
    feedback = AESENCLAST(feedback, rk[j]);
    STORE128(outvec + i, feedback);
  }
  ZEROALL256();
}

void aesni_cbc_decr(const uint8_t *in, uint8_t *out, unsigned int len,
                    const aes_ks *ks, const uint8_t ivec[AES_BLOCK_SIZE]) {
  const __m128i *rk = (const __m128i *)ks->rk;
  const __m128i *invec = (const __m128i *)in;
  __m128i *outvec = (__m128i *)out;
  __m128i data, feedback, last_in;
  int i, j;
  if (len % 16)
    len = len / 16 + 1;
  else
    len /= 16;
  feedback = LOAD128((const __m128i *)ivec);
  for (i = 0; i < len; i++) {
    last_in = LOAD128(invec + i);
    data = XOR128(last_in, rk[0]);
    for (j = 1; j < ks->nr; j++) {
      data = AESDEC(data, rk[j]);
    }
    data = AESDECLAST(data, rk[j]);
    data = XOR128(data, feedback);
    STORE128(outvec + i, data);
    feedback = last_in;
  }
  ZEROALL256();
}

void __aesni_ctr128_encr(const uint8_t *in, uint8_t *out, unsigned int len,
                         const aes_ks *ks, const uint8_t ctr[AES_BLOCK_SIZE]) {
  const __m128i *rk = (const __m128i *)ks->rk;
  const __m128i *invec = (const __m128i *)in;
  __m128i *outvec = (__m128i *)out;
  __m128i counter_be, counter_le, ONE, BSWAP_EPI32;
  int i, j;
  if (len % 16)
    len = len / 16 + 1;
  else
    len /= 16;
  ONE = SET32(0, 0, 0, 1);
  BSWAP_EPI32 = SET32(0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f);
  counter_be = LOAD128((const __m128i *)ctr);
  counter_le = SHUF8(counter_be, BSWAP_EPI32);
  for (i = 0; i < len; i++) {
    counter_be = SHUF8(counter_le, BSWAP_EPI32);
    counter_le = ADD32(counter_le, ONE);
    counter_be = XOR128(counter_be, rk[0]);
    for (j = 1; j < ks->nr; j++) {
      counter_be = AESENC(counter_be, rk[j]);
    }
    counter_be = AESENCLAST(counter_be, rk[j]);
    counter_be = XOR128(counter_be, LOAD128(invec + i));
    STORE128(outvec + i, counter_be);
  }
  ZEROALL256();
}

#ifdef AESNI_TEST_VECS
#include <assert.h>
#include <stdio.h>
#include <strings.h>

static void read_hex(const char *hex, uint8_t *buf, const uint32_t len) {
  uint32_t i, value;

  for (i = 0; i < len; ++i) {
    sscanf(hex + 2 * i, "%02x", &value);
    buf[i] = (uint8_t)value;
  }
}

/**
 * Test vectors obtained from NIST SP 800-38A (2001 ed.)
 * https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
 */

static void test_aesni_ecb() {
  aes_ks ks;
  aes_key key;
  uint8_t plaintext[64], ciphertext[64], buf[64];

  read_hex("6bc1bee22e409f96e93d7e117393172a"  // Block #1
           "ae2d8a571e03ac9c9eb76fac45af8e51"  // Block #2
           "30c81c46a35ce411e5fbc1191a0a52ef"  // Block #3
           "f69f2445df4f9b17ad2b417be66c3710", // Block #4
           plaintext, 64);

  /* F.1.1 ECB-AES128.Encrypt */
  read_hex("2b7e151628aed2a6abf7158809cf4f3c", (uint8_t *)key.k, 16);
  read_hex("3ad77bb40d7a3660a89ecaf32466ef97"  // Block #1
           "f5d3d58503b9699de785895a96fdbaaf"  // Block #2
           "43b1cd7f598ece23881b00e3ed030688"  // Block #3
           "7b0c785e27e8ad3f8223207104725dd4", // Block #4
           ciphertext, 64);

  aesni_set_encrypt_ks(&key, &ks, 128);
  aesni_ecb_encr(plaintext, buf, 64, &ks);
  assert(!memcmp(ciphertext, buf, 64));

  /* F.1.2 ECB-AES128.Decrypt */
  aesni_set_decrypt_ks(&key, &ks, 128);
  aesni_ecb_decr(ciphertext, buf, 64, &ks);
  assert(!memcmp(plaintext, buf, 64));

  /* F.1.3 ECB-AES192.Encrypt */
  read_hex("8e73b0f7da0e6452c810f32b809079e5"
           "62f8ead2522c6b7b",
           (uint8_t *)key.k, 24);
  read_hex("bd334f1d6e45f25ff712a214571fa5cc"  // Block #1
           "974104846d0ad3ad7734ecb3ecee4eef"  // Block #2
           "ef7afd2270e2e60adce0ba2face6444e"  // Block #3
           "9a4b41ba738d6c72fb16691603c18e0e", // Block #4
           ciphertext, 64);

  aesni_set_encrypt_ks(&key, &ks, 192);
  aesni_ecb_encr(plaintext, buf, 64, &ks);
  assert(!memcmp(ciphertext, buf, 64));

  /* F.1.4 ECB-AES192.Decrypt */
  aesni_set_decrypt_ks(&key, &ks, 192);
  aesni_ecb_decr(ciphertext, buf, 64, &ks);
  assert(!memcmp(plaintext, buf, 64));

  /* ECB-AES256.Encrypt */
  read_hex("603deb1015ca71be2b73aef0857d7781"
           "1f352c073b6108d72d9810a30914dff4",
           (uint8_t *)key.k, 32);
  read_hex("f3eed1bdb5d2a03c064b5a7e3db181f8"  // Block #1
           "591ccb10d410ed26dc5ba74a31362870"  // Block #2
           "b6ed21b99ca6f4f9f153e7b1beafed1d"  // Block #3
           "23304b7a39f9f3ff067d8d8f9e24ecc7", // Block #4
           ciphertext, 64);

  aesni_set_encrypt_ks(&key, &ks, 256);
  aesni_ecb_encr(plaintext, buf, 64, &ks);
  assert(!memcmp(ciphertext, buf, 64));

  /* F.1.6 ECB-AES256.Decrypt */
  aesni_set_decrypt_ks(&key, &ks, 256);
  aesni_ecb_decr(ciphertext, buf, 64, &ks);
  assert(!memcmp(plaintext, buf, 64));
}

static void test_aesni_cbc() {
  aes_ks ks;
  aes_key key;
  uint8_t plaintext[64], ciphertext[64], buf[64], ivec[16];

  read_hex("6bc1bee22e409f96e93d7e117393172a"  // Block #1
           "ae2d8a571e03ac9c9eb76fac45af8e51"  // Block #2
           "30c81c46a35ce411e5fbc1191a0a52ef"  // Block #3
           "f69f2445df4f9b17ad2b417be66c3710", // Block #4
           plaintext, 64);
  read_hex("000102030405060708090a0b0c0d0e0f", ivec, 16);

  /* F.2.1 CBC-AES128.Encrypt */
  read_hex("2b7e151628aed2a6abf7158809cf4f3c", (uint8_t *)key.k, 16);
  read_hex("7649abac8119b246cee98e9b12e9197d"  // Block #1
           "5086cb9b507219ee95db113a917678b2"  // Block #2
           "73bed6b8e3c1743b7116e69e22229516"  // Block #3
           "3ff1caa1681fac09120eca307586e1a7", // Block #4
           ciphertext, 64);

  aesni_set_encrypt_ks(&key, &ks, 128);
  aes_cbc_encr(plaintext, buf, 64, &ks, ivec);
  assert(!memcmp(ciphertext, buf, 64));

  /* F.2.2 CBC-AES128.Decrypt */
  aesni_set_decrypt_ks(&key, &ks, 128);
  aesni_cbc_decr(ciphertext, buf, 64, &ks, ivec);
  assert(!memcmp(plaintext, buf, 64));

  /* F.2.3 CBC-AES192.Encrypt */
  read_hex("8e73b0f7da0e6452c810f32b809079e5"
           "62f8ead2522c6b7b",
           (uint8_t *)key.k, 24);
  read_hex("4f021db243bc633d7178183a9fa071e8"  // Block #1
           "b4d9ada9ad7dedf4e5e738763f69145a"  // Block #2
           "571b242012fb7ae07fa9baac3df102e0"  // Block #3
           "08b0e27988598881d920a9e64f5615cd", // Block #4
           ciphertext, 64);

  aesni_set_encrypt_ks(&key, &ks, 192);
  aes_cbc_encr(plaintext, buf, 64, &ks, ivec);
  assert(!memcmp(ciphertext, buf, 64));

  /* F.2.4 CBC-AES192.Decrypt */
  aesni_set_decrypt_ks(&key, &ks, 192);
  aesni_cbc_decr(ciphertext, buf, 64, &ks, ivec);
  assert(!memcmp(plaintext, buf, 64));

  /*F.2.5 CBC-AES256.Encrypt */
  read_hex("603deb1015ca71be2b73aef0857d7781"
           "1f352c073b6108d72d9810a30914dff4",
           (uint8_t *)key.k, 32);
  read_hex("f58c4c04d6e5f1ba779eabfb5f7bfbd6"  // Block #1
           "9cfc4e967edb808d679f777bc6702c7d"  // Block #2
           "39f23369a9d9bacfa530e26304231461"  // Block #3
           "b2eb05e2c39be9fcda6c19078c6a9d1b", // Block #4
           ciphertext, 64);

  aesni_set_encrypt_ks(&key, &ks, 256);
  aes_cbc_encr(plaintext, buf, 64, &ks, ivec);
  assert(!memcmp(ciphertext, buf, 64));

  /* F.2.6 CBC-AES256.Decrypt */
  aesni_set_decrypt_ks(&key, &ks, 256);
  aesni_cbc_decr(ciphertext, buf, 64, &ks, ivec);
  assert(!memcmp(plaintext, buf, 64));
}

static void test_aesni_ctr() {
  aes_ks ks;
  aes_key key;

  uint8_t plaintext[64], ciphertext[64], buf[64], counter[16];

  read_hex("6bc1bee22e409f96e93d7e117393172a"  // Block #1
           "ae2d8a571e03ac9c9eb76fac45af8e51"  // Block #2
           "30c81c46a35ce411e5fbc1191a0a52ef"  // Block #3
           "f69f2445df4f9b17ad2b417be66c3710", // Block #4
           plaintext, 64);
  read_hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", counter, 16);

  /* F.5.1 CTR-AES128.Encrypt */
  read_hex("2b7e151628aed2a6abf7158809cf4f3c", (uint8_t *)key.k, 16);
  read_hex("874d6191b620e3261bef6864990db6ce"  // Block #1
           "9806f66b7970fdff8617187bb9fffdff"  // Block #2
           "5ae4df3edbd5d35e5b4f09020db03eab"  // Block #3
           "1e031dda2fbe03d1792170a0f3009cee", // Block #4
           ciphertext, 64);

  aesni_set_encrypt_ks(&key, &ks, 128);
  __aesni_ctr128_encr(plaintext, buf, 64, &ks, counter);
  assert(!memcmp(ciphertext, buf, 64));

  /* F.5.2 CTR-AES128.Decrypt */
  __aesni_ctr128_encr(ciphertext, buf, 64, &ks, counter);
  assert(!memcmp(plaintext, buf, 64));

  /* F.5.3 CTR-AES192.Encrypt */
  read_hex("8e73b0f7da0e6452c810f32b809079e56"
           "2f8ead2522c6b7b",
           (uint8_t *)key.k, 24);
  read_hex("1abc932417521ca24f2b0459fe7e6e0b"  // Block #1
           "090339ec0aa6faefd5ccc2c6f4ce8e94"  // Block #2
           "1e36b26bd1ebc670d1bd1d665620abf7"  // Block #3
           "4f78a7f6d29809585a97daec58c6b050", // Block #4
           ciphertext, 64);

  aesni_set_encrypt_ks(&key, &ks, 192);
  __aesni_ctr128_encr(plaintext, buf, 64, &ks, counter);
  assert(!memcmp(ciphertext, buf, 64));

  /* F.5.4 CTR-AES192.Decrypt */
  __aesni_ctr128_encr(ciphertext, buf, 64, &ks, counter);
  assert(!memcmp(plaintext, buf, 64));

  /* F.5.5 CTR-AES256.Encrypt */
  read_hex("603deb1015ca71be2b73aef0857d7781"
           "1f352c073b6108d72d9810a30914dff4",
           (uint8_t *)key.k, 32);
  read_hex("601ec313775789a5b7a7f504bbf3d228"  // Block #1
           "f443e3ca4d62b59aca84e990cacaf5c5"  // Block #2
           "2b0930daa23de94ce87017ba2d84988d"  // Block #3
           "dfc9c58db67aada613c2dd08457941a6", // Block #4
           ciphertext, 64);

  aesni_set_encrypt_ks(&key, &ks, 256);
  __aesni_ctr128_encr(plaintext, buf, 64, &ks, counter);
  assert(!memcmp(ciphertext, buf, 64));

  /* F.5.6 CTR-AES256.Decrypt */
  __aesni_ctr128_encr(ciphertext, buf, 64, &ks, counter);
  assert(!memcmp(plaintext, buf, 64));
}

int main() {
  /* Test AES-ECB with key sizes 128, 192, and 256 */
  test_aesni_ecb();

  /* Test AES-CBC with key sizes 128, 192, and 256 */
  test_aesni_cbc();

  /* Test AES-CTR with key sizes 128, 192, and 256 */
  test_aesni_ctr();

  printf("All tests passed\n");
}

#endif /* AESNI_TEST_VECS */
