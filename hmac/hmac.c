#include "hmac.h"
#include "common/defines.h"

#include <stdlib.h>

#define BYTE_LEN(bits) ((bits) / 8)

/** Table 2 */
static const int hash_method_size[][3] = {
    [DIGEST_SHA224] = {BYTE_LEN(512), BYTE_LEN(256), BYTE_LEN(224)},
    [DIGEST_SHA256] = {BYTE_LEN(512), BYTE_LEN(256), BYTE_LEN(256)},
    [DIGEST_SHA384] = {BYTE_LEN(1024), BYTE_LEN(512), BYTE_LEN(384)},
    [DIGEST_SHA512] = {BYTE_LEN(1024), BYTE_LEN(512), BYTE_LEN(512)},
    [DIGEST_SHA512_224] = {BYTE_LEN(1024), BYTE_LEN(512), BYTE_LEN(224)},
    [DIGEST_SHA512_256] = {BYTE_LEN(1024), BYTE_LEN(512), BYTE_LEN(256)},
    [DIGEST_SHA3_224] = {BYTE_LEN(1152), BYTE_LEN(1152), BYTE_LEN(224)},
    [DIGEST_SHA3_256] = {BYTE_LEN(1088), BYTE_LEN(1088), BYTE_LEN(256)},
    [DIGEST_SHA3_384] = {BYTE_LEN(832), BYTE_LEN(832), BYTE_LEN(384)},
    [DIGEST_SHA3_512] = {BYTE_LEN(576), BYTE_LEN(576), BYTE_LEN(512)}};

#define CHECK(cond)                                                            \
  do {                                                                         \
    if (ret = (cond))                                                          \
      goto cleanup;                                                            \
  } while (0)

int hmac(digest_method_t *digest_method, const uint8_t *key, size_t key_len,
         const uint8_t *data, size_t data_len, uint8_t *digest,
         size_t *digest_len) {
  int ret = 0;
  uint8_t *k0, *ipad, *opad;
  size_t B, L, alloc_len;
  void *hctx;

  if (!digest_method)
    return -1;

  // Key can be null but not null with non-zero length
  if (!key && key_len)
    return -1;

  if (!data || !data_len)
    return -1;

  if (digest_len)
    *digest_len = hash_method_size[digest_method->type][2];

  // Allow passing null pointer to query the digest length
  if (!digest)
    return 0;

  B = hash_method_size[digest_method->type][0];
  L = hash_method_size[digest_method->type][2];
  alloc_len = MAX(B, L);

  k0 = calloc(1, B);
  if (!k0)
    return -1;
  ipad = calloc(1, alloc_len);
  if (!ipad) {
    free(k0);
    return -1;
  }
  opad = calloc(1, alloc_len);
  if (!opad) {
    free(k0);
    free(ipad);
    return -1;
  }

  hctx = digest_method->ctx;
  /** Key processing */
  if (key_len > B) {
    CHECK(digest_method->reset(hctx));
    CHECK(digest_method->update(hctx, key, key_len));
    CHECK(digest_method->final(hctx, k0));
  } else {
    crypt_memcpy(k0, key, key_len);
  }

  /** Output tag generation */
  crypt_memset(ipad, 0x36, B);
  crypt_memset(opad, 0x5c, B);
  for (size_t i = 0; i < B; i++) {
    ipad[i] ^= k0[i];
    opad[i] ^= k0[i];
  }

  // ipad = H(ipad || data)
  CHECK(digest_method->reset(hctx));
  CHECK(digest_method->update(hctx, ipad, B));
  if (data_len > 0)
    CHECK(digest_method->update(hctx, data, data_len));
  CHECK(digest_method->final(hctx, ipad));

  // opad = H(opad || ipad)
  CHECK(digest_method->reset(hctx));
  CHECK(digest_method->update(hctx, opad, B));
  CHECK(digest_method->update(hctx, ipad, L));
  CHECK(digest_method->final(hctx, opad));

  crypt_memcpy(digest, opad, L);

cleanup:
  (void)digest_method->reset(hctx);
  memzero(k0, B);
  memzero(ipad, alloc_len);
  memzero(opad, alloc_len);
  free(k0);
  free(ipad);
  free(opad);
  return ret;
}

#if defined(HMAC_KATS)
#include "common/test_utils.h"
#include "sha512/sha512.h"

/**
 * Test vectors imported from https://datatracker.ietf.org/doc/html/rfc4231.
 * Note: tests will be added as and when required.
 */
void test_hmac_sha512() {
  sha512_digest_t ctx;
  digest_method_t sha512 = {.ctx = &ctx,
                            .type = DIGEST_SHA512,
                            .init = sha512_init,
                            .update = sha512_update,
                            .final = sha512_final,
                            .reset = sha512_reset};
  uint8_t k[131], data[50], buf[MAX_HMAC_SIZE], digest[MAX_HMAC_SIZE];

  // Test case #1
  read_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", k, 20);
  read_hex("87aa7cdea5ef619d4ff0b4241a1d6cb0"
           "2379f4e2ce4ec2787ad0b30545e17cde"
           "daa833b7d6b8a702038b274eaea3f4e4"
           "be9d914eeb61f1702e696c203a126854",
           digest, 64);
  assert(!hmac(&sha512, k, 20, (uint8_t *)"Hi There", 8, buf, NULL));
  assert(!memcmp(digest, buf, 64));

  // Test case #2
  read_hex("4a656665", k, 4);
  read_hex("164b7a7bfcf819e2e395fbe73b56e0a3"
           "87bd64222e831fd610270cd7ea250554"
           "9758bf75c05a994a6d034f65f8f0e6fd"
           "caeab1a34d4a6b4b636e070a38bce737",
           digest, 64);
  assert(!hmac(&sha512, k, 4,
               (uint8_t *)"what do ya want "
                          "for nothing?",
               28, buf, NULL));
  assert(!memcmp(digest, buf, 64));

  // Test case #3
  read_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", k, 20);
  read_hex("dddddddddddddddddddddddddddddddd"
           "dddddddddddddddddddddddddddddddd"
           "dddddddddddddddddddddddddddddddd"
           "dddd",
           data, 50);
  read_hex("fa73b0089d56a284efb0f0756c890be9"
           "b1b5dbdd8ee81a3655f83e33b2279d39"
           "bf3e848279a722c806b485a47e67c807"
           "b946a337bee8942674278859e13292fb",
           digest, 64);
  assert(!hmac(&sha512, k, 20, data, 50, buf, NULL));
  assert(!memcmp(digest, buf, 64));

  // Test case #4
  read_hex("0102030405060708090a0b0c0d0e0f10111213141516171819", k, 25);
  read_hex("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
           "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
           "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
           "cdcd",
           data, 50);
  read_hex("b0ba465637458c6990e5a8c5f61d4af7"
           "e576d97ff94b872de76f8050361ee3db"
           "a91ca5c11aa25eb4d679275cc5788063"
           "a5f19741120c4f2de2adebeb10a298dd",
           digest, 64);
  assert(!hmac(&sha512, k, 25, data, 50, buf, NULL));
  assert(!memcmp(digest, buf, 64));

  // Test case #5
  read_hex("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", k, 20);
  read_hex("415fad6271580a531d4179bc891d87a6", digest, 16);
  assert(!hmac(&sha512, k, 20,
               (uint8_t *)"Test With Trunca"
                          "tion",
               20, buf, NULL));
  assert(!memcmp(digest, buf, 16));

  // Test case #6
  read_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
           "aaaaaa",
           k, 131);
  read_hex("80b24263c7c1a3ebb71493c1dd7be8b4"
           "9b46d1f41b4aeec1121b013783f8f352"
           "6b56d037e05f2598bd0fd2215d6a1e52"
           "95e64f73f63f0aec8b915a985d786598",
           digest, 64);
  assert(!hmac(&sha512, k, 131,
               (uint8_t *)"Test Using Large"
                          "r Than Block-Siz"
                          "e Key - Hash Key"
                          " First",
               54, buf, NULL));
  assert(!memcmp(digest, buf, 64));

  // Test case #7
  // Same key as #6
  read_hex("e37b6a775dc87dbaa4dfa9f96e5e3ffd"
           "debd71f8867289865df5a32d20cdc944"
           "b6022cac3c4982b10d5eeb55c3e4de15"
           "134676fb6de0446065c97440fa8c6a58",
           digest, 64);
  assert(!hmac(&sha512, k, 131,
               (uint8_t *)"This is a test u"
                          "sing a larger th"
                          "an block-size ke"
                          "y and a larger t"
                          "han block-size d"
                          "ata. The key nee"
                          "ds to be hashed "
                          "before being use"
                          "d by the HMAC al"
                          "gorithm.",
               152, buf, NULL));
  assert(!memcmp(digest, buf, 64));

  printf("All tests passed\n");
}

int main() {
  test_hmac_sha512();
  return 0;
}

#endif // HMAC_KATS
