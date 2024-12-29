#pragma once

#include "common/defines.h"

#include <stdint.h>

#define MAX_HMAC_SIZE 64

int hmac(digest_method_t *digest_method, const uint8_t *key, size_t key_len,
         const uint8_t *data, size_t data_len, uint8_t *digest,
         size_t *digest_len);
