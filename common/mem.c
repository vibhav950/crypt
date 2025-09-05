/**
 * mem.c - safer alternatives for common memory functions
 */

#include "defines.h"
#include <string.h>

typedef void *(*memset_t)(void *, int, size_t);
static volatile memset_t memset_func = memset;

void *crypt_memset(void *mem, int ch, size_t len) {
  volatile char *p;

  if (mem == NULL)
    return NULL;
  memset_func(mem, ch, len);
  return mem;
}

void *crypt_memzero(void *mem, size_t len) {
  volatile char *p;

  if (mem == NULL)
    return NULL;
  memset_func(mem, 0, len);
  return mem;
}

void *crypt_memcpy(void *dst, const void *src, size_t len) {
  return memcpy(dst, src, len);
}

void *crypt_memmove(void *dst, const void *src, size_t len) {
  return memmove(dst, src, len);
}

/* Returns zero if a[0:len-1] == b[0:len-1], otherwise non-zero. */
int crypt_memcmp(const void *a, const void *b, size_t len) {
  unsigned char res = 0;
  const volatile unsigned char *ca = (const volatile unsigned char *)a;
  const volatile unsigned char *cb = (const volatile unsigned char *)b;

  for (; len; --len, res |= ca[len] ^ cb[len])
    ;
  return res;
}

/* Returns zero if the strings are equal, otherwise non-zero.

  Note: To avoid leaking the length of a secret string, use x
  as the private string and str as the provided string.

  Thanks to John's blog:
  https://nachtimwald.com/2017/04/02/constant-time-string-comparison-in-c/
*/
int crypt_strcmp(const char *str, const char *x) {
  int res = 0;
  volatile size_t i, j, k;

  if (!str || !x)
    return 1;
  i = j = k = 0;
  for (;;) {
    res |= str[i] ^ x[j];
    if (str[i] == '\0')
      break;
    i++;
    if (x[j] != '\0')
      j++;
    if (x[j] == '\0')
      k++;
  }
  return res;
}
