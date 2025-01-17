/**
 * mem.c - safer alternatives for common memory functions
 */

#include <stdint.h>

volatile void *crypt_memset(volatile void *mem, int ch, size_t len) {
  volatile char *p;

  if (!mem)
    return NULL;
  for (p = (volatile char *)mem; len; p[--len] = ch)
    ;
  return mem;
}

volatile void *crypt_memzero(volatile void *mem, size_t len) {
  volatile char *p;

  if (!mem)
    return NULL;
  for (p = (volatile char *)mem; len; p[--len] = 0x00)
    ;
  return mem;
}

volatile void *crypt_memcpy(volatile void *dst, volatile void *src,
                            size_t len) {
  volatile char *cdst, *csrc;

  if (!dst || !src)
    return NULL;
  cdst = (volatile char *)dst;
  csrc = (volatile char *)src;
  while (len--)
    cdst[len] = csrc[len];
  return dst;
}

volatile void *crypt_memmove(volatile void *dst, volatile void *src,
                             size_t len) {
  size_t i;
  volatile char *cdst, *csrc;

  if (!dst || !src)
    return NULL;
  cdst = (volatile char *)dst;
  csrc = (volatile char *)src;
  if (csrc > cdst && csrc < cdst + len) {
    for (i = 0; i < len; i++)
      cdst[i] = csrc[i];
  } else {
    while (len--)
      cdst[len] = csrc[len];
  }
  return dst;
}

/* Returns zero if a[0:len-1] == b[0:len-1], otherwise non-zero. */
unsigned int crypt_memcmp(const void *a, const void *b, size_t len) {
  unsigned int res = 0;
  const char *pa, *pb;

  if (!a || !b)
    return 1;
  pa = (const char *)a;
  pb = (const char *)b;
  for (; len; res |= pa[len] ^ pb[len], len--)
    ;
  return res;
}

/* Returns zero if the strings are equal, otherwise non-zero.

  Note: To avoid leaking the length of a secret string, use x
  as the private string and str as the provided string.

  Thanks to John's blog:
  https://nachtimwald.com/2017/04/02/constant-time-string-comparison-in-c/
*/
unsigned int crypt_strcmp(const char *str, const char *x) {
  unsigned int res = 0;
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
