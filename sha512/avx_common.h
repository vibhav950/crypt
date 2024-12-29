#ifndef __AVX_COMMON_H__
#define __AVX_COMMON_H__

#define LOAD128(x) (_mm_loadu_si128((const __m128i *)(x)))
#define STORE128(x, r) (_mm_store_si128((__m128i *)(x), r))

#define LSB1(x) ((x)&0x1)
#define LSB2(x) ((x)&0x3)
#define LSB4(x) ((x)&0xf)

#endif // __AVX_COMMON_H__