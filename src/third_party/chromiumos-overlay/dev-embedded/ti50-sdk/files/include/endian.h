/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#ifndef DEV_EMBEDDED_TI50_SDK_FILES_INCLUDE_ENDIAN_H_
#define DEV_EMBEDDED_TI50_SDK_FILES_INCLUDE_ENDIAN_H_

#include <stdint.h>

#ifdef __soteria
static inline uint32_t __bswap32(uint32_t data) {
    uint32_t ret;
    asm volatile("grevi %0, %1, 0x18" : "=r"(ret) : "r"(data));
    return ret;
}

static inline uint16_t __bswap16(uint16_t x) {
    uint16_t i;
    asm("grevi %0, %1, 0x08\n" : "=r"(i) : "r"(x));
    return i;
}

static inline uint64_t __bswap64(uint64_t x) {
    uint32_t lo = __bswap32((uint32_t)x);
    uint32_t hi = __bswap32((uint32_t)(x >> 32));
    return ((uint64_t)lo << 32) | (uint64_t)hi;
}
#else
#define __bswap16(_x) __builtin_bswap16(_x)
#define __bswap32(_x) __builtin_bswap32(_x)
#define __bswap64(_x) __builtin_bswap64(_x)
#endif

#if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)

static inline uint16_t be16toh(uint16_t in) {
    return __bswap16(in);
}
static inline uint32_t be32toh(uint32_t in) {
    return __bswap32(in);
}
static inline uint64_t be64toh(uint64_t in) {
    return __bswap64(in);
}

static inline uint16_t htobe16(uint16_t in) {
    return __bswap16(in);
}
static inline uint32_t htobe32(uint32_t in) {
    return __bswap32(in);
}
static inline uint64_t htobe64(uint64_t in) {
    return __bswap64(in);
}

#else /* __BYTE_ORDER__  == __ORDER_BIG_ENDIAN__ */
static inline uint16_t be16toh(uint16_t in) {
    return in;
}
static inline uint32_t be32toh(uint32_t in) {
    return in;
}
static inline uint64_t be64toh(uint64_t in) {
    return in;
}

static inline uint16_t htobe16(uint16_t in) {
    return in;
}
static inline uint32_t htobe32(uint32_t in) {
    return in;
}
static inline uint64_t htobe64(uint64_t in) {
    return in;
}

#endif /* __BYTE_ORDER__  == __ORDER_LITTLE_ENDIAN__ */

#endif /* DEV_EMBEDDED_TI50_SDK_FILES_INCLUDE_ENDIAN_H_ */
