/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#ifndef DEV_EMBEDDED_TI50_SDK_FILES_INCLUDE_SYS_CDEFS_H_
#define DEV_EMBEDDED_TI50_SDK_FILES_INCLUDE_SYS_CDEFS_H_

#include <stddef.h>
#include <stdint.h>
#include <stdnoreturn.h>
#include <stdarg.h>

#define __restrict restrict
#undef noreturn
#define _Noreturn __attribute__((noreturn))

#define __weak __attribute__((__weak__))
#define __dead2 __attribute__((__noreturn__))
#define __pure2 __attribute__((__const__))
#define __unused __attribute__((__unused__))
#define __used __attribute__((__used__))
#define __packed __attribute__((__packed__))
#define __aligned(x) __attribute__((__aligned__(x)))
#define __section(x) __attribute__((__section__(x)))

typedef intptr_t ssize_t;

typedef struct {
    uintptr_t __x;
} FILE;

#endif /* DEV_EMBEDDED_TI50_SDK_FILES_INCLUDE_SYS_CDEFS_H_ */
