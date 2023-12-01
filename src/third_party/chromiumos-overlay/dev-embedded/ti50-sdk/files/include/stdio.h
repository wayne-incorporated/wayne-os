/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#ifndef DEV_EMBEDDED_TI50_SDK_FILES_INCLUDE_STDIO_H_
#define DEV_EMBEDDED_TI50_SDK_FILES_INCLUDE_STDIO_H_

#include <sys/cdefs.h>

#ifdef __cplusplus
extern "C" {
#endif

extern FILE* const stdin;
extern FILE* const stdout;
extern FILE* const stderr;

#define stdin (stdin)
#define stdout (stdout)
#define stderr (stderr)

int printf(const char* __restrict, ...);
int vsnprintf(char* __restrict, size_t, const char* __restrict, va_list);

#ifdef __cplusplus
}
#endif

#endif /* DEV_EMBEDDED_TI50_SDK_FILES_INCLUDE_STDIO_H_ */
