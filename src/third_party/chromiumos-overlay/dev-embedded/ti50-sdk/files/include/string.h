/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#ifndef DEV_EMBEDDED_TI50_SDK_FILES_INCLUDE_STRING_H_
#define DEV_EMBEDDED_TI50_SDK_FILES_INCLUDE_STRING_H_

#include <sys/cdefs.h>

#ifdef __cplusplus
extern "C" {
#endif

void* memcpy(void* __restrict, const void* __restrict, size_t);
void* memmove(void*, const void*, size_t);
void* memset(void*, int, size_t);
int memcmp(const void*, const void*, size_t);
void* memchr(const void*, int, size_t);

char* strncpy(char* __restrict, const char* __restrict, size_t);

char* strncat(char* __restrict, const char* __restrict, size_t);

int strncmp(const char*, const char*, size_t);

char* strchr(const char*, int);
char* strrchr(const char*, int);

size_t strlen(const char*);

#ifdef __cplusplus
}
#endif

#endif /* DEV_EMBEDDED_TI50_SDK_FILES_INCLUDE_STRING_H_ */
