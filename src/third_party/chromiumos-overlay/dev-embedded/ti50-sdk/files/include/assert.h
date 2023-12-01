/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#ifndef DEV_EMBEDDED_TI50_SDK_FILES_INCLUDE_ASSERT_H_
#define DEV_EMBEDDED_TI50_SDK_FILES_INCLUDE_ASSERT_H_

#ifdef NDEBUG
#define assert(x) (void)0
#else
#define assert(x) ((void)((x) || (__builtin_trap(), 0)))
#endif

#if __STDC_VERSION__ >= 201112L && !defined(__cplusplus)
#define static_assert _Static_assert
#endif

#endif /* DEV_EMBEDDED_TI50_SDK_FILES_INCLUDE_ASSERT_H_ */
