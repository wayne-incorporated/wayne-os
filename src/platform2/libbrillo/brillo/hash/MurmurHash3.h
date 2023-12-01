// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This source file is modified from a verbatim copy of MurmurHash3.cc from
// the smhasher project. The modifications done to this file is licensed
// according to the Chromium OS license notice above. The original, verbatim
// source's license is as below.

//-----------------------------------------------------------------------------
// MurmurHash3 was written by Austin Appleby, and is placed in the public
// domain. The author hereby disclaims copyright to this source code.

//-----------------------------------------------------------------------------
// The functions in this file compute the MurmurHash3.
// Note that the MurmurHash is not cryptographically secure, and should
// definitely not be used in any situation that demands security.
// It would be better to view the functions below as similar to std::hash,
// but will remain stable across releases.

#ifndef LIBBRILLO_BRILLO_HASH_MURMURHASH3_H_
#define LIBBRILLO_BRILLO_HASH_MURMURHASH3_H_

#include <brillo/brillo_export.h>

//-----------------------------------------------------------------------------
// Platform-specific functions and macros

// Microsoft Visual Studio

#if defined(_MSC_VER) && (_MSC_VER < 1600)

typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef unsigned __int64 uint64_t;

// Other compilers

#else  // defined(_MSC_VER)

#include <stdint.h>

#endif  // !defined(_MSC_VER)

//-----------------------------------------------------------------------------

namespace brillo {

BRILLO_EXPORT void MurmurHash3_x86_32(const void* key,
                                      int len,
                                      uint32_t seed,
                                      void* out);

BRILLO_EXPORT void MurmurHash3_x86_128(const void* key,
                                       int len,
                                       uint32_t seed,
                                       void* out);

BRILLO_EXPORT void MurmurHash3_x64_128(const void* key,
                                       int len,
                                       uint32_t seed,
                                       void* out);

}  // namespace brillo

//-----------------------------------------------------------------------------

#endif  // LIBBRILLO_BRILLO_HASH_MURMURHASH3_H_
