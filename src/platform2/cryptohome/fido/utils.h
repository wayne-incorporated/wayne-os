// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file contains some utility function to print fido
// related data structures

#ifndef CRYPTOHOME_FIDO_UTILS_H_
#define CRYPTOHOME_FIDO_UTILS_H_

#include <string>

namespace cryptohome {
namespace fido {

// Read a big endian number. Fido devices use big endian.
template <typename T>
inline void ReadBigEndian(const char buf[], T* out) {
  *out = buf[0];
  for (size_t i = 1; i < sizeof(T); ++i) {
    *out <<= 8;
    // Must cast to uint8_t to avoid clobbering by sign extension.
    *out |= static_cast<uint8_t>(buf[i]);
  }
}

}  // namespace fido
}  // namespace cryptohome

#endif  // CRYPTOHOME_FIDO_UTILS_H_
