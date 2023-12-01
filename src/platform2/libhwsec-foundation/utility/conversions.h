// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_UTILITY_CONVERSIONS_H_
#define LIBHWSEC_FOUNDATION_UTILITY_CONVERSIONS_H_

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace hwsec_foundation {
namespace utility {

// Type conversion from C string buffer (char*) to bytes buffer (uint8_t*)
inline const uint8_t* CStringAsBytesByffer(const char* str) {
  return reinterpret_cast<const uint8_t*>(str);
}

inline std::string BytesToString(const std::vector<uint8_t>& bytes) {
  return std::string(bytes.begin(), bytes.end());
}

inline std::optional<std::string> BytesToString(
    const std::optional<std::vector<uint8_t>>& maybe_bytes) {
  if (maybe_bytes == std::nullopt) {
    return std::nullopt;
  }
  return BytesToString(*maybe_bytes);
}

}  // namespace utility
}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_UTILITY_CONVERSIONS_H_
