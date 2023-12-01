// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_CRC_H_
#define CRYPTOHOME_CRC_H_

#include <stdint.h>
#include <limits>

#include <base/metrics/crc32.h>

namespace cryptohome {

// Calculate the CRC-8 of the data, using the x^8 + x^2 + x + 1 polynomial.
inline uint8_t Crc8(const void* buffer, uint32_t len) {
  // Calculate CRC-8 directly. A table-based algorithm would be faster but for
  // only a few bytes it isn't worth the code size.
  auto* data = static_cast<const uint8_t*>(buffer);
  uint32_t crc = 0;
  for (auto* next = data; next != data + len; ++next) {
    crc ^= (*next << 8);
    for (int i = 0; i < 8; ++i) {
      if (crc & 0x8000)
        crc ^= (0x1070 << 3);
      crc <<= 1;
    }
  }
  return static_cast<uint8_t>(crc >> 8);
}

// Calculate the CRC-32 of the data. Based on base::Crc32 which does not quite
// calculate the actual CRC.
inline uint32_t Crc32(const void* buffer, uint32_t len) {
  // The base::Crc32 method should really be called "UpdateCRC". Initial
  // checksum needs to be initialized to all 1's; final value is 1's
  // complement.
  // See https://www.w3.org/TR/PNG/#D-CRCAppendix.
  // TODO(b/168049518): Move to libchrome.
  return ~base::Crc32(std::numeric_limits<uint32_t>::max(), buffer, len);
}

}  // namespace cryptohome

#endif  // CRYPTOHOME_CRC_H_
