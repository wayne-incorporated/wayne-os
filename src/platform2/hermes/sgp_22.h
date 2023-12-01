// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_SGP_22_H_
#define HERMES_SGP_22_H_

#include <array>
#include <cstdint>

namespace hermes {

constexpr uint8_t kLpaTerminalCapabilityTag = 0x83;
constexpr uint8_t kLpaTerminalCapabilityValue = 0x07;

// Application identifier for the eUICC's ISD-R, as per SGP.02 2.2.3
constexpr std::array<uint8_t, 16> kAidIsdr = {
    0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xFF,
    0xFF, 0xFF, 0xFF, 0x89, 0x00, 0x00, 0x01, 0x00,
};

// Application identifier for the eUICC's ECASD, as per SGP.02 2.2.3
constexpr std::array<uint8_t, 16> kAidEcasd = {
    0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xFF,
    0xFF, 0xFF, 0xFF, 0x89, 0x00, 0x00, 0x02, 0x00,
};

}  // namespace hermes

#endif  // HERMES_SGP_22_H_
