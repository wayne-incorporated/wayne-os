// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/mac_address_generator.h"

#include <base/rand_util.h>

namespace patchpanel {
namespace {
constexpr MacAddress kStableBaseAddr = {0x42, 0x37, 0x05, 0x13, 0x17, 0x00};
}  // namespace

MacAddress MacAddressGenerator::Generate() {
  MacAddress addr;
  do {
    base::RandBytes(addr.data(), addr.size());

    // Set the locally administered flag.
    addr[0] |= static_cast<uint8_t>(0x02);

    // Unset the multicast flag.
    addr[0] &= static_cast<uint8_t>(0xfe);
  } while (addrs_.find(addr) != addrs_.end() ||
           (addr[0] == kStableBaseAddr[0] && addr[1] == kStableBaseAddr[1] &&
            addr[2] == kStableBaseAddr[2] && addr[3] == kStableBaseAddr[3] &&
            addr[4] == kStableBaseAddr[4]));

  addrs_.insert(addr);

  return addr;
}

MacAddress MacAddressGenerator::GetStable(uint32_t id) const {
  MacAddress addr = kStableBaseAddr;
  addr[5] = static_cast<uint8_t>(id);
  return addr;
}

}  // namespace patchpanel
