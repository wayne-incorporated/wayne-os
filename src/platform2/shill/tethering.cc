// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/tethering.h"

#include <iterator>
#include <set>
#include <vector>

namespace shill {

// static
const uint8_t Tethering::kAndroidBSSIDPrefix[] = {0x02, 0x1a, 0x11};
const uint32_t Tethering::kIosOui = 0x0017f2;
const uint8_t Tethering::kLocallyAdministratedMacBit = 0x02;

// static
bool Tethering::IsAndroidBSSID(const std::vector<uint8_t>& bssid) {
  std::vector<uint8_t> truncated_bssid = bssid;
  truncated_bssid.resize(std::size(kAndroidBSSIDPrefix));
  return truncated_bssid ==
         std::vector<uint8_t>(
             kAndroidBSSIDPrefix,
             kAndroidBSSIDPrefix + std::size(kAndroidBSSIDPrefix));
}

// static
bool Tethering::IsLocallyAdministeredBSSID(const std::vector<uint8_t>& bssid) {
  return !bssid.empty() && (bssid[0] & kLocallyAdministratedMacBit);
}

// static
bool Tethering::HasIosOui(const std::set<uint32_t>& oui_set) {
  return oui_set.find(kIosOui) != oui_set.end();
}

}  // namespace shill
