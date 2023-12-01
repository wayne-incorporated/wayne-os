// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <linux/nl80211.h>

#include "shill/wifi/wifi_rf.h"

#include <chromeos/dbus/shill/dbus-constants.h>

namespace shill {

std::string WiFiBandName(WiFiBand band) {
  switch (band) {
    case WiFiBand::kLowBand:
      return kBand2GHz;
    case WiFiBand::kHighBand:
      return kBand5GHz;
    case WiFiBand::kAllBands:
      return kBandAll;
    case WiFiBand::kUnknownBand:
    default:
      return kBandUnknown;
  }
}

WiFiBand WiFiBandFromName(const std::string& name) {
  if (name == kBand2GHz) {
    return WiFiBand::kLowBand;
  } else if (name == kBand5GHz) {
    return WiFiBand::kHighBand;
  } else if (name == kBandAll) {
    return WiFiBand::kAllBands;
  } else {
    return WiFiBand::kUnknownBand;
  }
}

int WiFiBandToNl(WiFiBand band) {
  switch (band) {
    case WiFiBand::kLowBand:
      return NL80211_BAND_2GHZ;
    case WiFiBand::kHighBand:
      return NL80211_BAND_5GHZ;
    default:
      return -1;
  }
}

bool IsWiFiLimitedFreq(uint32_t freq) {
  if (freq > 2462 && freq <= 2495) {
    // Channel 12 and 13 should be avoided as it is only allowed in low power
    // operation. Channel 14 should be avoided as it only allows non-OFDM mode
    // in JP.
    return true;
  }

  return false;
}

}  // namespace shill
