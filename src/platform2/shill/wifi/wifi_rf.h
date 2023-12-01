// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_WIFI_WIFI_RF_H_
#define SHILL_WIFI_WIFI_RF_H_

#include <string>

namespace shill {

// These are special country codes for regulatory domain defined in
// linux/include/net/regulatory.h.
// "00" is a code for world/global regulatory domain.
constexpr char kWorldRegDomain[] = "00";
// "99" is a code for "custom world/global" regulatory domain used by some
// drivers.
constexpr char kCustomWorldRegDomain[] = "99";
// "98" is a code for "intersection" regulatory domain - meaning that what is
// being used is an intersection of what used to be set with what was requested.
constexpr char kIntersectionRegDomain[] = "98";
// "97" signals that regulatory domain has not yet been configured.
constexpr char kUnconfiguredRegDomain[] = "97";

// Enum and utility functions to handle WiFi RF parameters like band, bandwidth
// and frequency.
enum class WiFiBand {
  kUnknownBand,
  kLowBand,   // 2.4GHz band (2401MHz - 2495MHz, channel 1 - 14)
  kHighBand,  // 5GHz band (5150MHz - 5895MHz, channel 32 - 177)
  kAllBands,  // All 2 bands
};

std::string WiFiBandName(WiFiBand band);

WiFiBand WiFiBandFromName(const std::string& name);

// Converts WiFiBand to the value used in Netlink messages.  Returns negative
// value for kUnknownBand and kAllBands since these can't be converted.
int WiFiBandToNl(WiFiBand band);

inline std::ostream& operator<<(std::ostream& stream, WiFiBand band) {
  return stream << WiFiBandName(band);
}

// Some frequencies are marked as usable but with some limitation. Return
// whether the given frequency is limited or not.
bool IsWiFiLimitedFreq(uint32_t freq);

}  // namespace shill

#endif  // SHILL_WIFI_WIFI_RF_H_
