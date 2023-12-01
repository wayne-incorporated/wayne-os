// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_WIFI_MOCK_WIFI_PHY_H_
#define SHILL_WIFI_MOCK_WIFI_PHY_H_

#include "shill/wifi/wifi_phy.h"

#include <gmock/gmock.h>

namespace shill {

class MockWiFiPhy : public WiFiPhy {
 public:
  explicit MockWiFiPhy(uint32_t phy_index);

  ~MockWiFiPhy() override;

  void SetFrequencies(const Frequencies& freqs) { frequencies_ = freqs; }

  MOCK_METHOD(void, OnNewWiphy, (const Nl80211Message&), (override));
  MOCK_METHOD(bool, SupportAPMode, (), (const, override));
  MOCK_METHOD(bool, SupportAPSTAConcurrency, (), (const, override));
};

}  // namespace shill

#endif  // SHILL_WIFI_MOCK_WIFI_PHY_H_
