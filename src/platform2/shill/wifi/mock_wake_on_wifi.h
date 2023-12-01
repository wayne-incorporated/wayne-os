// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_WIFI_MOCK_WAKE_ON_WIFI_H_
#define SHILL_WIFI_MOCK_WAKE_ON_WIFI_H_

#include <optional>
#include <string>
#include <vector>

#include <base/time/time.h>
#include <gmock/gmock.h>

#include "shill/error.h"
#include "shill/net/nl80211_message.h"
#include "shill/store/property_store.h"
#include "shill/wifi/wake_on_wifi_interface.h"

namespace shill {

class MockWakeOnWiFi : public WakeOnWiFiInterface {
 public:
  MockWakeOnWiFi();
  MockWakeOnWiFi(const MockWakeOnWiFi&) = delete;
  MockWakeOnWiFi& operator=(const MockWakeOnWiFi&) = delete;

  ~MockWakeOnWiFi() override;

  MOCK_METHOD(void, InitPropertyStore, (PropertyStore * store), (override));
  MOCK_METHOD(void, Start, (), (override));
  MOCK_METHOD(void,
              ParseWakeOnWiFiCapabilities,
              (const Nl80211Message&),
              (override));
  MOCK_METHOD(void,
              OnBeforeSuspend,
              (bool,
               const std::vector<ByteString>&,
               ResultCallback,
               base::OnceClosure,
               base::OnceClosure,
               std::optional<base::TimeDelta>),
              (override));
  MOCK_METHOD(void, OnAfterResume, (), (override));
  MOCK_METHOD(void,
              OnDarkResume,
              (bool,
               const std::vector<ByteString>&,
               ResultCallback,
               base::OnceClosure,
               InitiateScanCallback,
               const base::RepeatingClosure&),
              (override));
  MOCK_METHOD(void,
              OnConnectedAndReachable,
              (std::optional<base::TimeDelta>),
              (override));
  MOCK_METHOD(void, ReportConnectedToServiceAfterWake, (bool, int), (override));
  MOCK_METHOD(void,
              OnNoAutoConnectableServicesAfterScan,
              (const std::vector<ByteString>&,
               base::OnceClosure,
               InitiateScanCallback),
              (override));
  MOCK_METHOD(void, OnScanStarted, (bool), (override));
  MOCK_METHOD(void, OnScanCompleted, (), (override));
  MOCK_METHOD(void, OnWiphyIndexReceived, (uint32_t), (override));
};

}  // namespace shill

#endif  // SHILL_WIFI_MOCK_WAKE_ON_WIFI_H_
