// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_WIFI_MOCK_HOTSPOT_DEVICE_H_
#define SHILL_WIFI_MOCK_HOTSPOT_DEVICE_H_

#include "shill/wifi/hotspot_device.h"

#include <memory>
#include <string>
#include <vector>

#include <gmock/gmock.h>

namespace shill {

class MockHotspotDevice : public HotspotDevice {
 public:
  MockHotspotDevice(Manager* manager,
                    const std::string& primary_link_name,
                    const std::string& link_name,
                    const std::string& mac_address,
                    uint32_t phy_index,
                    const EventCallback& callback);
  ~MockHotspotDevice() override;

  bool Start() override { return true; }

  bool Stop() override { return true; }

  MOCK_METHOD(bool, ConfigureService, (std::unique_ptr<HotspotService>), ());
  MOCK_METHOD(bool, DeconfigureService, (), ());
  MOCK_METHOD(bool, IsServiceUp, (), (const, override));
  MOCK_METHOD(std::vector<std::vector<uint8_t>>, GetStations, (), ());
};

}  // namespace shill

#endif  // SHILL_WIFI_MOCK_HOTSPOT_DEVICE_H_
