// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/local_device.h"

#include <base/functional/bind.h>
#include <base/test/mock_callback.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/mock_control.h"
#include "shill/mock_event_dispatcher.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/test_event_dispatcher.h"

using ::testing::_;
using ::testing::Mock;
using ::testing::NiceMock;
using ::testing::StrictMock;

namespace shill {

namespace {
const char kDeviceName[] = "ap0";
const char kDeviceAddress[] = "00:01:02:03:04:05";
const uint32_t kPhyIndex = 5678;
}  // namespace

class TestLocalDevice : public LocalDevice {
 public:
  TestLocalDevice(Manager* manager,
                  IfaceType type,
                  const std::string& link_name,
                  const std::string& mac_address,
                  uint32_t phy_index,
                  const EventCallback& callback)
      : LocalDevice(
            manager, type, link_name, mac_address, phy_index, callback) {}
  ~TestLocalDevice() override = default;

  bool Start() override { return true; }

  bool Stop() override { return true; }

  LocalService* GetService() const override { return nullptr; }
};

class LocalDeviceTest : public testing::Test {
 public:
  LocalDeviceTest() : manager_(&control_interface_, &dispatcher_, &metrics_) {
    device_ = new NiceMock<TestLocalDevice>(
        &manager_, LocalDevice::IfaceType::kAP, kDeviceName, kDeviceAddress,
        kPhyIndex, cb.Get());
  }
  ~LocalDeviceTest() override = default;

  void DispatchPendingEvents() { dispatcher_.DispatchPendingEvents(); }

 protected:
  NiceMock<MockControl> control_interface_;
  EventDispatcherForTest dispatcher_;
  NiceMock<MockMetrics> metrics_;
  StrictMock<base::MockRepeatingCallback<void(LocalDevice::DeviceEvent,
                                              const LocalDevice*)>>
      cb;
  NiceMock<MockManager> manager_;

  scoped_refptr<TestLocalDevice> device_;
};

TEST_F(LocalDeviceTest, SetEnabled) {
  EXPECT_FALSE(device_->enabled_);
  EXPECT_TRUE(device_->SetEnabled(true));
  EXPECT_TRUE(device_->enabled_);

  EXPECT_TRUE(device_->SetEnabled(false));
  EXPECT_FALSE(device_->enabled_);
}

TEST_F(LocalDeviceTest, PostDeviceEvent) {
  device_->PostDeviceEvent(LocalDevice::DeviceEvent::kInterfaceDisabled);
  EXPECT_CALL(cb, Run(LocalDevice::DeviceEvent::kInterfaceDisabled, _))
      .Times(1);
  DispatchPendingEvents();
  Mock::VerifyAndClearExpectations(&cb);
}

}  // namespace shill
