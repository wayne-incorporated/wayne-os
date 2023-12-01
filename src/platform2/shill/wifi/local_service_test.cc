// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/local_service.h"

#include <memory>

#include <base/test/mock_callback.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/mock_control.h"
#include "shill/mock_event_dispatcher.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/store/key_value_store.h"
#include "shill/test_event_dispatcher.h"
#include "shill/wifi/local_device.h"
#include "shill/wifi/mock_local_device.h"

using ::testing::_;
using ::testing::Mock;
using ::testing::NiceMock;
using ::testing::StrictMock;

namespace shill {

class TestLocalService : public LocalService {
 public:
  TestLocalService(LocalDeviceConstRefPtr device) : LocalService(device) {}
  ~TestLocalService() override = default;

  KeyValueStore GetSupplicantConfigurationParameters() const override {
    return KeyValueStore();
  }
};

class LocalServiceTest : public testing::Test {
 public:
  LocalServiceTest()
      : manager_(&control_interface_, &dispatcher_, &metrics_),
        device_(new NiceMock<MockLocalDevice>(&manager_,
                                              LocalDevice::IfaceType::kAP,
                                              "ap0",
                                              "00:00:00:00:00:00",
                                              0,
                                              cb.Get())),
        service_(new NiceMock<TestLocalService>(device_)) {}
  ~LocalServiceTest() override = default;

  void DispatchPendingEvents() { dispatcher_.DispatchPendingEvents(); }

  LocalService::LocalServiceState ServiceState() { return service_->state_; }

 protected:
  StrictMock<base::MockRepeatingCallback<void(LocalDevice::DeviceEvent,
                                              const LocalDevice*)>>
      cb;

  NiceMock<MockControl> control_interface_;
  EventDispatcherForTest dispatcher_;
  NiceMock<MockMetrics> metrics_;
  NiceMock<MockManager> manager_;

  scoped_refptr<MockLocalDevice> device_;
  std::unique_ptr<TestLocalService> service_;
};

TEST_F(LocalServiceTest, SetState) {
  // Service has an initial state kStateIdle.
  EXPECT_EQ(ServiceState(), LocalService::LocalServiceState::kStateIdle);

  // No device event if service is starting.
  service_->SetState(LocalService::LocalServiceState::kStateStarting);
  EXPECT_CALL(cb, Run(_, _)).Times(0);
  DispatchPendingEvents();
  Mock::VerifyAndClearExpectations(&cb);
  EXPECT_EQ(ServiceState(), LocalService::LocalServiceState::kStateStarting);

  // Emit device event kServiceUp if service is up.
  service_->SetState(LocalService::LocalServiceState::kStateUp);
  EXPECT_CALL(cb, Run(LocalDevice::DeviceEvent::kServiceUp, _)).Times(1);
  DispatchPendingEvents();
  Mock::VerifyAndClearExpectations(&cb);
  EXPECT_EQ(ServiceState(), LocalService::LocalServiceState::kStateUp);

  // Emit device event kServiceDown if service is down.
  service_->SetState(LocalService::LocalServiceState::kStateIdle);
  EXPECT_CALL(cb, Run(LocalDevice::DeviceEvent::kServiceDown, _)).Times(1);
  DispatchPendingEvents();
  Mock::VerifyAndClearExpectations(&cb);
  EXPECT_EQ(ServiceState(), LocalService::LocalServiceState::kStateIdle);

  // No device event if service is changed from starting to idle.
  service_->SetState(LocalService::LocalServiceState::kStateStarting);
  EXPECT_EQ(ServiceState(), LocalService::LocalServiceState::kStateStarting);
  service_->SetState(LocalService::LocalServiceState::kStateIdle);
  EXPECT_CALL(cb, Run(_, _)).Times(0);
  DispatchPendingEvents();
  Mock::VerifyAndClearExpectations(&cb);
  EXPECT_EQ(ServiceState(), LocalService::LocalServiceState::kStateIdle);
}

}  // namespace shill
