// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <power_manager/proto_bindings/power_supply_properties.pb.h>
#include <power_manager/proto_bindings/suspend.pb.h>

#include "diagnostics/wilco_dtc_supportd/telemetry/powerd_event_service.h"
#include "diagnostics/wilco_dtc_supportd/telemetry/powerd_event_service_impl.h"
#include "diagnostics/wilco_dtc_supportd/utils/system/fake_powerd_adapter.h"

using ::testing::StrictMock;

using PowerEventType =
    diagnostics::wilco::PowerdEventService::Observer::PowerEventType;

namespace diagnostics {
namespace wilco {
namespace {

class MockPowerdEventServiceObserver : public PowerdEventService::Observer {
 public:
  MOCK_METHOD(void, OnPowerdEvent, (PowerEventType), (override));
};

class PowerdEventServiceImplTest : public ::testing::Test {
 public:
  PowerdEventServiceImplTest() = default;
  PowerdEventServiceImplTest(const PowerdEventServiceImplTest&) = delete;
  PowerdEventServiceImplTest& operator=(const PowerdEventServiceImplTest&) =
      delete;

  void SetUp() override {
    service_ = std::make_unique<PowerdEventServiceImpl>(&fake_powerd_adapter_);
    service_->AddObserver(&observer_);
    EXPECT_TRUE(fake_powerd_adapter_.HasPowerObserver(service_.get()));
  }

  void TearDown() override {
    service_->RemoveObserver(&observer_);
    service_.reset();
    EXPECT_FALSE(fake_powerd_adapter_.HasPowerObserver(service_.get()));
  }

 protected:
  FakePowerdAdapter fake_powerd_adapter_;

  StrictMock<MockPowerdEventServiceObserver> observer_;

  std::unique_ptr<PowerdEventServiceImpl> service_;
};

TEST_F(PowerdEventServiceImplTest, OnPowerSupplyPollSignal) {
  power_manager::PowerSupplyProperties power_supply;

  // Do not receive power event, because |power_supply| does not have
  // |external_power| field.
  fake_powerd_adapter_.EmitPowerSupplyPollSignal(power_supply);

  EXPECT_CALL(observer_, OnPowerdEvent(PowerEventType::kAcInsert));
  power_supply.set_external_power(power_manager::PowerSupplyProperties::AC);
  fake_powerd_adapter_.EmitPowerSupplyPollSignal(power_supply);

  EXPECT_CALL(observer_, OnPowerdEvent(PowerEventType::kAcRemove));
  power_supply.set_external_power(
      power_manager::PowerSupplyProperties::DISCONNECTED);
  fake_powerd_adapter_.EmitPowerSupplyPollSignal(power_supply);

  EXPECT_CALL(observer_, OnPowerdEvent(PowerEventType::kAcInsert));
  power_supply.set_external_power(power_manager::PowerSupplyProperties::USB);
  fake_powerd_adapter_.EmitPowerSupplyPollSignal(power_supply);

  // Do not receive the same power event twice in a row.
  fake_powerd_adapter_.EmitPowerSupplyPollSignal(power_supply);

  // Do not receive the same power event twice in a row.
  fake_powerd_adapter_.EmitPowerSupplyPollSignal(power_supply);
}

TEST_F(PowerdEventServiceImplTest, OnSuspendImminentSignal) {
  const power_manager::SuspendImminent kSuspendImminent;
  EXPECT_CALL(observer_, OnPowerdEvent(PowerEventType::kOsSuspend));
  fake_powerd_adapter_.EmitSuspendImminentSignal(kSuspendImminent);
}

TEST_F(PowerdEventServiceImplTest, OnDarkSuspendImminentSignal) {
  const power_manager::SuspendImminent kSuspendImminent;
  EXPECT_CALL(observer_, OnPowerdEvent(PowerEventType::kOsSuspend));
  fake_powerd_adapter_.EmitDarkSuspendImminentSignal(kSuspendImminent);
}

TEST_F(PowerdEventServiceImplTest, OnSuspendDoneSignal) {
  const power_manager::SuspendDone kSuspendDone;
  EXPECT_CALL(observer_, OnPowerdEvent(PowerEventType::kOsResume));
  fake_powerd_adapter_.EmitSuspendDoneSignal(kSuspendDone);
}

}  // namespace
}  // namespace wilco
}  // namespace diagnostics
