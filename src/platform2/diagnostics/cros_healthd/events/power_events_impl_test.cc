// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/run_loop.h>
#include <base/test/task_environment.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <power_manager/dbus-proxy-mocks.h>
#include <power_manager/proto_bindings/power_supply_properties.pb.h>

#include "diagnostics/cros_healthd/events/mock_event_observer.h"
#include "diagnostics/cros_healthd/events/power_events_impl.h"
#include "diagnostics/cros_healthd/system/mock_context.h"
#include "diagnostics/mojom/public/cros_healthd_events.mojom.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

using ::testing::_;
using ::testing::Invoke;
using ::testing::SaveArg;
using ::testing::StrictMock;

class MockCrosHealthdPowerObserver : public mojom::CrosHealthdPowerObserver {
 public:
  MockCrosHealthdPowerObserver(
      mojo::PendingReceiver<mojom::CrosHealthdPowerObserver> receiver)
      : receiver_{this /* impl */, std::move(receiver)} {
    DCHECK(receiver_.is_bound());
  }
  MockCrosHealthdPowerObserver(const MockCrosHealthdPowerObserver&) = delete;
  MockCrosHealthdPowerObserver& operator=(const MockCrosHealthdPowerObserver&) =
      delete;

  MOCK_METHOD(void, OnAcInserted, (), (override));
  MOCK_METHOD(void, OnAcRemoved, (), (override));
  MOCK_METHOD(void, OnOsSuspend, (), (override));
  MOCK_METHOD(void, OnOsResume, (), (override));

 private:
  mojo::Receiver<mojom::CrosHealthdPowerObserver> receiver_;
};

// Tests for the PowerEventsImpl class.
class PowerEventsImplTest : public testing::Test {
 protected:
  PowerEventsImplTest() = default;
  PowerEventsImplTest(const PowerEventsImplTest&) = delete;
  PowerEventsImplTest& operator=(const PowerEventsImplTest&) = delete;

  void SetUp() override {
    EXPECT_CALL(*mock_power_manager_proxy(),
                DoRegisterPowerSupplyPollSignalHandler(_, _))
        .WillOnce(SaveArg<0>(&power_supply_poll_signal_));
    EXPECT_CALL(*mock_power_manager_proxy(),
                DoRegisterSuspendImminentSignalHandler(_, _))
        .WillOnce(SaveArg<0>(&suspend_imminent_signal));
    EXPECT_CALL(*mock_power_manager_proxy(),
                DoRegisterDarkSuspendImminentSignalHandler(_, _))
        .WillOnce(SaveArg<0>(&dark_suspend_imminent_signal));
    EXPECT_CALL(*mock_power_manager_proxy(),
                DoRegisterSuspendDoneSignalHandler(_, _))
        .WillOnce(SaveArg<0>(&suspend_done_signal_));
    power_events_impl_ = std::make_unique<PowerEventsImpl>(&mock_context_);

    mojo::PendingRemote<mojom::EventObserver> observer;
    mojo::PendingReceiver<mojom::EventObserver> observer_receiver(
        observer.InitWithNewPipeAndPassReceiver());
    observer_ = std::make_unique<StrictMock<MockEventObserver>>(
        std::move(observer_receiver));
    power_events_impl_->AddObserver(std::move(observer));

    mojo::PendingRemote<mojom::CrosHealthdPowerObserver> deprecated_observer;
    mojo::PendingReceiver<mojom::CrosHealthdPowerObserver>
        deprecated_observer_receiver(
            deprecated_observer.InitWithNewPipeAndPassReceiver());
    deprecated_observer_ =
        std::make_unique<StrictMock<MockCrosHealthdPowerObserver>>(
            std::move(deprecated_observer_receiver));
    power_events_impl_->AddObserver(std::move(deprecated_observer));
  }

  org::chromium::PowerManagerProxyMock* mock_power_manager_proxy() {
    return mock_context_.mock_power_manager_proxy();
  }

  MockEventObserver* mock_observer() { return observer_.get(); }
  MockCrosHealthdPowerObserver* mock_deprecated_observer() {
    return deprecated_observer_.get();
  }

  void EmitPowerSupplyPollSignal(
      const power_manager::PowerSupplyProperties& power_supply) {
    std::string power_supply_str = power_supply.SerializeAsString();
    std::vector<uint8_t> signal(power_supply_str.begin(),
                                power_supply_str.end());
    power_supply_poll_signal_.Run(signal);
  }

  void EmitSuspendImminentSignal() { suspend_imminent_signal.Run({}); }

  void EmitDarkSuspendImminentSignal() { dark_suspend_imminent_signal.Run({}); }

  void EmitSuspendDoneSignal() { suspend_done_signal_.Run({}); }

  void SetExpectedEvent(mojom::PowerEventInfo::State state) {
    EXPECT_CALL(*mock_observer(), OnEvent(_))
        .WillOnce(Invoke([=](mojom::EventInfoPtr info) {
          EXPECT_TRUE(info->is_power_event_info());
          const auto& power_event_info = info->get_power_event_info();
          EXPECT_EQ(power_event_info->state, state);
        }));
  }

 private:
  base::test::TaskEnvironment task_environment_;
  MockContext mock_context_;
  std::unique_ptr<StrictMock<MockEventObserver>> observer_;
  std::unique_ptr<StrictMock<MockCrosHealthdPowerObserver>>
      deprecated_observer_;
  std::unique_ptr<PowerEventsImpl> power_events_impl_;
  base::RepeatingCallback<void(const std::vector<uint8_t>&)>
      power_supply_poll_signal_;
  base::RepeatingCallback<void(const std::vector<uint8_t>&)>
      suspend_imminent_signal;
  base::RepeatingCallback<void(const std::vector<uint8_t>&)>
      dark_suspend_imminent_signal;
  base::RepeatingCallback<void(const std::vector<uint8_t>&)>
      suspend_done_signal_;
};

// Test that we can receive AC inserted events from powerd's AC proto.
TEST_F(PowerEventsImplTest, ReceiveAcInsertedEventFromAcProto) {
  base::RunLoop run_loop;
  SetExpectedEvent(mojom::PowerEventInfo::State::kAcInserted);
  EXPECT_CALL(*mock_deprecated_observer(), OnAcInserted())
      .WillOnce(Invoke([&]() { run_loop.Quit(); }));

  power_manager::PowerSupplyProperties power_supply;
  power_supply.set_external_power(power_manager::PowerSupplyProperties::AC);
  EmitPowerSupplyPollSignal(power_supply);

  run_loop.Run();
}

// Test that we can receive AC inserted events from powerd's USB proto.
TEST_F(PowerEventsImplTest, ReceiveAcInsertedEventFromUsbProto) {
  base::RunLoop run_loop;
  SetExpectedEvent(mojom::PowerEventInfo::State::kAcInserted);
  EXPECT_CALL(*mock_deprecated_observer(), OnAcInserted())
      .WillOnce(Invoke([&]() { run_loop.Quit(); }));

  power_manager::PowerSupplyProperties power_supply;
  power_supply.set_external_power(power_manager::PowerSupplyProperties::USB);
  EmitPowerSupplyPollSignal(power_supply);

  run_loop.Run();
}

// Test that we can receive AC removed events.
TEST_F(PowerEventsImplTest, ReceiveAcRemovedEvent) {
  base::RunLoop run_loop;
  SetExpectedEvent(mojom::PowerEventInfo::State::kAcRemoved);
  EXPECT_CALL(*mock_deprecated_observer(), OnAcRemoved())
      .WillOnce(Invoke([&]() { run_loop.Quit(); }));

  power_manager::PowerSupplyProperties power_supply;
  power_supply.set_external_power(
      power_manager::PowerSupplyProperties::DISCONNECTED);
  EmitPowerSupplyPollSignal(power_supply);

  run_loop.Run();
}

// Test that we can receive OS suspend events from suspend imminent signals.
TEST_F(PowerEventsImplTest, ReceiveOsSuspendEventFromSuspendImminent) {
  base::RunLoop run_loop;
  SetExpectedEvent(mojom::PowerEventInfo::State::kOsSuspend);
  EXPECT_CALL(*mock_deprecated_observer(), OnOsSuspend())
      .WillOnce(Invoke([&]() { run_loop.Quit(); }));

  EmitSuspendImminentSignal();

  run_loop.Run();
}

// Test that we can receive OS suspend events from dark suspend imminent
// signals.
TEST_F(PowerEventsImplTest, ReceiveOsSuspendEventFromDarkSuspendImminent) {
  base::RunLoop run_loop;
  SetExpectedEvent(mojom::PowerEventInfo::State::kOsSuspend);
  EXPECT_CALL(*mock_deprecated_observer(), OnOsSuspend())
      .WillOnce(Invoke([&]() { run_loop.Quit(); }));

  EmitDarkSuspendImminentSignal();

  run_loop.Run();
}

// Test that we can receive OS resume events.
TEST_F(PowerEventsImplTest, ReceiveOsResumeEvent) {
  base::RunLoop run_loop;
  SetExpectedEvent(mojom::PowerEventInfo::State::kOsResume);
  EXPECT_CALL(*mock_deprecated_observer(), OnOsResume()).WillOnce(Invoke([&]() {
    run_loop.Quit();
  }));

  EmitSuspendDoneSignal();

  run_loop.Run();
}

// Test that powerd events without external power are ignored.
TEST_F(PowerEventsImplTest, IgnorePayloadWithoutExternalPower) {
  power_manager::PowerSupplyProperties power_supply;
  EmitPowerSupplyPollSignal(power_supply);
}

// Test that multiple of the same powerd events in a row are only reported once.
TEST_F(PowerEventsImplTest, MultipleIdenticalPayloadsReportedOnlyOnce) {
  base::RunLoop run_loop;
  SetExpectedEvent(mojom::PowerEventInfo::State::kAcRemoved);
  EXPECT_CALL(*mock_deprecated_observer(), OnAcRemoved())
      .WillOnce(Invoke([&]() { run_loop.Quit(); }));

  // Make the first call, which should be reported.
  power_manager::PowerSupplyProperties power_supply;
  power_supply.set_external_power(
      power_manager::PowerSupplyProperties::DISCONNECTED);
  EmitPowerSupplyPollSignal(power_supply);

  run_loop.Run();

  // A second identical call should be ignored.
  EmitPowerSupplyPollSignal(power_supply);

  // Changing the type of external power should again be reported.
  base::RunLoop run_loop2;
  SetExpectedEvent(mojom::PowerEventInfo::State::kAcInserted);
  EXPECT_CALL(*mock_deprecated_observer(), OnAcInserted())
      .WillOnce(Invoke([&]() { run_loop2.Quit(); }));

  power_supply.set_external_power(power_manager::PowerSupplyProperties::AC);
  EmitPowerSupplyPollSignal(power_supply);

  run_loop2.Run();
}

}  // namespace
}  // namespace diagnostics
