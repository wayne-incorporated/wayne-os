// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/policy/thermal_event_handler.h"

#include <vector>

#include <base/logging.h>
#include <chromeos/dbus/service_constants.h>
#include <gtest/gtest.h>

#include "power_manager/common/clock.h"
#include "power_manager/common/power_constants.h"
#include "power_manager/powerd/system/dbus_wrapper_stub.h"
#include "power_manager/powerd/system/thermal/device_thermal_state.h"
#include "power_manager/powerd/system/thermal/thermal_device.h"
#include "power_manager/powerd/system/thermal/thermal_device_stub.h"
#include "power_manager/powerd/testing/test_environment.h"
#include "power_manager/proto_bindings/thermal.pb.h"

namespace power_manager::policy {

class ThermalEventHandlerTest : public TestEnvironment {
 public:
  ThermalEventHandlerTest()
      : handler_(std::vector<system::ThermalDeviceInterface*>(
                     {&thermal_devices_[0], &thermal_devices_[1]}),
                 &dbus_wrapper_) {
    handler_.clock_for_testing()->set_current_time_for_testing(
        base::TimeTicks() + base::Microseconds(1000));
  }
  ThermalEventHandlerTest(const ThermalEventHandlerTest&) = delete;
  ThermalEventHandlerTest& operator=(const ThermalEventHandlerTest&) = delete;
  ~ThermalEventHandlerTest() override = default;

  void SetUp() override { handler_.Init(); }

 protected:
  system::ThermalDeviceStub thermal_devices_[2];
  system::DBusWrapperStub dbus_wrapper_;
  ThermalEventHandler handler_;

  // Tests that one ThermalEvent D-Bus signal has been sent and returns the
  // signal's |thermal_state| field.
  ThermalEvent::ThermalState GetThermalEventThermalState() {
    ThermalEvent proto;
    EXPECT_EQ(1, dbus_wrapper_.num_sent_signals());
    EXPECT_TRUE(
        dbus_wrapper_.GetSentSignal(0, kThermalEventSignal, &proto, nullptr));
    return proto.thermal_state();
  }

  // Tests that one ThermalEvent D-Bus signal has been sent and returns the
  // signal's |timestamp| field.
  base::TimeTicks GetThermalEventTimestamp() {
    ThermalEvent proto;
    EXPECT_EQ(1, dbus_wrapper_.num_sent_signals());
    EXPECT_TRUE(
        dbus_wrapper_.GetSentSignal(0, kThermalEventSignal, &proto, nullptr));
    return base::TimeTicks() + base::Microseconds(proto.timestamp());
  }

  // Returns the current (fake) time.
  base::TimeTicks Now() {
    return handler_.clock_for_testing()->GetCurrentTime();
  }

  // Advances the current time by |interval|.
  void AdvanceTime(const base::TimeDelta& interval) {
    handler_.clock_for_testing()->set_current_time_for_testing(Now() +
                                                               interval);
  }
};

TEST_F(ThermalEventHandlerTest, BasicThermalEvents) {
  ThermalEvent proto;
  system::DeviceThermalState states[] = {
      system::DeviceThermalState::kNominal,
      system::DeviceThermalState::kSerious,
      system::DeviceThermalState::kUnknown,
      system::DeviceThermalState::kCritical,
      system::DeviceThermalState::kFair,
  };

  for (const auto& state : states) {
    AdvanceTime(base::Seconds(1));
    thermal_devices_[0].set_thermal_state(state);
    thermal_devices_[0].NotifyObservers();
    EXPECT_EQ(DeviceThermalStateToProto(state), GetThermalEventThermalState());
    EXPECT_EQ(Now(), GetThermalEventTimestamp());
    dbus_wrapper_.ClearSentSignals();
  }
}

TEST_F(ThermalEventHandlerTest, ThermalEventNotChange) {
  ThermalEvent proto;
  system::DeviceThermalState states[] = {
      system::DeviceThermalState::kSerious,
      system::DeviceThermalState::kFair,
      system::DeviceThermalState::kCritical,
      system::DeviceThermalState::kUnknown,
      system::DeviceThermalState::kNominal,
  };

  thermal_devices_[0].set_thermal_state(system::DeviceThermalState::kCritical);
  thermal_devices_[0].NotifyObservers();
  EXPECT_EQ(DeviceThermalStateToProto(system::DeviceThermalState::kCritical),
            GetThermalEventThermalState());
  EXPECT_EQ(Now(), GetThermalEventTimestamp());
  dbus_wrapper_.ClearSentSignals();

  // No thermal state change dbus signal because thermal_devices_[0] is always
  // at critical state which makes the overall state always at critical.
  for (const auto& state : states) {
    AdvanceTime(base::Seconds(1));
    thermal_devices_[1].set_thermal_state(state);
    thermal_devices_[1].NotifyObservers();
    EXPECT_EQ(0, dbus_wrapper_.num_sent_signals());
  }
}

TEST_F(ThermalEventHandlerTest, ThermalEventVoting) {
  ThermalEvent proto;
  typedef struct {
    // Thermal_devices_[0]'s state, thermal_devices_[1]'s state.
    system::DeviceThermalState input[2];
    // Expected output state which is the higher one of the input.
    system::DeviceThermalState output;
  } input_output_state;

  input_output_state states[] = {
      {.input = {system::DeviceThermalState::kSerious,
                 system::DeviceThermalState::kCritical},
       .output = system::DeviceThermalState::kCritical},
      {.input = {system::DeviceThermalState::kFair,
                 system::DeviceThermalState::kNominal},
       .output = system::DeviceThermalState::kFair},
      {.input = {system::DeviceThermalState::kSerious,
                 system::DeviceThermalState::kFair},
       .output = system::DeviceThermalState::kSerious},
      {.input = {system::DeviceThermalState::kNominal,
                 system::DeviceThermalState::kUnknown},
       .output = system::DeviceThermalState::kNominal},
      {.input = {system::DeviceThermalState::kFair,
                 system::DeviceThermalState::kCritical},
       .output = system::DeviceThermalState::kCritical},
  };

  for (const auto& state : states) {
    AdvanceTime(base::Seconds(1));
    thermal_devices_[0].set_thermal_state(state.input[0]);
    thermal_devices_[1].set_thermal_state(state.input[1]);
    thermal_devices_[0].NotifyObservers();
    thermal_devices_[1].NotifyObservers();
    EXPECT_EQ(DeviceThermalStateToProto(state.output),
              GetThermalEventThermalState());
    EXPECT_EQ(Now(), GetThermalEventTimestamp());
    dbus_wrapper_.ClearSentSignals();
  }
}

TEST_F(ThermalEventHandlerTest, IgnoreChargerWhenOnBattery) {
  // Charger: Critical, Processor: Fair, Power: AC -> Critical.
  handler_.HandlePowerSourceChange(PowerSource::AC);
  thermal_devices_[0].set_type(system::ThermalDeviceType::kChargerCooling);
  thermal_devices_[1].set_type(system::ThermalDeviceType::kProcessorCooling);
  thermal_devices_[0].set_thermal_state(system::DeviceThermalState::kCritical);
  thermal_devices_[1].set_thermal_state(system::DeviceThermalState::kFair);
  thermal_devices_[0].NotifyObservers();
  thermal_devices_[1].NotifyObservers();
  EXPECT_EQ(DeviceThermalStateToProto(system::DeviceThermalState::kCritical),
            GetThermalEventThermalState());
  EXPECT_EQ(Now(), GetThermalEventTimestamp());
  dbus_wrapper_.ClearSentSignals();

  // Charger: Critical, Processor: Fair, Power: Battery -> Fair.
  AdvanceTime(base::Seconds(1));
  handler_.HandlePowerSourceChange(PowerSource::BATTERY);
  EXPECT_EQ(DeviceThermalStateToProto(system::DeviceThermalState::kFair),
            GetThermalEventThermalState());
  EXPECT_EQ(Now(), GetThermalEventTimestamp());
  dbus_wrapper_.ClearSentSignals();

  // Charger: Serious, Processor: Fair, Power: Battery -> No change.
  AdvanceTime(base::Seconds(1));
  thermal_devices_[0].set_thermal_state(system::DeviceThermalState::kSerious);
  thermal_devices_[0].NotifyObservers();
  EXPECT_EQ(0, dbus_wrapper_.num_sent_signals());

  // Charger: Serious, Processor: Fair, Power: AC -> Serious.
  AdvanceTime(base::Seconds(1));
  handler_.HandlePowerSourceChange(PowerSource::AC);
  EXPECT_EQ(DeviceThermalStateToProto(system::DeviceThermalState::kSerious),
            GetThermalEventThermalState());
  EXPECT_EQ(Now(), GetThermalEventTimestamp());
  dbus_wrapper_.ClearSentSignals();
}

TEST_F(ThermalEventHandlerTest, GetThermalState) {
  ThermalEvent proto;
  system::DeviceThermalState states[] = {
      system::DeviceThermalState::kNominal,
      system::DeviceThermalState::kSerious,
      system::DeviceThermalState::kUnknown,
      system::DeviceThermalState::kCritical,
      system::DeviceThermalState::kFair,
  };

  thermal_devices_[0].set_thermal_state(system::DeviceThermalState::kUnknown);

  for (const auto& state : states) {
    AdvanceTime(base::Seconds(1));
    thermal_devices_[1].set_thermal_state(state);
    thermal_devices_[1].NotifyObservers();
    dbus::MethodCall method_call(kPowerManagerInterface,
                                 kGetThermalStateMethod);
    std::unique_ptr<dbus::Response> response =
        dbus_wrapper_.CallExportedMethodSync(&method_call);
    ASSERT_TRUE(response);
    proto.Clear();
    ASSERT_TRUE(
        dbus::MessageReader(response.get()).PopArrayOfBytesAsProto(&proto));
    EXPECT_EQ(DeviceThermalStateToProto(state), proto.thermal_state());
    EXPECT_EQ(Now(), base::TimeTicks() + base::Microseconds(proto.timestamp()));
    dbus_wrapper_.ClearSentSignals();
    proto.Clear();
  }
}

}  // namespace power_manager::policy
