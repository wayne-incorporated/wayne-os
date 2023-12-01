// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/display/display_power_setter.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/logging.h"
#include <base/check.h>
#include <base/functional/bind.h>
#include <base/run_loop.h>
#include <base/test/simple_test_tick_clock.h>
#include <chromeos/dbus/service_constants.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "power_manager/powerd/system/dbus_wrapper_stub.h"
#include "power_manager/powerd/testing/test_environment.h"

namespace power_manager {
namespace system {
namespace {

class DisplayPowerSetterTest : public TestEnvironment {
 public:
  DisplayPowerSetterTest() {
    display_service_proxy_ = dbus_wrapper_.GetObjectProxy(
        chromeos::kDisplayServiceName, chromeos::kDisplayServicePath);
    dbus_wrapper_.SetMethodCallback(base::BindRepeating(
        &DisplayPowerSetterTest::HandleMethodCall, base::Unretained(this)));
    display_power_setter_.Init(&dbus_wrapper_);
    dbus_wrapper_.NotifyServiceAvailable(display_service_proxy_, true);
  }
  DisplayPowerSetterTest(const DisplayPowerSetterTest&) = delete;
  DisplayPowerSetterTest& operator=(const DisplayPowerSetterTest&) = delete;

  ~DisplayPowerSetterTest() override {}

  // Mock display service.
  //
  // `DisplayPowerSetter` makes external DBus calls to a display service.
  // This test fixture intercepts these calls, deserializes them in
  // `HandleMethodCall`, and calls into this mock object, making it easier
  // for tests to verify what DBus calls were issued.
  class MockDisplayService {
   public:
    MOCK_METHOD(void, SetDimming, (bool dimming));
    MOCK_METHOD(void, SetPowerState, (chromeos::DisplayPowerState state));
  };

 protected:
  DBusWrapperStub dbus_wrapper_;
  dbus::ObjectProxy* display_service_proxy_ = nullptr;
  DisplayPowerSetter display_power_setter_;
  MockDisplayService mock_display_service_;
  base::RunLoop loop;
  base::RepeatingCallback<void()> completed_callback = base::BindRepeating(
      [](base::OnceClosure closure) { std::move(closure).Run(); },
      loop.QuitClosure());

  // Internal state for tests.
  bool dimming_ = false;
  chromeos::DisplayPowerState power_state_ = chromeos::DISPLAY_POWER_ALL_ON;

 private:
  // DBusWrapperStub::MethodCallback implementation used to handle D-Bus calls
  // from |display_power_setter_|.
  std::unique_ptr<dbus::Response> HandleMethodCall(
      dbus::ObjectProxy* proxy, dbus::MethodCall* method_call) {
    if (proxy != display_service_proxy_) {
      ADD_FAILURE() << "Unhandled method call to proxy " << proxy;
      return nullptr;
    }
    if (method_call->GetInterface() != chromeos::kDisplayServiceInterface) {
      ADD_FAILURE() << "Unhandled method call to interface "
                    << method_call->GetInterface();
      return nullptr;
    }

    std::unique_ptr<dbus::Response> response =
        dbus::Response::FromMethodCall(method_call);
    const std::string member = method_call->GetMember();
    dbus::MessageReader reader = dbus::MessageReader(method_call);
    if (member == chromeos::kDisplayServiceSetPowerMethod) {
      int32_t power_state_arg;
      EXPECT_TRUE(reader.PopInt32(&power_state_arg));
      mock_display_service_.SetPowerState(
          static_cast<chromeos::DisplayPowerState>(power_state_arg));
    } else if (member == chromeos::kDisplayServiceSetSoftwareDimmingMethod) {
      bool dimming;
      EXPECT_TRUE(reader.PopBool(&dimming));
      mock_display_service_.SetDimming(dimming);

    } else {
      ADD_FAILURE() << "Unhandled method call to member " << member;
      return nullptr;
    }
    completed_callback.Run();
    return response;
  }
};

TEST_F(DisplayPowerSetterTest, SetDimmingOn) {
  EXPECT_CALL(mock_display_service_, SetDimming(true));
  display_power_setter_.SetDisplaySoftwareDimming(true);
  loop.Run();
}

TEST_F(DisplayPowerSetterTest, SetDimmingOff) {
  EXPECT_CALL(mock_display_service_, SetDimming(false));
  display_power_setter_.SetDisplaySoftwareDimming(false);
  loop.Run();
}

TEST_F(DisplayPowerSetterTest, SetPowerImmediate) {
  EXPECT_CALL(mock_display_service_,
              SetPowerState(chromeos::DISPLAY_POWER_ALL_OFF));
  display_power_setter_.SetDisplayPower(chromeos::DISPLAY_POWER_ALL_OFF,
                                        base::Seconds(0));
  loop.Run();
}

TEST_F(DisplayPowerSetterTest, SetPowerDelayed) {
  EXPECT_CALL(mock_display_service_,
              SetPowerState(chromeos::DISPLAY_POWER_ALL_OFF));
  display_power_setter_.SetDisplayPower(chromeos::DISPLAY_POWER_ALL_OFF,
                                        base::Milliseconds(1000));
  display_power_setter_.FireTimerForTesting();
  loop.Run();
}

TEST_F(DisplayPowerSetterTest, SetPowerTwice) {
  EXPECT_CALL(mock_display_service_,
              SetPowerState(chromeos::DISPLAY_POWER_INTERNAL_OFF_EXTERNAL_ON));
  display_power_setter_.SetDisplayPower(chromeos::DISPLAY_POWER_ALL_OFF,
                                        base::Milliseconds(1500));
  display_power_setter_.SetDisplayPower(
      chromeos::DISPLAY_POWER_INTERNAL_OFF_EXTERNAL_ON,
      base::Milliseconds(1000));
  display_power_setter_.FireTimerForTesting();
  loop.Run();
}

}  // namespace
}  // namespace system
}  // namespace power_manager
