// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <base/check_op.h>
#include <base/strings/stringprintf.h>
#include <gtest/gtest.h>

#include "power_manager/common/action_recorder.h"
#include "power_manager/common/fake_prefs.h"
#include "power_manager/common/power_constants.h"
#include "power_manager/powerd/policy/user_proximity_handler.h"
#include "power_manager/powerd/system/user_proximity_observer.h"
#include "power_manager/powerd/system/user_proximity_watcher_stub.h"
#include "power_manager/powerd/testing/test_environment.h"

namespace power_manager::policy {

namespace {

constexpr char kWifiSensorDetected[] = "WifiDelegate::ProximitySensorDetected";
constexpr char kLteSensorDetected[] = "LteDelegate::ProximitySensorDetected";

constexpr char kWifiChangeNear[] = "WifiDelegate::HandleProximityChange(near)";
constexpr char kWifiChangeFar[] = "WifiDelegate::HandleProximityChange(far)";

class WifiDelegate : public UserProximityHandler::Delegate,
                     public ActionRecorder {
 public:
  WifiDelegate() = default;
  ~WifiDelegate() override = default;

  // UserProximityHandler::Delegate overrides:
  void ProximitySensorDetected(UserProximity value) override {
    AppendAction(kWifiSensorDetected);
  }
  void HandleProximityChange(UserProximity value) override {
    auto action = base::StringPrintf("WifiDelegate::HandleProximityChange(%s)",
                                     UserProximityToString(value).c_str());
    AppendAction(action);
  }
};

class LteDelegate : public UserProximityHandler::Delegate,
                    public ActionRecorder {
 public:
  LteDelegate() = default;
  ~LteDelegate() override = default;

  // UserProximityHandler::Delegate overrides:
  void ProximitySensorDetected(UserProximity value) override {
    AppendAction(kLteSensorDetected);
  }
  void HandleProximityChange(UserProximity value) override {
    auto action = base::StringPrintf("LteDelegate::HandleProximityChange(%s)",
                                     UserProximityToString(value).c_str());
    AppendAction(action);
  }
};

class UserProximityHandlerTest : public TestEnvironment {
 public:
  UserProximityHandlerTest() = default;
  UserProximityHandlerTest(const UserProximityHandlerTest&) = delete;
  UserProximityHandlerTest& operator=(const UserProximityHandlerTest&) = delete;

  ~UserProximityHandlerTest() override = default;

 protected:
  void Init(bool honor_prefer_far) {
    prefs_.SetInt64(kSetTransmitPowerPreferFarForProximityPref,
                    honor_prefer_far);
    user_proximity_handler_.Init(&user_proximity_watcher_, &wifi_delegate_,
                                 &lte_delegate_, &prefs_);
  }
  system::UserProximityWatcherStub user_proximity_watcher_;
  WifiDelegate wifi_delegate_;
  LteDelegate lte_delegate_;
  FakePrefs prefs_;
  UserProximityHandler user_proximity_handler_;
};

}  // namespace

TEST_F(UserProximityHandlerTest, DetectSensor) {
  Init(false);
  user_proximity_watcher_.AddSensor(
      1, system::UserProximityObserver::SensorRole::SENSOR_ROLE_WIFI);
  CHECK_EQ(JoinActions(kWifiSensorDetected, nullptr),
           wifi_delegate_.GetActions());

  user_proximity_watcher_.AddSensor(
      1, system::UserProximityObserver::SensorRole::SENSOR_ROLE_LTE);
  CHECK_EQ(JoinActions(kLteSensorDetected, nullptr),
           lte_delegate_.GetActions());
}

TEST_F(UserProximityHandlerTest, ProximityChange) {
  Init(false);
  user_proximity_watcher_.AddSensor(
      1, system::UserProximityObserver::SensorRole::SENSOR_ROLE_WIFI);
  user_proximity_watcher_.AddSensor(
      2, system::UserProximityObserver::SensorRole::SENSOR_ROLE_WIFI);
  wifi_delegate_.GetActions();  //  consume the detection events

  user_proximity_watcher_.SendEvent(1, UserProximity::FAR);
  CHECK_EQ(JoinActions(nullptr), wifi_delegate_.GetActions());

  user_proximity_watcher_.SendEvent(2, UserProximity::FAR);
  CHECK_EQ(JoinActions(kWifiChangeFar, nullptr), wifi_delegate_.GetActions());

  user_proximity_watcher_.SendEvent(1, UserProximity::NEAR);
  CHECK_EQ(JoinActions(kWifiChangeNear, nullptr), wifi_delegate_.GetActions());
  user_proximity_watcher_.SendEvent(2, UserProximity::NEAR);
  CHECK_EQ(JoinActions(nullptr), wifi_delegate_.GetActions());
}

}  // namespace power_manager::policy
