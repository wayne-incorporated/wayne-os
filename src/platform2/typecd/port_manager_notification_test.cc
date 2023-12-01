// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "typecd/port_manager.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "typecd/mock_dbus_manager.h"
#include "typecd/mock_ec_util.h"
#include "typecd/mock_port.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::StrictMock;

namespace typecd {

class PortManagerNotificationTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Create a DBusObject.
    dbus_object_ = std::make_unique<brillo::dbus_utils::DBusObject>(
        nullptr, nullptr, dbus::ObjectPath(kTypecdServicePath));

    // Create PortManager, MockPort and MockDBusManager instances.
    port_manager_ = std::make_unique<PortManager>();
    dbus_manager_ =
        std::make_unique<StrictMock<MockDBusManager>>(dbus_object_.get());
    port_ = std::make_unique<MockPort>(base::FilePath("fakepath"), 0);
    ec_util_ = std::make_unique<MockECUtil>();

    // Expect |port_manager_| to execute the RunModeEntry guards.
    EXPECT_CALL(*port_, GetDataRole())
        .WillRepeatedly(testing::Return(DataRole::kHost));
    EXPECT_CALL(*port_, IsPartnerDiscoveryComplete())
        .WillRepeatedly(testing::Return(true));
    EXPECT_CALL(*port_, IsCableDiscoveryComplete())
        .WillRepeatedly(testing::Return(true));
  }

 public:
  std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object_;
  std::unique_ptr<PortManager> port_manager_;
  std::unique_ptr<MockDBusManager> dbus_manager_;
  std::unique_ptr<MockPort> port_;
  std::unique_ptr<MockECUtil> ec_util_;
};

// Test case for notifications during AP mode entry.
// Port enters USB4 and sends DeviceConnectedType::kThunderboltDp.
// - OWC TBT4 dock and Caldigit TBT4 cable.
TEST_F(PortManagerNotificationTest, ModeEntryUSB4NotifyThunderboltDp) {
  // Add OWC TBT4 dock and Caldigit TBT4 cable.
  AddOWCTBT4Dock(*port_);
  AddCalDigitTBT4Cable(*port_);

  // Set AP mode entry to true for test case covering AP driven mode entry.
  port_manager_->SetModeEntrySupported(true);

  // Set expectations for port to enter USB4.
  EXPECT_CALL(*port_, CanEnterTBTCompatibilityMode())
      .WillRepeatedly(testing::Return(ModeEntryResult::kSuccess));
  EXPECT_CALL(*port_, CanEnterDPAltMode(_))
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(*port_, CanEnterUSB4())
      .WillRepeatedly(testing::Return(ModeEntryResult::kSuccess));
  EXPECT_CALL(*ec_util_, EnterMode(0, TypeCMode::kUSB4))
      .WillRepeatedly(testing::Return(true));

  // Expect to send DeviceConnectedType::kThunderboltDp.
  EXPECT_CALL(*dbus_manager_,
              NotifyConnected(DeviceConnectedType::kThunderboltDp))
      .Times(1);

  // Configure |port_manager_| and run mode entry.
  port_manager_->SetUserActive(true);
  port_manager_->SetDBusManager(dbus_manager_.get());
  port_manager_->SetECUtil(ec_util_.get());
  port_manager_->ports_.insert(
      std::pair<int, std::unique_ptr<Port>>(0, std::move(port_)));
  port_manager_->RunModeEntry(0);
}

// Test case for notifications during AP mode entry.
// Port enters TBT and sends DeviceConnectedType::kThunderboltOnly.
// - Startech TB3DK2DPW dock and Caldigit TBT4 cable.
TEST_F(PortManagerNotificationTest, ModeEntryTBTNotifyThunderboltOnly) {
  // Add Startech TB3DK2DPW dock and Caldigit TBT4 cable.
  AddStartechTB3DK2DPWDock(*port_);
  AddCalDigitTBT4Cable(*port_);

  // Set AP mode entry to true for test case covering AP driven mode entry.
  port_manager_->SetModeEntrySupported(true);

  // Set expectations for port to enter TBT.
  EXPECT_CALL(*port_, CanEnterTBTCompatibilityMode())
      .WillRepeatedly(testing::Return(ModeEntryResult::kSuccess));
  EXPECT_CALL(*port_, CanEnterDPAltMode(_))
      .WillRepeatedly(testing::Return(false));
  EXPECT_CALL(*port_, CanEnterUSB4())
      .WillRepeatedly(testing::Return(ModeEntryResult::kPartnerError));
  EXPECT_CALL(*ec_util_, EnterMode(0, TypeCMode::kTBT))
      .WillRepeatedly(testing::Return(true));

  // Expect to send DeviceConnectedType::kThunderboltOnly.
  EXPECT_CALL(*dbus_manager_,
              NotifyConnected(DeviceConnectedType::kThunderboltOnly))
      .Times(1);

  // Configure |port_manager_| and run mode entry.
  port_manager_->SetUserActive(true);
  port_manager_->SetDBusManager(dbus_manager_.get());
  port_manager_->SetECUtil(ec_util_.get());
  port_manager_->ports_.insert(
      std::pair<int, std::unique_ptr<Port>>(0, std::move(port_)));
  port_manager_->RunModeEntry(0);
}

// Test case for notifications during AP mode entry.
// Port enters DP and sends no notifications.
// - Wimaxit display and Caldigit TBT4 cable.
TEST_F(PortManagerNotificationTest, ModeEntryDpAltModeNoNotifications) {
  // Add Wimaxit display and Caldigit TBT4 cable.
  AddWimaxitDisplay(*port_);
  AddCalDigitTBT4Cable(*port_);

  // Set AP mode entry to true for test case covering AP driven mode entry.
  port_manager_->SetModeEntrySupported(true);

  // Set expectations for port to enter DP.
  EXPECT_CALL(*port_, CanEnterTBTCompatibilityMode())
      .WillRepeatedly(testing::Return(ModeEntryResult::kPartnerError));
  EXPECT_CALL(*port_, CanEnterUSB4())
      .WillRepeatedly(testing::Return(ModeEntryResult::kPartnerError));
  EXPECT_CALL(*port_, CanEnterDPAltMode(_))
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(*ec_util_, EnterMode(0, TypeCMode::kDP))
      .WillRepeatedly(testing::Return(true));

  // Configure |port_manager_| and run mode entry.
  port_manager_->SetUserActive(true);
  port_manager_->SetDBusManager(dbus_manager_.get());
  port_manager_->SetECUtil(ec_util_.get());
  port_manager_->ports_.insert(
      std::pair<int, std::unique_ptr<Port>>(0, std::move(port_)));
  port_manager_->RunModeEntry(0);
}

// Test case for notifications during AP mode entry.
// Port enters USB4 and sends DeviceConnectedType::kThunderboltDp and
// CableWarningType::kSpeedLimitingCable.
// - OWC TBT4 dock with Anker USB 3.2 Gen2 cable.
TEST_F(PortManagerNotificationTest, ModeEntryUSB4NotifySpeedLimitingCable) {
  // Add OWC TBT4 dock with Anker USB 3.2 Gen2 cable.
  AddOWCTBT4Dock(*port_);
  AddAnkerUSB3p2Gen2Cable(*port_);

  // Set AP mode entry to true for test case covering AP driven mode entry.
  port_manager_->SetModeEntrySupported(true);

  // Set expectations for port to enter USB4.
  EXPECT_CALL(*port_, CanEnterTBTCompatibilityMode())
      .WillRepeatedly(testing::Return(ModeEntryResult::kSuccess));
  EXPECT_CALL(*port_, CanEnterDPAltMode(_))
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(*port_, CanEnterUSB4())
      .WillRepeatedly(testing::Return(ModeEntryResult::kSuccess));
  EXPECT_CALL(*ec_util_, EnterMode(0, TypeCMode::kUSB4))
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(*port_, CableLimitingUSBSpeed(false))
      .WillRepeatedly(testing::Return(true));

  // Expect to send DeviceConnectedType::kThunderboltDp and
  // CableWarningType::kSpeedLimitingCable.
  EXPECT_CALL(*dbus_manager_,
              NotifyConnected(DeviceConnectedType::kThunderboltDp))
      .Times(1);
  EXPECT_CALL(*dbus_manager_,
              NotifyCableWarning(CableWarningType::kSpeedLimitingCable))
      .Times(1);

  // Configure |port_manager_| and run mode entry.
  port_manager_->SetUserActive(true);
  port_manager_->SetDBusManager(dbus_manager_.get());
  port_manager_->SetECUtil(ec_util_.get());
  port_manager_->ports_.insert(
      std::pair<int, std::unique_ptr<Port>>(0, std::move(port_)));
  port_manager_->RunModeEntry(0);
}

// Test case for notifications during AP mode entry.
// Port enters TBT and sends DeviceConnectedType::kThunderboltDp and
// CableWarningType::kSpeedLimitingCable.
// - Thinkpad TBT3 dock and Anker USB 3.2 Gen2 passive cable.
TEST_F(PortManagerNotificationTest, ModeEntryTBTNotifySpeedLimitingCable) {
  // Add Thinkpad TBT3 Dock and Anker USB 3.2 Gen2 passive cable.
  AddThinkpadTBT3Dock(*port_);
  AddAnkerUSB3p2Gen2Cable(*port_);

  // Set AP mode entry to true for test case covering AP driven mode entry.
  port_manager_->SetModeEntrySupported(true);

  // Set expectations for port to enter TBT.
  EXPECT_CALL(*port_, CanEnterTBTCompatibilityMode())
      .WillRepeatedly(testing::Return(ModeEntryResult::kSuccess));
  EXPECT_CALL(*port_, CanEnterDPAltMode(_))
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(*port_, CanEnterUSB4())
      .WillRepeatedly(testing::Return(ModeEntryResult::kPartnerError));
  EXPECT_CALL(*ec_util_, EnterMode(0, TypeCMode::kTBT))
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(*port_, CableLimitingUSBSpeed(true))
      .WillRepeatedly(testing::Return(true));

  // Expect to send DeviceConnectedType::kThunderboltDp and
  // CableWarningType::kSpeedLimitingCable.
  EXPECT_CALL(*dbus_manager_,
              NotifyConnected(DeviceConnectedType::kThunderboltDp))
      .Times(1);
  EXPECT_CALL(*dbus_manager_,
              NotifyCableWarning(CableWarningType::kSpeedLimitingCable))
      .Times(1);

  // Configure |port_manager_| and run mode entry.
  port_manager_->SetUserActive(true);
  port_manager_->SetDBusManager(dbus_manager_.get());
  port_manager_->SetECUtil(ec_util_.get());
  port_manager_->ports_.insert(
      std::pair<int, std::unique_ptr<Port>>(0, std::move(port_)));
  port_manager_->RunModeEntry(0);
}

// Test case for notifications during AP mode entry.
// Port enters TBT and sends DeviceConnectedType::kThunderboltDp and
// CableWarningType::kInvalidUSB4ValidTBTCable.
// - OWC TBT4 dock and Belkin TBT3 active cable.
TEST_F(PortManagerNotificationTest,
       ModeEntryTBTNotifyInvalidUSB4ValidTBTCable) {
  // Add OWC TBT4 dock and Belkin TBT3 active cable.
  AddOWCTBT4Dock(*port_);
  AddBelkinTBT3ActiveCable(*port_);

  // Set AP mode entry to true for test case covering AP driven mode entry.
  port_manager_->SetModeEntrySupported(true);

  // Set expectations for port to enter TBT.
  EXPECT_CALL(*port_, CanEnterTBTCompatibilityMode())
      .WillRepeatedly(testing::Return(ModeEntryResult::kSuccess));
  EXPECT_CALL(*port_, CanEnterDPAltMode(_))
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(*port_, CanEnterUSB4())
      .WillRepeatedly(testing::Return(ModeEntryResult::kCableError));
  EXPECT_CALL(*ec_util_, EnterMode(0, TypeCMode::kTBT))
      .WillRepeatedly(testing::Return(true));

  // Expect to send DeviceConnectedType::kThunderboltDp and
  // CableWarningType::kInvalidUSB4ValidTBTCable.
  EXPECT_CALL(*dbus_manager_,
              NotifyConnected(DeviceConnectedType::kThunderboltDp))
      .Times(1);
  EXPECT_CALL(*dbus_manager_,
              NotifyCableWarning(CableWarningType::kInvalidUSB4ValidTBTCable))
      .Times(1);

  // Configure |port_manager_| and run mode entry.
  port_manager_->SetUserActive(true);
  port_manager_->SetDBusManager(dbus_manager_.get());
  port_manager_->SetECUtil(ec_util_.get());
  port_manager_->ports_.insert(
      std::pair<int, std::unique_ptr<Port>>(0, std::move(port_)));
  port_manager_->RunModeEntry(0);
}

// Test case for notifications during AP mode entry.
// Port enters DP and sends CableWarningType::kInvalidUSB4Cable).
// - OWC TBT4 dock and unbranded USB 2.0 cable.
TEST_F(PortManagerNotificationTest, ModeEntryDpAltModeNotifyInvalidUSB4Cable) {
  // Add OWC TBT4 dock and unbranded USB 2.0 cable.
  AddOWCTBT4Dock(*port_);
  AddUnbrandedUSB2Cable(*port_);

  // Set AP mode entry to true for test case covering AP driven mode entry.
  port_manager_->SetModeEntrySupported(true);

  // Set expectations for port to enter DP.
  EXPECT_CALL(*port_, CanEnterTBTCompatibilityMode())
      .WillRepeatedly(testing::Return(ModeEntryResult::kCableError));
  EXPECT_CALL(*port_, CanEnterUSB4())
      .WillRepeatedly(testing::Return(ModeEntryResult::kCableError));
  EXPECT_CALL(*port_, CanEnterDPAltMode(_))
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(*ec_util_, EnterMode(0, TypeCMode::kDP))
      .WillRepeatedly(testing::Return(true));

  // Expect to send CableWarningType::kInvalidUSB4Cable.
  EXPECT_CALL(*dbus_manager_,
              NotifyCableWarning(CableWarningType::kInvalidUSB4Cable))
      .Times(1);

  // Configure |port_manager_| and run mode entry.
  port_manager_->SetUserActive(true);
  port_manager_->SetDBusManager(dbus_manager_.get());
  port_manager_->SetECUtil(ec_util_.get());
  port_manager_->ports_.insert(
      std::pair<int, std::unique_ptr<Port>>(0, std::move(port_)));
  port_manager_->RunModeEntry(0);
}

// Test case for notifications during AP mode entry.
// Port enters DP and sends CableWarningType::kInvalidTBTCable.
// - Thinkpad TBT3 dock and unbranded USB 2.0 cable.
TEST_F(PortManagerNotificationTest, ModeEntryDpAltModeNotifyInvalidTBTCable) {
  // Add Thinkpad TBT3 dock and unbranded USB 2.0 cable.
  AddThinkpadTBT3Dock(*port_);
  AddUnbrandedUSB2Cable(*port_);

  // Set AP mode entry to true for test case covering AP driven mode entry.
  port_manager_->SetModeEntrySupported(true);

  // Set expectations for port to enter DP.
  EXPECT_CALL(*port_, CanEnterTBTCompatibilityMode())
      .WillRepeatedly(testing::Return(ModeEntryResult::kCableError));
  EXPECT_CALL(*port_, CanEnterUSB4())
      .WillRepeatedly(testing::Return(ModeEntryResult::kPartnerError));
  EXPECT_CALL(*port_, CanEnterDPAltMode(_))
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(*ec_util_, EnterMode(0, TypeCMode::kDP))
      .WillRepeatedly(testing::Return(true));

  // Expect to send CableWarningType::kInvalidTBTCable.
  EXPECT_CALL(*dbus_manager_,
              NotifyCableWarning(CableWarningType::kInvalidTBTCable))
      .Times(1);

  // Configure |port_manager_| and run mode entry.
  port_manager_->SetUserActive(true);
  port_manager_->SetDBusManager(dbus_manager_.get());
  port_manager_->SetECUtil(ec_util_.get());
  port_manager_->ports_.insert(
      std::pair<int, std::unique_ptr<Port>>(0, std::move(port_)));
  port_manager_->RunModeEntry(0);
}

// Test case for notifications during AP mode entry.
// Port enters DP and sends CableWarningType::kInvalidDpCable.
// - Add Wimaxit display and unbranded USB 2.0 cable.
TEST_F(PortManagerNotificationTest, ModeEntryDpAltModeNotifyInvalidDpCable) {
  // Add Wimaxit display and unbranded USB 2.0 cable.
  AddWimaxitDisplay(*port_);
  AddUnbrandedUSB2Cable(*port_);

  // Set AP mode entry to true for test case covering AP driven mode entry.
  port_manager_->SetModeEntrySupported(true);

  // Set expectations for port to enter DP.
  EXPECT_CALL(*port_, CanEnterTBTCompatibilityMode())
      .WillRepeatedly(testing::Return(ModeEntryResult::kPartnerError));
  EXPECT_CALL(*port_, CanEnterUSB4())
      .WillRepeatedly(testing::Return(ModeEntryResult::kPartnerError));
  EXPECT_CALL(*port_, CanEnterDPAltMode(_))
      .WillRepeatedly(DoAll(SetArgPointee<0>(true), testing::Return(true)));
  EXPECT_CALL(*ec_util_, EnterMode(0, TypeCMode::kDP))
      .WillRepeatedly(testing::Return(true));

  // Expect to send CableWarningType::kInvalidDpCable
  EXPECT_CALL(*dbus_manager_,
              NotifyCableWarning(CableWarningType::kInvalidDpCable))
      .Times(1);

  // Configure |port_manager_| and run mode entry.
  port_manager_->SetUserActive(true);
  port_manager_->SetDBusManager(dbus_manager_.get());
  port_manager_->SetECUtil(ec_util_.get());
  port_manager_->ports_.insert(
      std::pair<int, std::unique_ptr<Port>>(0, std::move(port_)));
  port_manager_->RunModeEntry(0);
}

// Test case for notifications during EC mode entry.
// Port does not enter mode, or send any notifications.
// - OWC TBT4 dock and Caldigit TBT4 cable.
TEST_F(PortManagerNotificationTest, ECModeEntryNoCableNotification) {
  // Add OWC TBT4 dock and Caldigit TBT4 cable.
  AddOWCTBT4Dock(*port_);
  AddCalDigitTBT4Cable(*port_);

  // Set AP mode entry to false for test case covering EC driven mode entry.
  port_manager_->SetModeEntrySupported(false);

  // Expect |port_manager| to check for cable notifications. This happens
  // when GetModeEntrySupported returns false.
  EXPECT_CALL(*port_, CanEnterDPAltMode(_))
      .WillOnce(DoAll(SetArgPointee<0>(false), Return(true)));

  // Configure |port_manager| and run mode entry.
  port_manager_->SetUserActive(true);
  port_manager_->SetDBusManager(dbus_manager_.get());
  port_manager_->SetECUtil(ec_util_.get());
  port_manager_->ports_.insert(
      std::pair<int, std::unique_ptr<Port>>(0, std::move(port_)));
  port_manager_->RunModeEntry(0);
}

// Test case for notifications during EC mode entry.
// Port does not enter a mode, but sends CableWarningType::kInvalidDpCable.
// - OWC TBT4 dock and unbranded USB 2.0 cable.
TEST_F(PortManagerNotificationTest, ECModeEntryNotifyInvalidDpCable) {
  // Add OWC TBT4 dock and unbranded USB 2.0 cable.
  AddOWCTBT4Dock(*port_);
  AddUnbrandedUSB2Cable(*port_);

  // Set AP mode entry to false for test case covering EC driven mode entry.
  port_manager_->SetModeEntrySupported(false);

  // Expect |port_manager| to check for cable notifications. This happens
  // when GetModeEntrySupported returns false.
  EXPECT_CALL(*port_, CanEnterDPAltMode(_))
      .WillRepeatedly(DoAll(SetArgPointee<0>(true), Return(true)));

  // Expect to send CableWarningType::kInvalidDpCable.
  EXPECT_CALL(*dbus_manager_,
              NotifyCableWarning(CableWarningType::kInvalidDpCable))
      .Times(1);

  // Configure |port_manager| and run mode entry.
  port_manager_->SetUserActive(true);
  port_manager_->SetDBusManager(dbus_manager_.get());
  port_manager_->SetECUtil(ec_util_.get());
  port_manager_->ports_.insert(
      std::pair<int, std::unique_ptr<Port>>(0, std::move(port_)));
  port_manager_->RunModeEntry(0);
}

}  // namespace typecd
