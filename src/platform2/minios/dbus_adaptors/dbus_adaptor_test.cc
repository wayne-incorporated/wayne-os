// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>
#include <linux/input.h>

#include "minios/dbus_adaptors/dbus_adaptor.h"
#include "minios/mock_minios.h"
#include "minios/mock_network_manager.h"

namespace minios {

class DBusServiceTest : public testing::Test {
 public:
  DBusServiceTest()
      : mock_mini_os_(std::make_shared<MockMiniOs>()),
        mock_network_manager_(std::make_shared<MockNetworkManager>()),
        dbus_service_(std::make_unique<DBusService>(mock_mini_os_,
                                                    mock_network_manager_)) {}

 protected:
  std::shared_ptr<MockMiniOs> mock_mini_os_;
  std::shared_ptr<MockNetworkManager> mock_network_manager_;
  std::unique_ptr<DBusService> dbus_service_;

 private:
  DBusServiceTest(const DBusServiceTest&) = delete;
  DBusServiceTest& operator=(const DBusServiceTest&) = delete;
};

TEST_F(DBusServiceTest, GetState) {
  State mini_os_state;
  EXPECT_CALL(*mock_mini_os_, GetState(&mini_os_state, nullptr))
      .WillOnce(testing::Return(true));
  EXPECT_TRUE(dbus_service_->GetState(nullptr, &mini_os_state));
}

TEST_F(DBusServiceTest, NextScreen) {
  EXPECT_CALL(*mock_mini_os_, NextScreen(nullptr))
      .WillOnce(testing::Return(false));
  EXPECT_FALSE(dbus_service_->NextScreen(nullptr));
}

TEST_F(DBusServiceTest, PressKey) {
  EXPECT_CALL(*mock_mini_os_, PressKey(KEY_ENTER));
  EXPECT_TRUE(dbus_service_->PressKey(nullptr, KEY_ENTER));
}

TEST_F(DBusServiceTest, PrevScreen) {
  EXPECT_CALL(*mock_mini_os_, PrevScreen(nullptr))
      .WillOnce(testing::Return(true));
  EXPECT_TRUE(dbus_service_->PrevScreen(nullptr));
}

TEST_F(DBusServiceTest, ResetState) {
  EXPECT_CALL(*mock_mini_os_, Reset(nullptr)).WillOnce(testing::Return(true));
  EXPECT_TRUE(dbus_service_->ResetState(nullptr));
}

TEST_F(DBusServiceTest, SetNetworkCredentials) {
  std::string ssid("test1");
  std::string passphrase("pass1");
  EXPECT_CALL(*mock_mini_os_, SetNetworkCredentials(ssid, passphrase));
  dbus_service_->SetNetworkCredentials(nullptr, ssid, passphrase);
}

TEST_F(DBusServiceTest, StartRecovery) {
  std::string ssid("test1");
  std::string passphrase("pass1");
  EXPECT_CALL(*mock_mini_os_, StartRecovery(ssid, passphrase));
  EXPECT_TRUE(dbus_service_->StartRecovery(nullptr, ssid, passphrase));
}

}  // namespace minios
