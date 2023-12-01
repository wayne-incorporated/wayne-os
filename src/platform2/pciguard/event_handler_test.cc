// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>

#include "pciguard/event_handler.h"

#include <base/logging.h>

using ::testing::_;

namespace pciguard {

namespace {

constexpr char kMockTestDevice1[] =
    "/sys/devices/pci0000:00/0000:00:0d.2/domain0/0-0/0-1";
constexpr char kMockTestDevice2[] =
    "/sys/devices/pci0000:00/0000:00:0d.2/domain0/0-0/0-2";

class MockSysfsUtils : public SysfsUtils {
 public:
  MOCK_METHOD(int, AuthorizeThunderboltDev, (base::FilePath devpath), ());
  MOCK_METHOD(int, AuthorizeAllDevices, (), ());
  MOCK_METHOD(int, DeauthorizeAllDevices, (), ());
  MOCK_METHOD(int, DenyNewDevices, (), ());
};

}  // namespace

class EventHandlerTest : public ::testing::Test {
 public:
  bool WaitForAuthorizerToFinish(EventHandler* event_handler) {
    std::lock_guard<std::mutex> lock(event_handler->lock_);

    if (!event_handler->authorizer_)
      return true;

    unsigned retries = 20;
    while (!event_handler->authorizer_->IsJobQueueEmpty() && retries--) {
      LOG(INFO) << "Waiting for Authorizer to empty the Job Queue";
      usleep(100000);  // 100 ms
    }
    if (!retries) {
      LOG(ERROR) << "Authorizer Queue still not empty after 20 retries";
      return false;
    }
    return true;
  }
};

// Check that if thunderbolt devices are plugged in before a user logs in,
// they are not authorized.
TEST_F(EventHandlerTest, CheckDevicesNotAuthorizedBeforeLogin) {
  auto mock_utils = std::make_unique<MockSysfsUtils>();

  EXPECT_CALL(*mock_utils, AuthorizeAllDevices()).Times(0);
  EXPECT_CALL(*mock_utils, AuthorizeThunderboltDev(_)).Times(0);

  auto event_handler = std::make_unique<EventHandler>(mock_utils.get());
  event_handler->OnNewThunderboltDev(base::FilePath(kMockTestDevice1));
  event_handler->OnNewThunderboltDev(base::FilePath(kMockTestDevice2));
  ASSERT_TRUE(WaitForAuthorizerToFinish(event_handler.get()));
}

// Check that thunderbolt devices are plugged in before/after a user logs in,
// but before user provided permission, they are not authorized.
TEST_F(EventHandlerTest, CheckDevicesNotAuthorizedOnLoginBeforeUserPermission) {
  auto mock_utils = std::make_unique<MockSysfsUtils>();

  EXPECT_CALL(*mock_utils, AuthorizeAllDevices()).Times(0);
  EXPECT_CALL(*mock_utils, AuthorizeThunderboltDev(_)).Times(0);

  auto event_handler = std::make_unique<EventHandler>(mock_utils.get());
  event_handler->OnNewThunderboltDev(base::FilePath(kMockTestDevice1));
  event_handler->OnUserLogin();
  event_handler->OnNewThunderboltDev(base::FilePath(kMockTestDevice2));
  ASSERT_TRUE(WaitForAuthorizerToFinish(event_handler.get()));
}

// Check that all plugged in devices are authorized once a user is logged in,
// and provides permission.
TEST_F(EventHandlerTest, CheckAllDevicesAuthorizedOnUserPermission) {
  auto mock_utils = std::make_unique<MockSysfsUtils>();

  EXPECT_CALL(*mock_utils, AuthorizeAllDevices()).Times(1);
  EXPECT_CALL(*mock_utils, AuthorizeThunderboltDev(_)).Times(0);

  auto event_handler = std::make_unique<EventHandler>(mock_utils.get());
  event_handler->OnNewThunderboltDev(base::FilePath(kMockTestDevice1));
  event_handler->OnUserLogin();
  event_handler->OnNewThunderboltDev(base::FilePath(kMockTestDevice2));
  event_handler->OnUserPermissionChanged(true);
  ASSERT_TRUE(WaitForAuthorizerToFinish(event_handler.get()));
}

// Check that all devices plugged in after user permission are authorized.
TEST_F(EventHandlerTest, CheckNewDevicesAuthorizedAfterUserPermission) {
  auto mock_utils = std::make_unique<MockSysfsUtils>();

  EXPECT_CALL(*mock_utils, AuthorizeAllDevices()).Times(1);
  EXPECT_CALL(*mock_utils,
              AuthorizeThunderboltDev(base::FilePath(kMockTestDevice1)))
      .Times(1);
  EXPECT_CALL(*mock_utils,
              AuthorizeThunderboltDev(base::FilePath(kMockTestDevice2)))
      .Times(1);

  auto event_handler = std::make_unique<EventHandler>(mock_utils.get());
  event_handler->OnUserLogin();
  event_handler->OnUserPermissionChanged(true);
  event_handler->OnNewThunderboltDev(base::FilePath(kMockTestDevice1));
  event_handler->OnNewThunderboltDev(base::FilePath(kMockTestDevice2));
  ASSERT_TRUE(WaitForAuthorizerToFinish(event_handler.get()));
}

// Check that if the user decides to remove the permission, any authorized
// devices are deauthorized
TEST_F(EventHandlerTest, CheckDevicesDeauthorizedAfterUserRevokesPermission) {
  auto mock_utils = std::make_unique<MockSysfsUtils>();

  EXPECT_CALL(*mock_utils, AuthorizeAllDevices()).Times(1);
  EXPECT_CALL(*mock_utils, DeauthorizeAllDevices()).Times(1);

  auto event_handler = std::make_unique<EventHandler>(mock_utils.get());
  event_handler->OnNewThunderboltDev(base::FilePath(kMockTestDevice1));
  event_handler->OnNewThunderboltDev(base::FilePath(kMockTestDevice2));
  event_handler->OnUserLogin();
  event_handler->OnUserPermissionChanged(true);
  ASSERT_TRUE(WaitForAuthorizerToFinish(event_handler.get()));
  event_handler->OnUserPermissionChanged(false);
}

// Check that if the user locks the screen, any devices plugged in after
// screen is locked are not authorized.
TEST_F(EventHandlerTest, CheckNewDevicesNotAuthorizedAfterScreenLocked) {
  auto mock_utils = std::make_unique<MockSysfsUtils>();

  EXPECT_CALL(*mock_utils, AuthorizeAllDevices()).Times(1);
  EXPECT_CALL(*mock_utils, AuthorizeThunderboltDev(_)).Times(0);
  EXPECT_CALL(*mock_utils, DenyNewDevices()).Times(1);

  auto event_handler = std::make_unique<EventHandler>(mock_utils.get());
  event_handler->OnUserLogin();
  event_handler->OnUserPermissionChanged(true);
  ASSERT_TRUE(WaitForAuthorizerToFinish(event_handler.get()));
  event_handler->OnScreenLocked();
  event_handler->OnNewThunderboltDev(base::FilePath(kMockTestDevice1));
  event_handler->OnNewThunderboltDev(base::FilePath(kMockTestDevice2));
  ASSERT_TRUE(WaitForAuthorizerToFinish(event_handler.get()));
}

// Check that any devices plugged in during screen locked, are authorized
// when the screen gets unlocked.
TEST_F(EventHandlerTest, CheckNewDevicesDuringScreenLockGetAuthorizedOnUnlock) {
  auto mock_utils = std::make_unique<MockSysfsUtils>();

  EXPECT_CALL(*mock_utils, AuthorizeAllDevices()).Times(2);
  EXPECT_CALL(*mock_utils, AuthorizeThunderboltDev(_)).Times(0);
  EXPECT_CALL(*mock_utils, DenyNewDevices()).Times(1);

  auto event_handler = std::make_unique<EventHandler>(mock_utils.get());
  event_handler->OnUserLogin();
  event_handler->OnUserPermissionChanged(true);
  ASSERT_TRUE(WaitForAuthorizerToFinish(event_handler.get()));
  event_handler->OnScreenLocked();
  event_handler->OnNewThunderboltDev(base::FilePath(kMockTestDevice1));
  event_handler->OnNewThunderboltDev(base::FilePath(kMockTestDevice2));
  event_handler->OnScreenUnlocked();
  ASSERT_TRUE(WaitForAuthorizerToFinish(event_handler.get()));
}

// Check that all authorized devices are deauthorized on user logout
TEST_F(EventHandlerTest, CheckAllDevicesDeauthorizedOnUserLogout) {
  auto mock_utils = std::make_unique<MockSysfsUtils>();

  EXPECT_CALL(*mock_utils, AuthorizeAllDevices()).Times(1);
  EXPECT_CALL(*mock_utils, DeauthorizeAllDevices()).Times(1);

  auto event_handler = std::make_unique<EventHandler>(mock_utils.get());
  event_handler->OnNewThunderboltDev(base::FilePath(kMockTestDevice1));
  event_handler->OnNewThunderboltDev(base::FilePath(kMockTestDevice2));
  event_handler->OnUserLogin();
  event_handler->OnUserPermissionChanged(true);
  ASSERT_TRUE(WaitForAuthorizerToFinish(event_handler.get()));
  event_handler->OnUserLogout();
}

// Check that User permission cannot be enabled before login
// (Thus cannot go to a new less restrictive state, unless you meet the
//  prerequisites for current state).)
TEST_F(EventHandlerTest, CheckUserPermissionEnableIgnoredBeforeLogin) {
  auto mock_utils = std::make_unique<MockSysfsUtils>();

  EXPECT_CALL(*mock_utils, AuthorizeAllDevices()).Times(0);
  EXPECT_CALL(*mock_utils, AuthorizeThunderboltDev(_)).Times(0);

  auto event_handler = std::make_unique<EventHandler>(mock_utils.get());
  event_handler->OnNewThunderboltDev(base::FilePath(kMockTestDevice1));
  event_handler->OnNewThunderboltDev(base::FilePath(kMockTestDevice2));
  event_handler->OnUserPermissionChanged(true);
  ASSERT_TRUE(WaitForAuthorizerToFinish(event_handler.get()));
}

// Check that User permission cannot be enabled during screen locked
// (Thus cannot go to a new less restrictive state, unless you meet the
//  prerequisites for current state).
TEST_F(EventHandlerTest, CheckUserPermissionEnableIgnoredWhileScreenLocked) {
  auto mock_utils = std::make_unique<MockSysfsUtils>();

  EXPECT_CALL(*mock_utils, AuthorizeAllDevices()).Times(0);
  EXPECT_CALL(*mock_utils, AuthorizeThunderboltDev(_)).Times(0);
  EXPECT_CALL(*mock_utils, DenyNewDevices()).Times(1);

  auto event_handler = std::make_unique<EventHandler>(mock_utils.get());
  event_handler->OnUserLogin();
  event_handler->OnScreenLocked();
  event_handler->OnUserPermissionChanged(true);
  event_handler->OnNewThunderboltDev(base::FilePath(kMockTestDevice1));
  event_handler->OnNewThunderboltDev(base::FilePath(kMockTestDevice2));
  event_handler->OnScreenUnlocked();
  ASSERT_TRUE(WaitForAuthorizerToFinish(event_handler.get()));
}

// Check that User permission can be disabled during screen locked
// (It is allowed to go to a more restricted state, regardless of the
//  current state).
TEST_F(EventHandlerTest, CheckUserPermissionDisableHonoredWhileScreenLocked) {
  auto mock_utils = std::make_unique<MockSysfsUtils>();

  EXPECT_CALL(*mock_utils, AuthorizeAllDevices()).Times(1);
  EXPECT_CALL(*mock_utils, AuthorizeThunderboltDev(_)).Times(0);
  EXPECT_CALL(*mock_utils, DenyNewDevices()).Times(1);
  EXPECT_CALL(*mock_utils, DeauthorizeAllDevices()).Times(1);

  auto event_handler = std::make_unique<EventHandler>(mock_utils.get());
  event_handler->OnNewThunderboltDev(base::FilePath(kMockTestDevice1));
  event_handler->OnNewThunderboltDev(base::FilePath(kMockTestDevice2));
  event_handler->OnUserLogin();
  event_handler->OnUserPermissionChanged(true);
  ASSERT_TRUE(WaitForAuthorizerToFinish(event_handler.get()));
  event_handler->OnScreenLocked();
  event_handler->OnUserPermissionChanged(false);
}

// Check that a User Login request is ignored on locked screen
// (Thus cannot go to a new less restrictive state, unless you meet the
//  prerequisites for current state).
TEST_F(EventHandlerTest, CheckUserLoginIgnoredWhileScreenLocked) {
  auto mock_utils = std::make_unique<MockSysfsUtils>();

  EXPECT_CALL(*mock_utils, AuthorizeAllDevices()).Times(1);
  EXPECT_CALL(*mock_utils, AuthorizeThunderboltDev(_)).Times(0);
  EXPECT_CALL(*mock_utils, DenyNewDevices()).Times(1);

  auto event_handler = std::make_unique<EventHandler>(mock_utils.get());
  event_handler->OnUserLogin();
  event_handler->OnUserPermissionChanged(true);
  ASSERT_TRUE(WaitForAuthorizerToFinish(event_handler.get()));
  event_handler->OnScreenLocked();
  event_handler->OnNewThunderboltDev(base::FilePath(kMockTestDevice1));
  event_handler->OnUserLogin();
  event_handler->OnNewThunderboltDev(base::FilePath(kMockTestDevice2));
  ASSERT_TRUE(WaitForAuthorizerToFinish(event_handler.get()));
}

// Check that a User Logout request is honored on locked screen
// (It is allowed to go to a more restricted state, regardless of the
//  current state).
TEST_F(EventHandlerTest, CheckUserLogoutHonoredWhileScreenLocked) {
  auto mock_utils = std::make_unique<MockSysfsUtils>();

  EXPECT_CALL(*mock_utils, AuthorizeAllDevices()).Times(1);
  EXPECT_CALL(*mock_utils, AuthorizeThunderboltDev(_)).Times(0);
  EXPECT_CALL(*mock_utils, DenyNewDevices()).Times(1);
  EXPECT_CALL(*mock_utils, DeauthorizeAllDevices()).Times(1);

  auto event_handler = std::make_unique<EventHandler>(mock_utils.get());
  event_handler->OnNewThunderboltDev(base::FilePath(kMockTestDevice1));
  event_handler->OnNewThunderboltDev(base::FilePath(kMockTestDevice2));
  event_handler->OnUserLogin();
  event_handler->OnUserPermissionChanged(true);
  ASSERT_TRUE(WaitForAuthorizerToFinish(event_handler.get()));
  event_handler->OnScreenLocked();
  event_handler->OnUserLogout();
}

// Check that a Screen unlock is not honored unless a user is signed in
// (Thus cannot go to a new less restrictive state, unless you meet the
//  prerequisites for current state).
TEST_F(EventHandlerTest, CheckScreenUnlockIgnoredIfNoUserLogin) {
  auto mock_utils = std::make_unique<MockSysfsUtils>();

  EXPECT_CALL(*mock_utils, AuthorizeAllDevices()).Times(0);
  EXPECT_CALL(*mock_utils, AuthorizeThunderboltDev(_)).Times(0);

  auto event_handler = std::make_unique<EventHandler>(mock_utils.get());
  event_handler->OnNewThunderboltDev(base::FilePath(kMockTestDevice1));
  event_handler->OnNewThunderboltDev(base::FilePath(kMockTestDevice2));
  event_handler->OnUserPermissionChanged(true);
  ASSERT_TRUE(WaitForAuthorizerToFinish(event_handler.get()));
  event_handler->OnScreenUnlocked();
  ASSERT_TRUE(WaitForAuthorizerToFinish(event_handler.get()));
}

}  // namespace pciguard
