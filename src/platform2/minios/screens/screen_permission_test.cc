// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include "minios/mock_draw_interface.h"
#include "minios/mock_screen_controller.h"
#include "minios/screens/screen_permission.h"

using ::testing::NiceMock;
using ::testing::StrictMock;

namespace minios {

class ScreenPermissionTest : public ::testing::Test {
 protected:
  std::shared_ptr<MockDrawInterface> mock_draw_interface_ =
      std::make_shared<NiceMock<MockDrawInterface>>();
  MockDrawInterface* mock_draw_interface_ptr_ = mock_draw_interface_.get();
  StrictMock<MockScreenControllerInterface> mock_screen_controller_;

  ScreenPermission screen_permission_{mock_draw_interface_,
                                      &mock_screen_controller_};
};

TEST_F(ScreenPermissionTest, GetState) {
  EXPECT_CALL(mock_screen_controller_, OnStateChanged);
  screen_permission_.Show();
  EXPECT_EQ(State::CONNECTED, screen_permission_.GetState().state());
}

TEST_F(ScreenPermissionTest, MoveForward) {
  EXPECT_CALL(mock_screen_controller_, OnForward(&screen_permission_));
  EXPECT_TRUE(screen_permission_.MoveForward(nullptr));
}

TEST_F(ScreenPermissionTest, MoveBackward) {
  EXPECT_CALL(mock_screen_controller_, OnBackward(&screen_permission_));
  EXPECT_TRUE(screen_permission_.MoveBackward(nullptr));
}

}  // namespace minios
