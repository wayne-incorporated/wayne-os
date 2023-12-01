// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include "minios/mock_draw_interface.h"
#include "minios/mock_screen_controller.h"
#include "minios/screens/screen_log.h"

using ::testing::NiceMock;
using ::testing::StrictMock;

namespace minios {

class ScreenLogTest : public ::testing::Test {
 protected:
  std::shared_ptr<MockDrawInterface> mock_draw_interface_ =
      std::make_shared<NiceMock<MockDrawInterface>>();
  MockDrawInterface* mock_draw_interface_ptr_ = mock_draw_interface_.get();
  StrictMock<MockScreenControllerInterface> mock_screen_controller_;

  ScreenLog screen_log_{mock_draw_interface_, &mock_screen_controller_};
};

TEST_F(ScreenLogTest, GetState) {
  EXPECT_CALL(mock_screen_controller_, OnStateChanged);
  screen_log_.Show();
  EXPECT_EQ(State::DEBUG_LOGS, screen_log_.GetState().state());
}

TEST_F(ScreenLogTest, MoveForward) {
  EXPECT_FALSE(screen_log_.MoveForward(nullptr));
}

TEST_F(ScreenLogTest, MoveBackward) {
  EXPECT_CALL(mock_screen_controller_, OnBackward(&screen_log_));
  EXPECT_TRUE(screen_log_.MoveBackward(nullptr));
}

}  // namespace minios
