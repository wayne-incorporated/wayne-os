// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include "minios/mock_draw_interface.h"
#include "minios/mock_screen_controller.h"
#include "minios/screens/screen_debug_options.h"

using ::testing::NiceMock;
using ::testing::StrictMock;

namespace minios {

class ScreenDebugOptionsTest : public ::testing::Test {
 protected:
  std::shared_ptr<MockDrawInterface> mock_draw_interface_ =
      std::make_shared<NiceMock<MockDrawInterface>>();
  MockDrawInterface* mock_draw_interface_ptr_ = mock_draw_interface_.get();
  StrictMock<MockScreenControllerInterface> mock_screen_controller_;

  ScreenDebugOptions screen_debug_options_{mock_draw_interface_,
                                           &mock_screen_controller_};
};

TEST_F(ScreenDebugOptionsTest, GetState) {
  EXPECT_CALL(mock_screen_controller_, OnStateChanged);
  screen_debug_options_.Show();
  EXPECT_EQ(State::DEBUG_OPTIONS, screen_debug_options_.GetState().state());
}

TEST_F(ScreenDebugOptionsTest, MoveForward) {
  EXPECT_CALL(mock_screen_controller_, OnForward(&screen_debug_options_));
  EXPECT_TRUE(screen_debug_options_.MoveForward(nullptr));
}

TEST_F(ScreenDebugOptionsTest, MoveBackward) {
  EXPECT_CALL(mock_screen_controller_, OnBackward(&screen_debug_options_));
  EXPECT_TRUE(screen_debug_options_.MoveBackward(nullptr));
}

}  // namespace minios
