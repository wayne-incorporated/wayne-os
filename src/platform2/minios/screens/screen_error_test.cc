// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include "minios/mock_draw_interface.h"
#include "minios/mock_screen_controller.h"
#include "minios/screen_types.h"
#include "minios/screens/screen_error.h"

using ::testing::NiceMock;
using ::testing::StrictMock;

namespace minios {

class ScreenErrorTest : public ::testing::Test {
 protected:
  std::shared_ptr<MockDrawInterface> mock_draw_interface_ =
      std::make_shared<NiceMock<MockDrawInterface>>();
  MockDrawInterface* mock_draw_interface_ptr_ = mock_draw_interface_.get();
  StrictMock<MockScreenControllerInterface> mock_screen_controller_;

  ScreenError screen_error_{ScreenType::kGeneralError, mock_draw_interface_,
                            &mock_screen_controller_};
};

TEST_F(ScreenErrorTest, GetState) {
  EXPECT_CALL(mock_screen_controller_, OnStateChanged);
  screen_error_.Show();
  EXPECT_EQ(State::ERROR, screen_error_.GetState().state());
}

TEST_F(ScreenErrorTest, MoveForward) {
  EXPECT_CALL(mock_screen_controller_, OnForward(&screen_error_));
  EXPECT_TRUE(screen_error_.MoveForward(nullptr));
}

TEST_F(ScreenErrorTest, MoveBackward) {
  EXPECT_CALL(mock_screen_controller_, OnBackward(&screen_error_));
  EXPECT_TRUE(screen_error_.MoveBackward(nullptr));
}

}  // namespace minios
