// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/ec_keyboard_backlight.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libec/ec_usb_endpoint.h>
#include <libec/pwm_command.h>
#include <memory>
#include <utility>
#include "power_manager/powerd/testing/test_environment.h"

using ::testing::Ref;
using ::testing::Return;

namespace power_manager::system {

class MockGetKeyboardBacklightCommand : public ec::GetKeyboardBacklightCommand {
 public:
  MOCK_METHOD(bool, Run, (int ec_fd), (override));
  MOCK_METHOD(bool, Run, (ec::EcUsbEndpointInterface & uep), (override));
  MOCK_METHOD(uint8_t, Brightness, (), (const, override));
};

class EcKeyboardBacklightTest : public TestEnvironment {
 protected:
  ec::EcUsbEndpointStub endpoint_;
  std::unique_ptr<MockGetKeyboardBacklightCommand> mock =
      std::make_unique<MockGetKeyboardBacklightCommand>();
};

TEST_F(EcKeyboardBacklightTest, Init) {
  EXPECT_CALL(*mock, Run(Ref(endpoint_))).WillOnce(Return(true));
  EXPECT_CALL(*mock, Brightness).WillOnce(Return(99));

  EcKeyboardBacklight backlight_(std::move(mock));
  ASSERT_TRUE(backlight_.Init(&endpoint_));
  ASSERT_EQ(backlight_.GetCurrentBrightnessLevel(), 99);
}

TEST_F(EcKeyboardBacklightTest, InitFail) {
  EXPECT_CALL(*mock, Run(Ref(endpoint_))).WillOnce(Return(false));

  EcKeyboardBacklight backlight_(std::move(mock));
  ASSERT_FALSE(backlight_.Init(&endpoint_));
}

/* TODO: Add unit test for SetBrightnessLevel (b:234926943). */

}  // namespace power_manager::system
