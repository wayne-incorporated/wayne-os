// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include <gtest/gtest.h>

#include "rgbkbd/internal_rgb_keyboard.h"

namespace rgbkbd {

class InternalRgbKeyboardTest : public testing::Test {
 public:
  InternalRgbKeyboardTest() {
    keyboard_ = std::make_unique<InternalRgbKeyboard>();
  }

  InternalRgbKeyboardTest(const InternalRgbKeyboardTest&) = delete;
  InternalRgbKeyboardTest& operator=(const InternalRgbKeyboardTest&) = delete;
  ~InternalRgbKeyboardTest() override = default;

 protected:
  std::unique_ptr<InternalRgbKeyboard> keyboard_;
};

TEST_F(InternalRgbKeyboardTest, InitializeInternalRgbKeyboard) {
  EXPECT_TRUE(keyboard_);
}

}  // namespace rgbkbd
