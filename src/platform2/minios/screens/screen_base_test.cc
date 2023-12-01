// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include "minios/key_reader.h"
#include "minios/screens/screen_welcome.h"

namespace minios {

class ScreenBaseTest : public ::testing::Test {
 protected:
  // Use ScreenWelcome as an example to test out screen base functions.
  ScreenWelcome screen_welcome_ = ScreenWelcome(nullptr, nullptr);
};

TEST_F(ScreenBaseTest, UpdateButtons) {
  screen_welcome_.SetIndexForTest(1);
  int menu_items = 4;
  screen_welcome_.SetButtonCountForTest(menu_items);

  bool enter = false;
  screen_welcome_.UpdateButtonsIndex(KEY_UP, &enter);
  EXPECT_EQ(0, screen_welcome_.GetIndexForTest());

  // Test range.
  screen_welcome_.UpdateButtonsIndex(KEY_UP, &enter);
  EXPECT_EQ(0, screen_welcome_.GetIndexForTest());
  // Move to last item.
  screen_welcome_.SetIndexForTest(menu_items - 1);
  screen_welcome_.UpdateButtonsIndex(KEY_DOWN, &enter);
  EXPECT_EQ(menu_items - 1, screen_welcome_.GetIndexForTest());
  EXPECT_FALSE(enter);
  // Enter key pressed.
  screen_welcome_.SetIndexForTest(1);
  screen_welcome_.UpdateButtonsIndex(KEY_ENTER, &enter);
  EXPECT_EQ(1, screen_welcome_.GetIndexForTest());
  EXPECT_TRUE(enter);

  // Unknown key, no action taken.
  screen_welcome_.SetIndexForTest(2);
  enter = false;
  screen_welcome_.UpdateButtonsIndex(89, &enter);
  EXPECT_EQ(2, screen_welcome_.GetIndexForTest());
  EXPECT_FALSE(enter);

  // If index somehow goes out of range, reset to 0.
  screen_welcome_.SetIndexForTest(menu_items + 5);
  enter = false;
  screen_welcome_.UpdateButtonsIndex(KEY_ENTER, &enter);
  EXPECT_EQ(0, screen_welcome_.GetIndexForTest());
}

TEST_F(ScreenBaseTest, UpdateButtonsIsDetachable) {
  screen_welcome_.SetIndexForTest(1);
  bool enter = false;
  int menu_items = 4;
  screen_welcome_.SetButtonCountForTest(menu_items);

  screen_welcome_.UpdateButtonsIndex(KEY_VOLUMEUP, &enter);
  EXPECT_EQ(0, screen_welcome_.GetIndexForTest());

  // Test range.
  screen_welcome_.UpdateButtonsIndex(KEY_VOLUMEUP, &enter);
  EXPECT_EQ(0, screen_welcome_.GetIndexForTest());
  // Move to last item.
  screen_welcome_.SetIndexForTest(menu_items - 1);
  screen_welcome_.UpdateButtonsIndex(KEY_VOLUMEDOWN, &enter);
  EXPECT_EQ(3, screen_welcome_.GetIndexForTest());
  EXPECT_FALSE(enter);
  // Enter key pressed.
  screen_welcome_.SetIndexForTest(1);
  screen_welcome_.UpdateButtonsIndex(KEY_POWER, &enter);
  EXPECT_EQ(1, screen_welcome_.GetIndexForTest());
  EXPECT_TRUE(enter);
}

}  // namespace minios
