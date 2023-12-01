// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "screen-capture-utils/uinput.h"

#include <gtest/gtest.h>
#include <linux/uinput.h>

namespace screenshot {
TEST(UinputTest, MapsCtrl) {
  ASSERT_EQ(KeySymToScancode(0xffe3), KEY_LEFTCTRL);
}

}  // namespace screenshot
