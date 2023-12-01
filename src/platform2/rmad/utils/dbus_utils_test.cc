// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/utils/dbus_utils.h"

#include <base/test/task_environment.h>
#include <gtest/gtest.h>

namespace rmad {

class DBusUtilsImplTest : public testing::Test {
 public:
  DBusUtilsImplTest() = default;
  ~DBusUtilsImplTest() override = default;
};

TEST_F(DBusUtilsImplTest, GetSystemBus_Success) {
  base::test::SingleThreadTaskEnvironment task_environment;
  EXPECT_TRUE(GetSystemBus());
}

TEST_F(DBusUtilsImplTest, GetSystemBus_Fail) {
  EXPECT_DEATH(GetSystemBus(), "");
}

}  // namespace rmad
