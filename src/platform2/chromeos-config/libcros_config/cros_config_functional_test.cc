// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Functional tests for the CrosConfig library. These tests are not unit tests,
// and are intended to be executed on the target hardware.
//
// Testcase(s):
//     CrosConfigTest.CheckName -
//               Verifies cros_config initializes and can read 'Name' property

#include <string>

#include <gtest/gtest.h>
#include "chromeos-config/libcros_config/cros_config.h"

class CrosConfigTest : public testing::Test {};

TEST_F(CrosConfigTest, CheckName) {
  brillo::CrosConfig cros_config;
  std::string name;
  EXPECT_TRUE(cros_config.GetString("/", "name", &name));
  EXPECT_NE(name, "");
}

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);

  return RUN_ALL_TESTS();
}
