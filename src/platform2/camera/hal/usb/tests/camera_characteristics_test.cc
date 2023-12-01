/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <brillo/flag_helper.h>
#include <gtest/gtest.h>

#include "cros-camera/common.h"
#include "hal/usb/camera_characteristics.h"

namespace cros {
namespace {

bool g_skip_if_no_config = false;

TEST(CameraCharacteristicsTest, ConfigFileFormat) {
  if (!CameraCharacteristics::ConfigFileExists()) {
    if (g_skip_if_no_config) {
      GTEST_SKIP();
    }
    FAIL() << "Camera characteristics file does not exist";
  }
  // This triggers crash when the characteristics file content doesn't follow
  // the format.
  CameraCharacteristics characteristics;
}

}  // namespace
}  // namespace cros

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);

  DEFINE_bool(skip_if_no_config, false, "Skip test if there's no config file");
  brillo::FlagHelper::Init(argc, argv, argv[0]);

  cros::g_skip_if_no_config = FLAGS_skip_if_no_config;
  return RUN_ALL_TESTS();
}
