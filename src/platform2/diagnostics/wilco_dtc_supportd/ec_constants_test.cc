// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/files/file_path.h>

#include <gtest/gtest.h>

#include "diagnostics/wilco_dtc_supportd/ec_constants.h"

namespace diagnostics {
namespace wilco {
namespace {

TEST(EcConstantsTest, PropertiesPath) {
  EXPECT_EQ(
      base::FilePath(kEcDriverSysfsPath).Append(kEcDriverSysfsPropertiesPath),
      base::FilePath("sys/bus/platform/devices/GOOG000C:00/properties/"));
}

}  // namespace
}  // namespace wilco
}  // namespace diagnostics
