// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/thermal/thermal_device_factory.h"

#include <set>
#include <string>
#include <vector>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>
#include "power_manager/powerd/testing/test_environment.h"

namespace power_manager::system {

class ThermalDeviceFactoryTest : public TestEnvironment {};

TEST_F(ThermalDeviceFactoryTest, CreateThermalDevices) {
  base::ScopedTempDir scoped_temp_dir;

  CHECK(scoped_temp_dir.CreateUniqueTempDir());
  base::FilePath temp_dir = scoped_temp_dir.GetPath();

  std::string dirs[] = {"cooling_device1", "cooling_device2", "thermal_zone1",
                        "thermal_zone2"};
  for (const auto& dir : dirs) {
    base::FilePath device_dir = temp_dir.Append(dir);
    CHECK(base::CreateDirectory(device_dir));
  }

  std::vector<std::unique_ptr<ThermalDeviceInterface>> res =
      ThermalDeviceFactory::CreateThermalDevices(temp_dir.value().c_str());
  EXPECT_EQ(2, res.size());
  std::set<base::FilePath> expected_paths = {
      temp_dir.Append("cooling_device1"), temp_dir.Append("cooling_device2")};
  std::set<base::FilePath> actual_paths = {
      static_cast<ThermalDevice*>(res[0].get())->get_device_path_for_testing(),
      static_cast<ThermalDevice*>(res[1].get())->get_device_path_for_testing()};
  EXPECT_EQ(expected_paths, actual_paths);
}

}  // namespace power_manager::system
