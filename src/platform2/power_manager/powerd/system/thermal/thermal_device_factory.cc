// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/thermal/thermal_device_factory.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/stl_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>

#include "power_manager/powerd/system/thermal/cooling_device.h"

namespace power_manager::system {

namespace {

// Default path for thermal device.
const char kDefaultDeviceListPath[] = "/sys/class/thermal";

// Name prefix for cooling device.
const char kCoolingDevicePrefix[] = "cooling_device";

}  // namespace

std::vector<std::unique_ptr<ThermalDeviceInterface>>
ThermalDeviceFactory::CreateThermalDevices(
    const char device_list_path_for_testing[]) {
  std::vector<std::unique_ptr<ThermalDeviceInterface>> ret;
  base::FilePath dir;
  if (device_list_path_for_testing) {
    dir = base::FilePath(device_list_path_for_testing);
  } else {
    dir = base::FilePath(kDefaultDeviceListPath);
  }

  if (!base::PathExists(dir)) {
    LOG(ERROR) << "Nonexistent path: " << dir;
    return ret;
  }

  base::FileEnumerator dir_enum(dir, false, base::FileEnumerator::DIRECTORIES);

  for (base::FilePath path = dir_enum.Next(); !path.empty();
       path = dir_enum.Next()) {
    std::string dir_name = path.BaseName().value();

    if (dir_name.rfind(kCoolingDevicePrefix) != 0)
      continue;

    auto device = std::make_unique<CoolingDevice>(path);
    device->Init(true);

    ret.push_back(std::move(device));
  }

  return ret;
}

}  // namespace power_manager::system
