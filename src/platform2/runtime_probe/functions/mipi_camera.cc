// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>
#include <utility>
#include <vector>

#include <base/containers/span.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/values.h>

#include "cros-camera/device_config.h"
#include "runtime_probe/functions/mipi_camera.h"

namespace runtime_probe {

std::optional<std::vector<cros::PlatformCameraInfo>>
MipiCameraFunction::GetPlatformCameraInfo() const {
  auto device_config = cros::DeviceConfig::Create();
  if (!device_config.has_value()) {
    LOG(ERROR) << "Failed to get camera device config.";
    return std::nullopt;
  }

  auto camera_info = device_config->GetPlatformCameraInfo();
  return std::vector<cros::PlatformCameraInfo>(camera_info.begin(),
                                               camera_info.end());
}

MipiCameraFunction::DataType MipiCameraFunction::EvalImpl() const {
  MipiCameraFunction::DataType results;

  auto cameras = GetPlatformCameraInfo();
  if (!cameras) {
    LOG(ERROR) << "Failed to get MIPI camera list.";
    return results;
  }

  for (const auto& camera : *cameras) {
    base::Value::Dict node;
    if (camera.eeprom) {
      node.Set("mipi_sysfs_name", camera.sysfs_name);
      node.Set("mipi_module_id", camera.module_id());
      node.Set("mipi_sensor_id", camera.sensor_id());
      node.Set("path", camera.eeprom->nvmem_path.value());
    } else if (camera.v4l2_sensor) {
      node.Set("mipi_name", camera.v4l2_sensor->name);
      node.Set("mipi_vendor", camera.v4l2_sensor->vendor_id);
      node.Set("path", camera.v4l2_sensor->subdev_path.value());
    } else {
      NOTREACHED() << "Unknown source of camera info.";
    }
    node.Set("bus_type", "mipi");
    results.Append(std::move(node));
  }

  return results;
}

}  // namespace runtime_probe
