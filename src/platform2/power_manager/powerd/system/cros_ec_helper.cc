// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/cros_ec_helper.h"

#include <string>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>

namespace power_manager::system {

namespace {

constexpr char k318WakeAngleSysPath[] =
    "/sys/class/chromeos/cros_ec/kb_wake_angle";
constexpr char k314IioLinkPath[] = "/dev/cros-ec-accel/0";
constexpr char k314IioSysfsPath[] = "/sys/bus/iio/devices";
constexpr char k314AccelNodeName[] = "in_angl_offset";

}  // namespace

CrosEcHelper::CrosEcHelper() {
  if (base::PathExists(
          base::FilePath(k318WakeAngleSysPath))) {  // Kernel 3.18 and later
    wake_angle_sysfs_node_ = base::FilePath(k318WakeAngleSysPath);
    wake_angle_supported_ = true;
    VLOG(1) << "Accessing EC wake angle through 3.18+ sysfs node: "
            << wake_angle_sysfs_node_.value();
    return;
  }

  const base::FilePath iio_link_path_314 = base::FilePath(k314IioLinkPath);
  if (base::IsLink(iio_link_path_314)) {  // Kernel 3.14
    base::FilePath iio_dev_path;
    if (!base::ReadSymbolicLink(iio_link_path_314, &iio_dev_path)) {
      LOG(ERROR) << "Cannot read link target of " << k314IioLinkPath;
      return;
    }
    iio_dev_path = iio_dev_path.BaseName();
    wake_angle_sysfs_node_ = base::FilePath(k314IioSysfsPath)
                                 .Append(iio_dev_path)
                                 .Append(k314AccelNodeName);
    if (base::PathExists(wake_angle_sysfs_node_)) {
      wake_angle_supported_ = true;
      VLOG(1) << "Accessing EC wake angle through 3.14 sysfs node: "
              << wake_angle_sysfs_node_.value();
      return;
    }
    // fallthrough.
  }

  LOG(INFO) << "This device does not support EC wake angle control";
}

bool CrosEcHelper::IsWakeAngleSupported() {
  return wake_angle_supported_;
}

bool CrosEcHelper::AllowWakeupAsTablet(bool enabled) {
  int new_wake_angle = enabled ? 360 : 180;
  std::string str = base::NumberToString(new_wake_angle);
  if (new_wake_angle == cached_wake_angle_) {
    VLOG(1) << "EC wake angle is already set to " << str;
    return true;
  }
  if (base::WriteFile(wake_angle_sysfs_node_, str.c_str(), str.size()) < 0) {
    PLOG(ERROR) << "Failed to set EC wake angle to " << str;
    return false;
  }
  LOG(INFO) << "EC wake angle set to " << str;
  cached_wake_angle_ = new_wake_angle;
  return true;
}

}  // namespace power_manager::system
