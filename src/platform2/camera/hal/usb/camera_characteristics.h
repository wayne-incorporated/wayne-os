/*
 * Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_USB_CAMERA_CHARACTERISTICS_H_
#define CAMERA_HAL_USB_CAMERA_CHARACTERISTICS_H_

#include <map>
#include <string>
#include <utility>

#include <base/files/file.h>

#include "hal/usb/common_types.h"

namespace cros {

// /etc/camera/camera_characteristics.conf contains camera information which
// driver cannot provide.
static const base::FilePath kCameraCharacteristicsConfigFile(
    "/etc/camera/camera_characteristics.conf");

// CameraCharacteristics reads the file /etc/camera/camera_characteristics.conf.
// There are several assumptions of the config file:
//  1. camera/module id should be in ascending order (i.e., 0, 1, 2, ...).
//  2. All configs of a camera/module should be put together.
//  3. Module specific characteristics should come after camera specific ones.
//  4. All usb_vid_pid shuold be distinct.
//
// Example of the config file:
//  camera0.lens_facing=0
//  camera0.module0.usb_vid_pid=0123:4567
//  camera0.module0.horizontal_view_angle=68.4
//  camera0.module0.lens_info_available_focal_lengths=1.64
//  camera0.module0.lens_info_minimum_focus_distance=0.22
//  camera0.module0.lens_info_optimal_focus_distance=0.5
//  camera0.module0.vertical_view_angle=41.6
//  camera0.module1.usb_vid_pid=89ab:cdef
//  camera0.module1.lens_info_available_focal_lengths=1.69,2
//  camera1.lens_facing=1
//  ...
class CameraCharacteristics {
 public:
  static bool ConfigFileExists();

  // Initialize camera characteristics from |kCameraCharacteristicsConfigFile|.
  // If the file does not exist, |camera_module_infos_| would be empty.
  CameraCharacteristics();

  // Initialize camera characteristics from |config_file|.
  explicit CameraCharacteristics(const base::FilePath& config_file);
  CameraCharacteristics(const CameraCharacteristics&) = delete;
  CameraCharacteristics& operator=(const CameraCharacteristics&) = delete;

  // Get the device information by vid and pid. Returns |nullptr| if not found.
  const DeviceInfo* Find(const std::string& vid, const std::string& pid) const;

 private:
  void InitFrom(const base::FilePath& config_file);

  // The key is a pair of usb (vid, pid).
  std::map<std::pair<std::string, std::string>, DeviceInfo>
      camera_module_infos_;
};

}  // namespace cros

#endif  // CAMERA_HAL_USB_CAMERA_CHARACTERISTICS_H_
