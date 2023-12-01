/*
 * Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_USB_COMMON_TYPES_H_
#define CAMERA_HAL_USB_COMMON_TYPES_H_

#include <string>
#include <vector>

#include "cros-camera/common_types.h"
#include "cros-camera/device_config.h"
#include "cros-camera/timezone.h"

// TODO(crbug.com/661877): Wrap this with kernel version check once the
// format is introduced to kernel.
#ifndef V4L2_PIX_FMT_INVZ
// 16 bit depth, Realsense SR300.
#define V4L2_PIX_FMT_INVZ v4l2_fourcc('I', 'N', 'V', 'Z')
#endif

namespace cros {

struct DeviceInfo {
  int camera_id = -1;

  // TODO(shik): Change this to base::FilePath.
  // ex: /dev/video0
  std::string device_path;

  // Whether the device is an emulated vivid camera.
  bool is_vivid = false;

  // USB vendor id, the emulated vivid devices do not have this field.
  std::string usb_vid;

  // USB product id, the emulated vivid devices do not have this field.
  std::string usb_pid;

  // Some cameras need to wait several frames to output correct images.
  uint32_t frames_to_skip_after_streamon = 0;

  // The camera doesn't support constant frame rate. That means HAL cannot set
  // V4L2_CID_EXPOSURE_AUTO_PRIORITY to 0 to have constant frame rate in low
  // light environment.
  bool constant_framerate_unsupported = false;

  // Region of interest is used for 3A. If this is true, it will enable
  // face detection and report ROI information to camera.
  bool region_of_interest_supported = false;

  // Enable face detection and ROI control by camera module from
  // camera_characteristics.conf.
  // TODO(henryhsu): Remove it when we enable the feature for all modules which
  // support ROI.
  bool enable_face_detection = false;

  // Member definitions can be found in https://developer.android.com/
  // reference/android/hardware/camera2/CameraCharacteristics.html
  LensFacing lens_facing = LensFacing::kFront;
  int32_t sensor_orientation = 0;

  // Special settings for device specific quirks.
  uint32_t quirks = 0;

  // These fields are not available for external cameras.
  std::vector<float> lens_info_available_apertures;
  std::vector<float> lens_info_available_focal_lengths;
  float lens_info_minimum_focus_distance = 0;
  float lens_info_optimal_focus_distance = 0;
  float sensor_info_physical_size_width = 0;
  float sensor_info_physical_size_height = 0;
  int32_t sensor_info_pixel_array_size_width = 0;
  int32_t sensor_info_pixel_array_size_height = 0;
  Rect<int32_t> sensor_info_active_array_size;

  // These values are only used for legacy devices (v1 devices).
  float horizontal_view_angle_16_9 = 0;
  float horizontal_view_angle_4_3 = 0;
  float vertical_view_angle_16_9 = 0;
  float vertical_view_angle_4_3 = 0;

  // Whether the device is detachable.
  bool is_detachable = false;

  // Whether the device has privacy switch.
  bool has_privacy_switch = false;
};

typedef std::vector<DeviceInfo> DeviceInfos;

struct SupportedFormat {
  uint32_t width = 0;
  uint32_t height = 0;
  uint32_t fourcc = 0;
  // All the supported frame rates in fps with given width, height, and
  // pixelformat. This is not sorted. For example, suppose width, height, and
  // fourcc are 640x480 YUYV. If frame rates are 15.0 and 30.0, the camera
  // supports outputting 640x480 YUYV in 15fps or 30fps.
  std::vector<float> frame_rates;

  uint32_t area() const { return width * height; }
  bool operator<(const SupportedFormat& rhs) const {
    if (area() == rhs.area()) {
      return width < rhs.width;
    }
    return area() < rhs.area();
  }
  bool operator==(const SupportedFormat& rhs) const {
    return width == rhs.width && height == rhs.height;
  }
};

typedef std::vector<SupportedFormat> SupportedFormats;

}  // namespace cros

#endif  // CAMERA_HAL_USB_COMMON_TYPES_H_
