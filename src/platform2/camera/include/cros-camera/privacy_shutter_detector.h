/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_INCLUDE_CROS_CAMERA_PRIVACY_SHUTTER_DETECTOR_H_
#define CAMERA_INCLUDE_CROS_CAMERA_PRIVACY_SHUTTER_DETECTOR_H_

#include <cutils/native_handle.h>

#include <memory>

#include "cros-camera/export.h"

namespace cros {

// Interface for YU12 to Privacy shutter detector.
class CROS_CAMERA_EXPORT PrivacyShutterDetector {
 public:
  static std::unique_ptr<PrivacyShutterDetector> New();

  virtual ~PrivacyShutterDetector() = default;

  // Detect Privacy Shutter from YUV image via buffer handles.
  virtual bool DetectPrivacyShutterFromHandle(buffer_handle_t input,
                                              bool* isShutterClosed) = 0;
};

}  // namespace cros

#endif  // CAMERA_INCLUDE_CROS_CAMERA_PRIVACY_SHUTTER_DETECTOR_H_
