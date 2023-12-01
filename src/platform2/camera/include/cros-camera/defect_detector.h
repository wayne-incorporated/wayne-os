/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_INCLUDE_CROS_CAMERA_DEFECT_DETECTOR_H_
#define CAMERA_INCLUDE_CROS_CAMERA_DEFECT_DETECTOR_H_

#include <cutils/native_handle.h>

#include <memory>

#include "cros-camera/export.h"

namespace cros {

// Interface for NV12 to Defect detector.
class CROS_CAMERA_EXPORT DefectDetector {
 public:
  static std::unique_ptr<DefectDetector> New();

  virtual ~DefectDetector() = default;

  // Detect Defective Line from YUV image via buffer handles.
  virtual bool DetectDefectiveLineFromHandle(buffer_handle_t input,
                                             bool* isLineFound) = 0;
};

}  // namespace cros

#endif  // CAMERA_INCLUDE_CROS_CAMERA_DEFECT_DETECTOR_H_
