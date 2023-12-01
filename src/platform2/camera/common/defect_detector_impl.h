/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_DEFECT_DETECTOR_IMPL_H_
#define CAMERA_COMMON_DEFECT_DETECTOR_IMPL_H_

#include "cros-camera/camera_buffer_manager.h"
#include "cros-camera/defect_detector.h"

namespace cros {

// Implementation of DefectDetector. This class is not thread-safe.
class DefectDetectorImpl : public DefectDetector {
 public:
  DefectDetectorImpl();
  ~DefectDetectorImpl() override;

  bool DetectDefectiveLineFromHandle(buffer_handle_t input,
                                     bool* isLineFound) override;

 private:
  bool DetectDefectiveLineFromHandleInternal(const ScopedMapping& mapping);
};

}  // namespace cros

#endif  // CAMERA_COMMON_DEFECT_DETECTOR_IMPL_H_
