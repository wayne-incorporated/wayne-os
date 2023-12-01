/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_FRAME_ANNOTATOR_LIBS_FACE_RECTANGLES_FRAME_ANNOTATOR_H_
#define CAMERA_FEATURES_FRAME_ANNOTATOR_LIBS_FACE_RECTANGLES_FRAME_ANNOTATOR_H_

#include "features/frame_annotator/libs/frame_annotator.h"

#include <vector>

#include "cros-camera/common_types.h"
#include "cros-camera/face_detector_client_cros_wrapper.h"

namespace cros {

class FaceRectanglesFrameAnnotator : public FrameAnnotator {
 public:
  // Implementations of FrameAnnotator.
  bool Initialize(const camera_metadata_t* static_info) override;
  bool ProcessCaptureResult(const Camera3CaptureDescriptor* result) override;
  bool IsPlotNeeded() const override;
  bool Plot(SkCanvas* canvas) override;
  void UpdateOptions(const FrameAnnotator::Options& options) override;

 private:
  FrameAnnotator::Options options_;

  Size active_array_dimension_;
  camera_metadata_enum_android_lens_facing_t facing_;

  std::vector<human_sensing::CrosFace> cached_faces_;
};

}  // namespace cros

#endif  // CAMERA_FEATURES_FRAME_ANNOTATOR_LIBS_FACE_RECTANGLES_FRAME_ANNOTATOR_H_
