/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_FRAME_ANNOTATOR_LIBS_METADATA_PREVIEWER_FRAME_ANNOTATOR_H_
#define CAMERA_FEATURES_FRAME_ANNOTATOR_LIBS_METADATA_PREVIEWER_FRAME_ANNOTATOR_H_

#include "features/frame_annotator/libs/frame_annotator.h"

#include <base/containers/queue.h>
#include <base/time/time.h>

namespace cros {

class MetadataPreviewerFrameAnnotator : public FrameAnnotator {
 public:
  bool Initialize(const camera_metadata_t* static_info) override;
  bool ProcessCaptureResult(const Camera3CaptureDescriptor* result) override;
  bool IsPlotNeeded() const override;
  bool Plot(SkCanvas* canvas) override;
  void UpdateOptions(const FrameAnnotator::Options& options) override;

 private:
  FrameAnnotator::Options options_;

  camera_metadata_enum_android_lens_facing_t facing_;

  static constexpr size_t kFpsMeasureFrames = 100;
  base::queue<base::TimeTicks> timestamps_;
  std::optional<camera_metadata_enum_android_statistics_face_detect_mode_t>
      face_detect_mode_;
  size_t num_faces_;

  bool af_enabled_;
  std::optional<float> focus_distance_;
  std::optional<camera_metadata_enum_android_control_af_state_t> af_state_;

  bool ae_enabled_;
  std::optional<int32_t> sensor_sensitivity_;
  std::optional<int32_t> sensor_sensitivity_boost_;
  std::optional<int64_t> exposure_time_;
  std::optional<int64_t> frame_duration_;
  std::optional<camera_metadata_enum_android_control_ae_antibanding_mode_t>
      ae_antibanding_mode_;
  std::optional<camera_metadata_enum_android_control_ae_state_t> ae_state_;

  bool awb_enabled_;
  std::optional<float> wb_gain_red_;
  std::optional<float> wb_gain_blue_;
  std::optional<camera_metadata_enum_android_control_awb_state_t> awb_state_;

  std::optional<float> hdr_ratio_;
};

}  // namespace cros

#endif  // CAMERA_FEATURES_FRAME_ANNOTATOR_LIBS_METADATA_PREVIEWER_FRAME_ANNOTATOR_H_
