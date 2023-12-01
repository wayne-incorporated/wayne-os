/*
 * Copyright 2023 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_PORTRAIT_MODE_PORTRAIT_MODE_STREAM_MANIPULATOR_H_
#define CAMERA_FEATURES_PORTRAIT_MODE_PORTRAIT_MODE_STREAM_MANIPULATOR_H_

#include "common/stream_manipulator.h"

#include <deque>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include "common/camera_hal3_helpers.h"
#include "cros-camera/camera_mojo_channel_manager_token.h"
#include "features/portrait_mode/portrait_mode_effect.h"

namespace cros {

class PortraitModeStreamManipulator : public StreamManipulator {
 public:
  PortraitModeStreamManipulator(
      CameraMojoChannelManagerToken* mojo_manager_token);
  ~PortraitModeStreamManipulator() override;

  static bool UpdateVendorTags(VendorTagManager& vendor_tag_manager);
  static bool UpdateStaticMetadata(android::CameraMetadata* static_info);

  // Implementations of StreamManipulator.
  bool Initialize(const camera_metadata_t* static_info,
                  StreamManipulator::Callbacks callbacks) override;
  bool ConfigureStreams(Camera3StreamConfiguration* stream_config,
                        const StreamEffectMap* stream_effects_map) override;
  bool OnConfiguredStreams(Camera3StreamConfiguration* stream_config) override;
  bool ConstructDefaultRequestSettings(
      android::CameraMetadata* default_request_settings, int type) override;
  bool ProcessCaptureRequest(Camera3CaptureDescriptor* request) override;
  bool ProcessCaptureResult(Camera3CaptureDescriptor result) override;
  void Notify(camera3_notify_msg_t msg) override;
  bool Flush() override;

 private:
  // A collection of all the info needed for Portrait Mode reprocessing.
  struct ReprocessContext {
    // The frame number associated with Portrait Mode reprocessing.
    uint32_t frame_number = -1;

    // The original input buffer handle replaced by reprocessing ones.
    buffer_handle_t original_input_buffer = nullptr;

    // The reprocessing buffer handle.
    ScopedBufferHandle replaced_input_buffer;

    // The Portrait Mode segmentation result.
    std::optional<SegmentationResult> segmentation_result;
  };

  StreamManipulator::Callbacks callbacks_;

  CameraMojoChannelManagerToken* mojo_manager_token_;

  // PortraitModeEffect instance.
  std::unique_ptr<PortraitModeEffect> portrait_mode_;

  std::optional<ReprocessContext> reprocess_context_
      GUARDED_BY(reprocess_context_lock_);
  base::Lock reprocess_context_lock_;
};

}  // namespace cros

#endif  // CAMERA_FEATURES_PORTRAIT_MODE_PORTRAIT_MODE_STREAM_MANIPULATOR_H_
