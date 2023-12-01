/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_FRAME_ANNOTATOR_FRAME_ANNOTATOR_LOADER_STREAM_MANIPULATOR_H_
#define CAMERA_FEATURES_FRAME_ANNOTATOR_FRAME_ANNOTATOR_LOADER_STREAM_MANIPULATOR_H_

#include "common/stream_manipulator.h"

#include <memory>

#include <base/scoped_native_library.h>

namespace cros {

class FrameAnnotatorLoaderStreamManipulator : public StreamManipulator {
 public:
  FrameAnnotatorLoaderStreamManipulator();
  ~FrameAnnotatorLoaderStreamManipulator() override;

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
  base::ScopedNativeLibrary frame_annotator_lib_;
  StreamManipulator::Callbacks callbacks_;

  std::unique_ptr<StreamManipulator> stream_manipulator_;
};

}  // namespace cros

#endif  // CAMERA_FEATURES_FRAME_ANNOTATOR_FRAME_ANNOTATOR_LOADER_STREAM_MANIPULATOR_H_
