/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_FRAME_ANNOTATOR_LIBS_FRAME_ANNOTATOR_STREAM_MANIPULATOR_H_
#define CAMERA_FEATURES_FRAME_ANNOTATOR_LIBS_FRAME_ANNOTATOR_STREAM_MANIPULATOR_H_

#include "common/stream_manipulator.h"

#include <memory>
#include <vector>

#include <base/functional/callback_forward.h>
#include <skia/gpu/GrDirectContext.h>
#include <skia/core/SkCanvas.h>

#include "common/reloadable_config_file.h"
#include "cros-camera/camera_thread.h"
#include "features/frame_annotator/libs/frame_annotator.h"
#include "gpu/egl/egl_context.h"

namespace cros {

class FrameAnnotatorStreamManipulator : public StreamManipulator {
 public:
  FrameAnnotatorStreamManipulator();
  ~FrameAnnotatorStreamManipulator() override;

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
  bool SetUpContextsOnGpuThread();
  bool ProcessCaptureResultOnGpuThread(Camera3CaptureDescriptor* result);
  bool PlotOnGpuThread(Camera3StreamBuffer& buffer);
  void FlushSkSurfaceToBuffer(SkSurface* surface, buffer_handle_t yuv_buf);

  void OnOptionsUpdated(const base::Value::Dict& json_values);

  ReloadableConfigFile config_;
  FrameAnnotator::Options options_;
  StreamManipulator::Callbacks callbacks_;

  Size active_array_dimension_;
  const camera3_stream_t* yuv_stream_ = nullptr;
  std::unique_ptr<EglContext> egl_context_;
  sk_sp<GrDirectContext> gr_context_;
  CameraThread gpu_thread_;

  std::vector<std::unique_ptr<FrameAnnotator>> frame_annotators_;
};

}  // namespace cros

#endif  // CAMERA_FEATURES_FRAME_ANNOTATOR_LIBS_FRAME_ANNOTATOR_STREAM_MANIPULATOR_H_
