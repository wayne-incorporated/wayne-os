/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_SW_PRIVACY_SWITCH_STREAM_MANIPULATOR_H_
#define CAMERA_COMMON_SW_PRIVACY_SWITCH_STREAM_MANIPULATOR_H_

#include "common/stream_manipulator.h"

#include <memory>

#include <hardware/camera3.h>

#include "cros-camera/camera_buffer_manager.h"
#include "cros-camera/camera_mojo_channel_manager_token.h"
#include "cros-camera/jpeg_compressor.h"
#include "gpu/shared_image.h"

namespace cros {

class SWPrivacySwitchStreamManipulator : public StreamManipulator {
 public:
  SWPrivacySwitchStreamManipulator(
      RuntimeOptions* runtime_options,
      CameraMojoChannelManagerToken* mojo_manager_token,
      GpuResources* gpu_resources);

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
  // Allocates |black_frame_|, fills it with black, and creates SharedImage for
  // it. Must be called on the GPU thread.
  bool InitializeBlackFrameOnGpuThread();

  // Used to fill in NV12 buffer with black pixels on GPU. Must be called on
  // the GPU thread.
  std::optional<base::ScopedFD> RedactNV12FrameOnGpu(buffer_handle_t handle);

  // Used to fill in JPEG buffer with a black JPEG image. Returns true if
  // successful. Returns false otherwise.
  bool RedactJpegFrame(buffer_handle_t handle,
                       ScopedMapping& mapping,
                       int width,
                       int height);

  // Used to notify an error to the framework when failing to fill the frame
  // with black.
  void NotifyBufferError(uint32_t frame_number, camera3_stream_t* stream);

  // Contains the current software privacy switch state.
  RuntimeOptions* runtime_options_;

  // CameraBufferManager instance.
  CameraBufferManager* camera_buffer_manager_;

  // JPEG compressor instance.
  std::unique_ptr<JpegCompressor> jpeg_compressor_;

  // A black NV12 frame that is used to paint frames with black.
  ScopedBufferHandle black_frame_ = nullptr;

  // SharedImage created from |black_frame_|.
  SharedImage black_frame_image_;

  GpuResources* gpu_resources_;
  StreamManipulator::Callbacks callbacks_;
};

}  // namespace cros

#endif  // CAMERA_COMMON_SW_PRIVACY_SWITCH_STREAM_MANIPULATOR_H_
