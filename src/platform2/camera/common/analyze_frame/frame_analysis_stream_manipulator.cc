// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "common/analyze_frame/frame_analysis_stream_manipulator.h"

#include <cstdint>
#include <memory>
#include <utility>

#include <drm_fourcc.h>
#include <libyuv/scale.h>

#include "camera/mojo/camera_diagnostics.mojom.h"
#include "common/analyze_frame/camera_diagnostics_client.h"
#include "cros-camera/camera_buffer_manager.h"
#include "cros-camera/camera_mojo_channel_manager.h"
#include "mojo/public/c/system/types.h"

namespace cros {

constexpr uint32_t kFrameCopyInterval = 27;

FrameAnalysisStreamManipulator::FrameAnalysisStreamManipulator(
    CameraMojoChannelManagerToken* mojo_manager_token)
    : mojo_manager_token_(mojo_manager_token),
      camera_buffer_manager_(cros::CameraBufferManager::GetInstance()) {}

bool FrameAnalysisStreamManipulator::Initialize(
    const camera_metadata_t* static_info,
    StreamManipulator::Callbacks callbacks) {
  callbacks_ = std::move(callbacks);
  return true;
}

bool FrameAnalysisStreamManipulator::ConfigureStreams(
    Camera3StreamConfiguration* stream_config,
    const StreamEffectMap* stream_effects_map) {
  return true;
}

bool FrameAnalysisStreamManipulator::OnConfiguredStreams(
    Camera3StreamConfiguration* stream_config) {
  return true;
}

bool FrameAnalysisStreamManipulator::ConstructDefaultRequestSettings(
    android::CameraMetadata* default_request_settings, int type) {
  return true;
}

bool FrameAnalysisStreamManipulator::ProcessCaptureRequest(
    Camera3CaptureDescriptor* request) {
  return true;
}

bool FrameAnalysisStreamManipulator::ProcessCaptureResult(
    Camera3CaptureDescriptor result) {
  if (result.frame_number() % kFrameCopyInterval != 0) {
    callbacks_.result_callback.Run(std::move(result));
    return true;
  }

  buffer_handle_t handle = nullptr;

  for (auto& stream_buffer : result.GetMutableOutputBuffers()) {
    constexpr int kSyncWaitTimeoutMs = 300;
    if (!stream_buffer.WaitOnAndClearReleaseFence(kSyncWaitTimeoutMs)) {
      LOGF(ERROR) << "Timed out waiting for acquiring output buffer";
      stream_buffer.mutable_raw_buffer().status = CAMERA3_BUFFER_STATUS_ERROR;
      continue;
    }
    handle = *stream_buffer.buffer();
    auto mapping_src = ScopedMapping(handle);
    if (mapping_src.is_valid() && mapping_src.drm_format() == DRM_FORMAT_NV12) {
      ProcessBuffer(mapping_src);
      break;
    }
  }
  if (!handle) {
    LOGF(WARNING) << "Valid output buffer not found for frame number:"
                  << result.frame_number();
  }

  callbacks_.result_callback.Run(std::move(result));
  return true;
}

void FrameAnalysisStreamManipulator::Notify(camera3_notify_msg_t msg) {
  callbacks_.notify_callback.Run(std::move(msg));
}

bool FrameAnalysisStreamManipulator::Flush() {
  return true;
}

void FrameAnalysisStreamManipulator::ProcessBuffer(ScopedMapping& mapping_src) {
  constexpr uint32_t kBufferUsage =
      GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN;

  uint32_t src_width = mapping_src.width();
  uint32_t src_height = mapping_src.height();

  const float kAspectRatioMargin = 0.04;
  const float kTargetAspectRatio16_9 = 1.778;
  const float kTargetAspectRatio4_3 = 1.333;

  float aspect_ratio =
      static_cast<float>(src_width) / static_cast<float>(src_height);

  uint32_t target_width, target_height;

  if (std::fabs(kTargetAspectRatio16_9 - aspect_ratio) < kAspectRatioMargin) {
    target_width = 640;
    target_height = 360;
  } else if (std::fabs(kTargetAspectRatio4_3 - aspect_ratio) <
             kAspectRatioMargin) {
    target_width = 640;
    target_height = 480;
  } else {
    LOGF(WARNING) << "Aspect ratio does not match";
    return;
  }

  // Scaling step
  ScopedBufferHandle scoped_handle = CameraBufferManager::AllocateScopedBuffer(
      target_width, target_height, mapping_src.hal_pixel_format(),
      kBufferUsage);
  buffer_handle_t scaled_buffer = *scoped_handle;
  auto mapping_scaled = ScopedMapping(scaled_buffer);
  int ret = libyuv::NV12Scale(
      mapping_src.plane(0).addr, mapping_src.plane(0).stride,
      mapping_src.plane(1).addr, mapping_src.plane(1).stride, src_width,
      src_height, mapping_scaled.plane(0).addr, mapping_scaled.plane(0).stride,
      mapping_scaled.plane(1).addr, mapping_scaled.plane(1).stride,
      target_width, target_height, libyuv::kFilterBilinear);

  if (ret != 0) {
    LOGF(ERROR) << "libyuv::NV12Scale() failed: " << ret;
  }
  mojom::CameraDiagnosticsFramePtr buffer =
      mojom::CameraDiagnosticsFrame::New();

  uint32_t y_size = mapping_scaled.width() * mapping_scaled.height();
  uint32_t nv12_data_size = y_size * 3 / 2;
  uint8_t* nv12_y_data = new uint8_t[nv12_data_size];
  uint8_t* nv12_uv_data = nv12_y_data + y_size;

  memcpy(nv12_y_data, mapping_scaled.plane(0).addr,
         mapping_scaled.plane(0).size);

  memcpy(nv12_uv_data, mapping_scaled.plane(1).addr,
         mapping_scaled.plane(1).size);

  mojo::ScopedDataPipeProducerHandle producer;
  mojo::ScopedDataPipeConsumerHandle consumer;
  mojo::CreateDataPipe(nv12_data_size, producer, consumer);

  uint32_t nv12_data_size_before = nv12_data_size;

  MojoResult mojo_res = producer->WriteData(nv12_y_data, &nv12_data_size,
                                            MOJO_WRITE_DATA_FLAG_NONE);
  if (mojo_res != MOJO_RESULT_OK || nv12_data_size != nv12_data_size_before) {
    LOGF(ERROR) << "Could not write nv12 data properly";
  }
  buffer->data_handle = std::move(consumer);
  buffer->width = target_width;
  buffer->height = target_height;
  buffer->data_size = nv12_data_size;

  CameraDiagnosticsClient::GetInstance(mojo_manager_token_)
      ->AnalyzeYuvFrame(std::move(buffer));
}

}  // namespace cros
