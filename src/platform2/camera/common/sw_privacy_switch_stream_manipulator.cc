/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common/sw_privacy_switch_stream_manipulator.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <drm_fourcc.h>
#include <linux/videodev2.h>
#include <sync/sync.h>

#include "common/camera_hal3_helpers.h"
#include "common/common_tracing.h"
#include "cros-camera/camera_buffer_manager.h"
#include "cros-camera/exif_utils.h"
#include "cros-camera/jpeg_compressor.h"
#include "cros-camera/tracing.h"
#include "gpu/egl/egl_fence.h"

namespace cros {

namespace {

// Used to fill in NV12 buffer with black pixels.
void RedactNV12Frame(ScopedMapping& mapping) {
  // TODO(b/231543984): Consider optimization by GPU.
  auto plane = mapping.plane(0);
  // Set 0 to Y values and padding.
  memset(plane.addr, 0, plane.size);

  // Set 128 to U/V values and padding.
  plane = mapping.plane(1);
  memset(plane.addr, 128, plane.size);
}

// Used to invalidate unsupported types of buffers.
void FillInFrameWithZeros(ScopedMapping& mapping) {
  for (uint32_t i = 0; i < mapping.num_planes(); ++i) {
    auto plane = mapping.plane(i);
    memset(plane.addr, 0, plane.size);
  }
}

}  // namespace

SWPrivacySwitchStreamManipulator::SWPrivacySwitchStreamManipulator(
    RuntimeOptions* runtime_options,
    CameraMojoChannelManagerToken* mojo_manager_token,
    GpuResources* gpu_resources)
    : runtime_options_(runtime_options),
      camera_buffer_manager_(CameraBufferManager::GetInstance()),
      jpeg_compressor_(JpegCompressor::GetInstance(mojo_manager_token)),
      gpu_resources_(gpu_resources) {}

bool SWPrivacySwitchStreamManipulator::Initialize(
    const camera_metadata_t* static_info,
    StreamManipulator::Callbacks callbacks) {
  callbacks_ = std::move(callbacks);
  if (gpu_resources_) {
    bool result = false;
    gpu_resources_->PostGpuTaskSync(
        FROM_HERE,
        base::BindOnce(
            &SWPrivacySwitchStreamManipulator::InitializeBlackFrameOnGpuThread,
            base::Unretained(this)),
        &result);
    return result;
  }
  return true;
}

bool SWPrivacySwitchStreamManipulator::ConfigureStreams(
    Camera3StreamConfiguration* stream_config,
    const StreamEffectMap* stream_effects_map) {
  return true;
}

bool SWPrivacySwitchStreamManipulator::OnConfiguredStreams(
    Camera3StreamConfiguration* stream_config) {
  return true;
}

bool SWPrivacySwitchStreamManipulator::ConstructDefaultRequestSettings(
    android::CameraMetadata* default_request_settings, int type) {
  return true;
}

bool SWPrivacySwitchStreamManipulator::ProcessCaptureRequest(
    Camera3CaptureDescriptor* request) {
  return true;
}

bool SWPrivacySwitchStreamManipulator::ProcessCaptureResult(
    Camera3CaptureDescriptor result) {
  TRACE_COMMON("frame_number", result.frame_number());
  if (runtime_options_->sw_privacy_switch_state() !=
      mojom::CameraPrivacySwitchState::ON) {
    callbacks_.result_callback.Run(std::move(result));
    return true;
  }

  for (auto& buffer : result.GetMutableOutputBuffers()) {
    constexpr int kSyncWaitTimeoutMs = 300;
    if (!buffer.WaitOnAndClearReleaseFence(kSyncWaitTimeoutMs)) {
      LOGF(ERROR) << "Timed out waiting for acquiring output buffer";
      buffer.mutable_raw_buffer().status = CAMERA3_BUFFER_STATUS_ERROR;
      NotifyBufferError(result.frame_number(),
                        buffer.mutable_raw_buffer().stream);
      continue;
    }
    // Try GPU painting first, and fall back to CPU painting if failed.
    if (black_frame_image_.IsValid() &&
        buffer.stream()->format == HAL_PIXEL_FORMAT_YCbCr_420_888) {
      std::optional<base::ScopedFD> fence;
      gpu_resources_->PostGpuTaskSync(
          FROM_HERE,
          base::BindOnce(
              &SWPrivacySwitchStreamManipulator::RedactNV12FrameOnGpu,
              base::Unretained(this), *buffer.buffer()),
          &fence);
      if (fence.has_value()) {
        buffer.mutable_raw_buffer().release_fence = fence->release();
        continue;
      }
    }
    buffer_handle_t handle = *buffer.buffer();
    auto mapping = ScopedMapping(handle);
    bool buffer_cleared = false;
    if (mapping.is_valid()) {
      switch (mapping.drm_format()) {
        case DRM_FORMAT_NV12:
          RedactNV12Frame(mapping);
          buffer_cleared = true;
          break;
        case DRM_FORMAT_R8:  // JPEG.
          buffer_cleared = RedactJpegFrame(
              handle, mapping, buffer.stream()->width, buffer.stream()->height);
          break;
        default:
          FillInFrameWithZeros(mapping);
          LOGF(WARNING) << "Unsupported format "
                        << FormatToString(mapping.drm_format());
          break;
      }
    }
    if (!buffer_cleared) {
      LOGF(ERROR) << "Failed to clear the buffer:"
                  << " hal_pixel_format = " << buffer.stream()->format
                  << ", width = " << buffer.stream()->width
                  << ", height = " << buffer.stream()->height;
      buffer.mutable_raw_buffer().status = CAMERA3_BUFFER_STATUS_ERROR;
      NotifyBufferError(result.frame_number(),
                        buffer.mutable_raw_buffer().stream);
    }
  }

  callbacks_.result_callback.Run(std::move(result));
  return true;
}

void SWPrivacySwitchStreamManipulator::Notify(camera3_notify_msg_t msg) {
  TRACE_COMMON();
  callbacks_.notify_callback.Run(std::move(msg));
}

bool SWPrivacySwitchStreamManipulator::Flush() {
  return true;
}

bool SWPrivacySwitchStreamManipulator::InitializeBlackFrameOnGpuThread() {
  DCHECK(gpu_resources_->gpu_task_runner()->BelongsToCurrentThread());
  // Set width and height to meet horizontal/vertical alignment requirements in
  // GPU.
  black_frame_ = camera_buffer_manager_->AllocateScopedBuffer(
      /*width=*/256, /*height=*/16, HAL_PIXEL_FORMAT_YCbCr_420_888,
      GRALLOC_USAGE_HW_TEXTURE);
  if (black_frame_ == nullptr) {
    LOGF(WARNING) << "Failed to allocate a buffer for the black frame";
    return false;
  }
  auto mapping = ScopedMapping(*black_frame_);
  if (!mapping.is_valid()) {
    LOGF(WARNING) << "Failed to map the black frame buffer";
    return false;
  }
  RedactNV12Frame(mapping);
  black_frame_image_ = SharedImage::CreateFromBuffer(
      *black_frame_, Texture2D::Target::kTarget2D, true);
  return true;
}

std::optional<base::ScopedFD>
SWPrivacySwitchStreamManipulator::RedactNV12FrameOnGpu(buffer_handle_t handle) {
  DCHECK(gpu_resources_->gpu_task_runner()->BelongsToCurrentThread());
  auto output_image =
      SharedImage::CreateFromBuffer(handle, Texture2D::Target::kTarget2D, true);
  if (!output_image.IsValid()) {
    LOGF(WARNING) << "Failed to create SharedImage";
    return std::nullopt;
  }
  if (!gpu_resources_->image_processor()->YUVToYUV(
          black_frame_image_.y_texture(), black_frame_image_.uv_texture(),
          output_image.y_texture(), output_image.uv_texture())) {
    LOGF(WARNING) << "Failed to paint frame with black on GPU";
    return std::nullopt;
  }
  EglFence fence;
  return fence.GetNativeFd();
}

bool SWPrivacySwitchStreamManipulator::RedactJpegFrame(buffer_handle_t handle,
                                                       ScopedMapping& mapping,
                                                       const int width,
                                                       const int height) {
  // TODO(b/231543984): Consider optimization by directly filling in a black
  // JPEG image possibly by GPU.
  ExifUtils utils;
  if (!utils.Initialize()) {
    LOGF(ERROR) << "Failed to initialize ExifUtils";
    return false;
  }
  if (!utils.SetImageWidth(width) || !utils.SetImageLength(height)) {
    LOGF(ERROR) << "Failed to set image resolution";
    return false;
  }

  constexpr uint32_t kBufferUsage =
      GRALLOC_USAGE_SW_WRITE_OFTEN | GRALLOC_USAGE_HW_VIDEO_ENCODER;
  auto in_handle = camera_buffer_manager_->AllocateScopedBuffer(
      width, height, HAL_PIXEL_FORMAT_YCbCr_420_888, kBufferUsage);
  if (in_handle == nullptr) {
    return false;
  }
  auto in_mapping = ScopedMapping(*in_handle);
  if (!in_mapping.is_valid()) {
    return false;
  }
  RedactNV12Frame(in_mapping);

  std::vector<uint8_t> empty_thumbnail;
  if (!utils.GenerateApp1(empty_thumbnail.data(), empty_thumbnail.size())) {
    LOGF(ERROR) << "Failed to generate APP1 segment";
    return false;
  }

  // We do not care about image quality for black frames, so use minimum value
  // 1 here.
  constexpr int kImageQuality = 1;
  uint32_t jpeg_data_size;
  if (!jpeg_compressor_->CompressImageFromHandle(
          *in_handle, handle, width, height, kImageQuality,
          utils.GetApp1Buffer(), utils.GetApp1Length(), &jpeg_data_size)) {
    LOGF(ERROR) << "Failed to compress JPEG image";
    return false;
  }

  auto plane = mapping.plane(0);
  camera3_jpeg_blob_t blob;
  blob.jpeg_blob_id = CAMERA3_JPEG_BLOB_ID;
  blob.jpeg_size = jpeg_data_size;
  memcpy(plane.addr + plane.size - sizeof(blob), &blob, sizeof(blob));

  return true;
}

void SWPrivacySwitchStreamManipulator::NotifyBufferError(
    uint32_t frame_number, camera3_stream_t* stream) {
  camera3_notify_msg_t msg = {
      .type = CAMERA3_MSG_ERROR,
      .message =
          {
              .error =
                  {
                      .frame_number = frame_number,
                      .error_stream = stream,
                      .error_code = CAMERA3_MSG_ERROR_BUFFER,
                  },
          },
  };
  Notify(std::move(msg));
}

}  // namespace cros
