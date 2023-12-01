/*
 * Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common/libcamera_connector/camera_client_ops.h"

#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/posix/safe_strerror.h>
#include <mojo/public/cpp/system/platform_handle.h>
#include <drm_fourcc.h>
#include <hardware/camera3.h>
#include <hardware/camera_common.h>
#include <hardware/gralloc.h>
#include <sync/sync.h>
#include <sys/mman.h>

#include "camera/mojo/camera3.mojom.h"
#include "common/camera_hal3_helpers.h"
#include "common/libcamera_connector/camera_metadata_utils.h"
#include "common/libcamera_connector/supported_formats.h"
#include "cros-camera/common.h"

namespace cros {

CameraClientOps::CameraClientOps() : camera3_callback_ops_(this) {}

mojo::PendingReceiver<mojom::Camera3DeviceOps> CameraClientOps::Init(
    uint32_t device_api_version, CaptureResultCallback result_callback) {
  ops_runner_ = base::SequencedTaskRunner::GetCurrentDefault();
  capturing_ = false;
  device_api_version_ = device_api_version;
  result_callback_ = std::move(result_callback);
  frame_number_ = 0;
  return device_ops_.BindNewPipeAndPassReceiver();
}

void CameraClientOps::StartCapture(int32_t camera_id,
                                   const cros_cam_format_info_t* format,
                                   int32_t jpeg_max_size) {
  DCHECK(ops_runner_->RunsTasksInCurrentSequence());

  capturing_ = true;
  // TODO(b/151047930): Check whether this format info is actually supported.
  request_camera_id_ = camera_id;
  request_format_ = *format;
  jpeg_max_size_ = jpeg_max_size;
  InitializeDevice();
}

void CameraClientOps::StopCapture(IntOnceCallback close_callback) {
  DCHECK(ops_runner_->RunsTasksInCurrentSequence());

  capturing_ = false;
  device_ops_->Close(base::BindOnce(&CameraClientOps::OnClosedDevice,
                                    base::Unretained(this),
                                    std::move(close_callback)));
}

void CameraClientOps::Reset() {
  DCHECK(ops_runner_->RunsTasksInCurrentSequence());

  capturing_ = false;
  device_ops_.reset();
  camera3_callback_ops_.reset();
}

void CameraClientOps::ProcessCaptureResult(
    mojom::Camera3CaptureResultPtr result) {
  DCHECK(ops_runner_->RunsTasksInCurrentSequence());

  if (!capturing_) {
    return;
  }
  if (result->output_buffers) {
    CHECK_EQ(result->output_buffers->size(), 1u);
    const auto& output_buffer = result->output_buffers->front();
    if (output_buffer->release_fence.is_valid()) {
      base::ScopedPlatformFile fence;
      CHECK_EQ(mojo::UnwrapPlatformFile(std::move(output_buffer->release_fence),
                                        &fence),
               MOJO_RESULT_OK);
      if (sync_wait(fence.get(), 1000) != 0) {
        LOGF(ERROR) << "Failed to wait for release fence on buffer";
      }
    }
    if (output_buffer->status ==
        mojom::Camera3BufferStatus::CAMERA3_BUFFER_STATUS_ERROR) {
      return;
    }

    int64_t page_size = sysconf(_SC_PAGE_SIZE);
    const auto* buffer_handle_ptr = buffer_manager_.GetBufferHandle(
        result->output_buffers->at(0)->buffer_id);
    CHECK_NE(buffer_handle_ptr, nullptr);
    const auto& buffer_handle = *buffer_handle_ptr;
    if (buffer_handle->drm_format == DRM_FORMAT_R8) {
      CHECK_EQ(buffer_handle->fds.size(), 1);

      const auto* fds_ptr = buffer_manager_.GetFds(output_buffer->buffer_id);

      uint32_t unaligned_offset = buffer_handle->offsets[0] % page_size;
      uint32_t mapped_size = buffer_handle->sizes->at(0) + unaligned_offset;
      uint32_t aligned_offset = buffer_handle->offsets[0] - unaligned_offset;
      CHECK_NE(fds_ptr, nullptr);
      void* data = mmap(NULL, mapped_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                        fds_ptr->at(0).get(), aligned_offset);
      CHECK_NE(data, MAP_FAILED);
      auto* blob = reinterpret_cast<camera3_jpeg_blob_t*>(
          static_cast<char*>(data) + unaligned_offset + jpeg_max_size_ -
          sizeof(camera3_jpeg_blob_t));
      CHECK_EQ(blob->jpeg_blob_id, CAMERA3_JPEG_BLOB_ID);

      cros_cam_frame_t frame = {
          .format = request_format_,
          .planes = {{
                         .stride = 0,
                         .size = static_cast<int>(blob->jpeg_size),
                         .data = static_cast<uint8_t*>(data) + unaligned_offset,
                     },
                     {.size = 0},
                     {.size = 0},
                     {.size = 0}}};
      SendCaptureResult(0, &frame);

      munmap(data, mapped_size);
      buffer_manager_.ReleaseBuffer(output_buffer->buffer_id);
    } else if (buffer_handle->drm_format == DRM_FORMAT_NV12) {
      CHECK_EQ(buffer_handle->fds.size(), 2);

      const auto* fds_ptr = buffer_manager_.GetFds(output_buffer->buffer_id);

      uint32_t y_unaligned_offset = buffer_handle->offsets[0] % page_size;
      uint32_t y_mapped_size = buffer_handle->sizes->at(0) + y_unaligned_offset;
      uint32_t y_aligned_offset =
          buffer_handle->offsets[0] - y_unaligned_offset;
      void* y_ptr = mmap(NULL, y_mapped_size, PROT_READ | PROT_WRITE,
                         MAP_SHARED, fds_ptr->at(0).get(), y_aligned_offset);
      CHECK_NE(y_ptr, MAP_FAILED);

      uint32_t cb_unaligned_offset = buffer_handle->offsets[1] % page_size;
      uint32_t cb_mapped_size =
          buffer_handle->sizes->at(1) + cb_unaligned_offset;
      uint32_t cb_aligned_offset =
          buffer_handle->offsets[1] - cb_unaligned_offset;
      void* cb_ptr = mmap(NULL, cb_mapped_size, PROT_READ | PROT_WRITE,
                          MAP_SHARED, fds_ptr->at(1).get(), cb_aligned_offset);
      CHECK_NE(cb_ptr, MAP_FAILED);

      cros_cam_frame_t frame = {
          .format = request_format_,
          .planes = {
              {.stride = static_cast<int>(buffer_handle->strides[0]),
               .size = static_cast<int>(buffer_handle->sizes->at(0)),
               .data = static_cast<uint8_t*>(y_ptr) + y_unaligned_offset},
              {.stride = static_cast<int>(buffer_handle->strides[1]),
               .size = static_cast<int>(buffer_handle->sizes->at(1)),
               .data = static_cast<uint8_t*>(cb_ptr) + cb_unaligned_offset},
              {.size = 0},
              {.size = 0}}};
      SendCaptureResult(0, &frame);

      munmap(y_ptr, y_mapped_size);
      munmap(cb_ptr, cb_mapped_size);
      buffer_manager_.ReleaseBuffer(output_buffer->buffer_id);
    }
  }
}

void CameraClientOps::Notify(mojom::Camera3NotifyMsgPtr msg) {
  DCHECK(ops_runner_->RunsTasksInCurrentSequence());

  // We only need to handle error messages for libcamera_connector.
  if (msg->type != mojom::Camera3MsgType::CAMERA3_MSG_ERROR) {
    return;
  }
  int status = msg->message->get_error()->error_code ==
                       mojom::Camera3ErrorMsgCode::CAMERA3_MSG_ERROR_DEVICE
                   ? -ENODEV
                   : -EIO;
  SendCaptureResult(status, nullptr);
}

void CameraClientOps::RequestStreamBuffers(
    std::vector<mojom::Camera3BufferRequestPtr> buffer_reqs,
    RequestStreamBuffersCallback callback) {
  // TODO(b/226688669): Implement CameraClientOps::RequestStreamBuffers.
}

void CameraClientOps::ReturnStreamBuffers(
    std::vector<mojom::Camera3StreamBufferPtr> buffers) {
  // TODO(b/226688669): Implement CameraClientOps::ReturnStreamBuffers.
}

void CameraClientOps::InitializeDevice() {
  DCHECK(ops_runner_->RunsTasksInCurrentSequence());

  device_ops_->Initialize(camera3_callback_ops_.BindNewPipeAndPassRemote(),
                          base::BindOnce(&CameraClientOps::OnInitializedDevice,
                                         base::Unretained(this)));
}

void CameraClientOps::OnInitializedDevice(int32_t result) {
  DCHECK(ops_runner_->RunsTasksInCurrentSequence());

  if (result != 0) {
    LOGF(ERROR) << "Failed to initialize device: "
                << base::safe_strerror(-result);
    SendCaptureResult(-ENODEV, nullptr);
    return;
  }
  LOGF(INFO) << "Successfully initialized device";
  ConfigureStreams();
}

void CameraClientOps::ConfigureStreams() {
  DCHECK(ops_runner_->RunsTasksInCurrentSequence());
  if (!capturing_) {
    return;
  }

  mojom::Camera3StreamPtr stream = mojom::Camera3Stream::New();
  stream->id = kStreamId;
  stream->stream_type = mojom::Camera3StreamType::CAMERA3_STREAM_OUTPUT;
  stream->width = request_format_.width;
  stream->height = request_format_.height;
  int hal_pixel_format = GetHalPixelFormat(request_format_.fourcc);
  CHECK_NE(hal_pixel_format, 0);
  stream->format = static_cast<mojom::HalPixelFormat>(hal_pixel_format);
  stream->data_space = 0;
  // TODO(b/151047930): Handle device rotations.
  stream->rotation = mojom::Camera3StreamRotation::CAMERA3_STREAM_ROTATION_0;
  if (device_api_version_ >= CAMERA_DEVICE_API_VERSION_3_5) {
    stream->physical_camera_id = "";
  }

  mojom::Camera3StreamConfigurationPtr stream_config =
      mojom::Camera3StreamConfiguration::New();
  stream_config->streams.push_back(std::move(stream));
  stream_config->operation_mode = mojom::Camera3StreamConfigurationMode::
      CAMERA3_STREAM_CONFIGURATION_NORMAL_MODE;
  if (device_api_version_ >= CAMERA_DEVICE_API_VERSION_3_5) {
    stream_config->session_parameters = cros::mojom::CameraMetadata::New();
  }

  device_ops_->ConfigureStreamsAndGetAllocatedBuffers(
      std::move(stream_config),
      base::BindOnce(&CameraClientOps::OnConfiguredStreams,
                     base::Unretained(this)));
}

void CameraClientOps::OnConfiguredStreams(
    int32_t result,
    cros::mojom::Camera3StreamConfigurationPtr updated_config,
    base::flat_map<uint64_t, std::vector<mojom::Camera3StreamBufferPtr>>
        allocated_buffers) {
  DCHECK(ops_runner_->RunsTasksInCurrentSequence());

  if (result != 0) {
    LOGF(ERROR)
        << "Failed to configure streams. Please check your capture parameters: "
        << base::safe_strerror(-result);
    SendCaptureResult(-ENODEV, nullptr);
    return;
  }
  LOGF(INFO) << "Stream configured successfully";
  stream_config_ = std::move(updated_config);
  buffer_manager_.Init(std::move(allocated_buffers[kStreamId]));
  ConstructDefaultRequestSettings();
}

void CameraClientOps::ConstructDefaultRequestSettings() {
  DCHECK(ops_runner_->RunsTasksInCurrentSequence());
  if (!capturing_) {
    return;
  }

  // TODO(b/151047930): Support other templates.
  mojom::Camera3RequestTemplate request_template =
      mojom::Camera3RequestTemplate::CAMERA3_TEMPLATE_PREVIEW;
  device_ops_->ConstructDefaultRequestSettings(
      request_template,
      base::BindOnce(&CameraClientOps::OnConstructedDefaultRequestSettings,
                     base::Unretained(this)));
}

void CameraClientOps::OnConstructedDefaultRequestSettings(
    mojom::CameraMetadataPtr settings) {
  DCHECK(ops_runner_->RunsTasksInCurrentSequence());

  if (settings.is_null()) {
    LOGF(ERROR) << "Failed to construct the specified capture template";
    SendCaptureResult(-ENODEV, nullptr);
    return;
  }
  LOGF(INFO) << "Gotten request template for capture";
  request_settings_ = std::move(settings);
  // TODO(b/151047930): Resolve to a proper fps range.
  SetFpsRangeInMetadata(&request_settings_, request_format_.fps);
  ConstructCaptureRequestOnThread();
}

void CameraClientOps::ConstructCaptureRequest() {
  ops_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&CameraClientOps::ConstructCaptureRequestOnThread,
                     base::Unretained(this)));
}

void CameraClientOps::ConstructCaptureRequestOnThread() {
  DCHECK(ops_runner_->RunsTasksInCurrentSequence());

  if (!buffer_manager_.HasFreeBuffers()) {
    buffer_manager_.SetNotifyBufferCallback(base::BindOnce(
        &CameraClientOps::ConstructCaptureRequest, base::Unretained(this)));
    return;
  }

  mojom::Camera3CaptureRequestPtr request = mojom::Camera3CaptureRequest::New();
  request->frame_number = frame_number_++;
  request->settings = request_settings_.Clone();

  auto buffer = buffer_manager_.AllocateBuffer();
  CHECK(!buffer.is_null());
  request->output_buffers.push_back(std::move(buffer));

  if (device_api_version_ >= CAMERA_DEVICE_API_VERSION_3_5) {
    request->physcam_settings = std::vector<mojom::Camera3PhyscamMetadataPtr>();
  }

  ProcessCaptureRequest(std::move(request));
}

void CameraClientOps::ProcessCaptureRequest(
    mojom::Camera3CaptureRequestPtr request) {
  DCHECK(ops_runner_->RunsTasksInCurrentSequence());
  if (!capturing_) {
    return;
  }

  device_ops_->ProcessCaptureRequest(
      std::move(request),
      base::BindOnce(&CameraClientOps::OnProcessedCaptureRequest,
                     base::Unretained(this)));
}

void CameraClientOps::OnProcessedCaptureRequest(int32_t result) {
  DCHECK(ops_runner_->RunsTasksInCurrentSequence());

  if (result != 0) {
    LOGF(ERROR) << "Failed to send capture request: "
                << base::safe_strerror(-result);
    SendCaptureResult(-ENODEV, nullptr);
    return;
  }
  ConstructCaptureRequestOnThread();
}

void CameraClientOps::SendCaptureResult(int status, cros_cam_frame_t* frame) {
  DCHECK(ops_runner_->RunsTasksInCurrentSequence());

  cros_cam_capture_result_t result = {.status = status, .frame = frame};
  result_callback_.Run(result);
}

void CameraClientOps::OnClosedDevice(IntOnceCallback close_callback,
                                     int32_t result) {
  DCHECK(ops_runner_->RunsTasksInCurrentSequence());

  device_ops_.reset();
  camera3_callback_ops_.reset();
  std::move(close_callback).Run(result);
}

}  // namespace cros
