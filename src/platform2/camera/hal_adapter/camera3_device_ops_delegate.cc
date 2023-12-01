/*
 * Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hal_adapter/camera3_device_ops_delegate.h"

#include <inttypes.h>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/json/json_writer.h>
#include <base/strings/string_number_conversions.h>

#include "cros-camera/common.h"
#include "hal_adapter/camera_device_adapter.h"
#include "hal_adapter/camera_trace_event.h"

namespace cros {

namespace {

std::string ConvertToJsonString(
    const mojom::Camera3StreamConfigurationPtr& stream_config) {
  base::Value::List val;
  for (const auto& stream : stream_config->streams) {
    base::Value::Dict s;
    s.Set("stream_id", base::NumberToString(stream->id));
    s.Set("width", base::checked_cast<int>(stream->width));
    s.Set("height", base::checked_cast<int>(stream->height));
    s.Set("format", base::checked_cast<int>(stream->format));
    val.Append(std::move(s));
  }
  std::string json_string;
  if (!base::JSONWriter::WriteWithOptions(
          val, base::JSONWriter::OPTIONS_PRETTY_PRINT, &json_string)) {
    LOGF(ERROR) << "Cannot convert Mojo stream configurations to JSON string";
    return std::string();
  }
  return json_string;
}

}  // namespace

Camera3DeviceOpsDelegate::Camera3DeviceOpsDelegate(
    CameraDeviceAdapter* camera_device_adapter,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : internal::MojoReceiver<Camera3DeviceOps>(task_runner),
      camera_device_adapter_(camera_device_adapter) {}

Camera3DeviceOpsDelegate::~Camera3DeviceOpsDelegate() = default;

void Camera3DeviceOpsDelegate::Initialize(
    mojo::PendingRemote<mojom::Camera3CallbackOps> callback_ops,
    InitializeCallback callback) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  TRACE_HAL_ADAPTER();

  std::move(callback).Run(
      camera_device_adapter_->Initialize(std::move(callback_ops)));
}

void Camera3DeviceOpsDelegate::ConfigureStreams(
    mojom::Camera3StreamConfigurationPtr config,
    ConfigureStreamsCallback callback) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  TRACE_HAL_ADAPTER("stream_configurations", ConvertToJsonString(config));

  mojom::Camera3StreamConfigurationPtr updated_config;
  int32_t result = camera_device_adapter_->ConfigureStreams(std::move(config),
                                                            &updated_config);
  std::move(callback).Run(result, std::move(updated_config));
}

void Camera3DeviceOpsDelegate::ConstructDefaultRequestSettings(
    mojom::Camera3RequestTemplate type,
    ConstructDefaultRequestSettingsCallback callback) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  TRACE_HAL_ADAPTER();

  std::move(callback).Run(
      camera_device_adapter_->ConstructDefaultRequestSettings(type));
}

void Camera3DeviceOpsDelegate::ProcessCaptureRequest(
    mojom::Camera3CaptureRequestPtr request,
    ProcessCaptureRequestCallback callback) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  TRACE_HAL_ADAPTER();

  std::move(callback).Run(
      camera_device_adapter_->ProcessCaptureRequest(std::move(request)));
}

void Camera3DeviceOpsDelegate::Dump(mojo::ScopedHandle fd) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  TRACE_HAL_ADAPTER();

  camera_device_adapter_->Dump(std::move(fd));
}

void Camera3DeviceOpsDelegate::Flush(FlushCallback callback) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  TRACE_HAL_ADAPTER();

  std::move(callback).Run(camera_device_adapter_->Flush());
}

void Camera3DeviceOpsDelegate::RegisterBuffer(
    uint64_t buffer_id,
    mojom::Camera3DeviceOps::BufferType type,
    std::vector<mojo::ScopedHandle> fds,
    uint32_t drm_format,
    mojom::HalPixelFormat hal_pixel_format,
    uint32_t width,
    uint32_t height,
    const std::vector<uint32_t>& strides,
    const std::vector<uint32_t>& offsets,
    RegisterBufferCallback callback) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  TRACE_HAL_ADAPTER("buffer_id", buffer_id);

  std::move(callback).Run(camera_device_adapter_->RegisterBuffer(
      buffer_id, type, std::move(fds), drm_format, hal_pixel_format, width,
      height, strides, offsets, DRM_FORMAT_MOD_LINEAR));
}

void Camera3DeviceOpsDelegate::Close(CloseCallback callback) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  TRACE_HAL_ADAPTER();

  std::move(callback).Run(camera_device_adapter_->Close());
}

void Camera3DeviceOpsDelegate::ConfigureStreamsAndGetAllocatedBuffers(
    mojom::Camera3StreamConfigurationPtr config,
    ConfigureStreamsAndGetAllocatedBuffersCallback callback) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  TRACE_HAL_ADAPTER("stream_configurations", ConvertToJsonString(config));

  mojom::Camera3StreamConfigurationPtr updated_config;
  CameraDeviceAdapter::AllocatedBuffers allocated_buffers;
  int32_t result =
      camera_device_adapter_->ConfigureStreamsAndGetAllocatedBuffers(
          std::move(config), &updated_config, &allocated_buffers);
  std::move(callback).Run(result, std::move(updated_config),
                          std::move(allocated_buffers));
}

void Camera3DeviceOpsDelegate::SignalStreamFlush(
    const std::vector<uint64_t>& stream_ids) {
  // TODO(b/226688669): Implement Camera3DeviceOpsDelegate::SignalStreamFlush.
}

}  // namespace cros
