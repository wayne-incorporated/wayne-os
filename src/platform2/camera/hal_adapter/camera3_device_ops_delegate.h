/*
 * Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_ADAPTER_CAMERA3_DEVICE_OPS_DELEGATE_H_
#define CAMERA_HAL_ADAPTER_CAMERA3_DEVICE_OPS_DELEGATE_H_

#include <vector>

#include "camera/mojo/camera3.mojom.h"
#include "common/utils/cros_camera_mojo_utils.h"

namespace cros {

class CameraDeviceAdapter;

class Camera3DeviceOpsDelegate
    : public internal::MojoReceiver<mojom::Camera3DeviceOps> {
 public:
  Camera3DeviceOpsDelegate(
      CameraDeviceAdapter* camera_device_adapter,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner);

  Camera3DeviceOpsDelegate(const Camera3DeviceOpsDelegate&) = delete;
  Camera3DeviceOpsDelegate& operator=(const Camera3DeviceOpsDelegate&) = delete;

  ~Camera3DeviceOpsDelegate() override;

 private:
  void Initialize(mojo::PendingRemote<mojom::Camera3CallbackOps> callback_ops,
                  InitializeCallback callback) override;

  void ConfigureStreams(mojom::Camera3StreamConfigurationPtr config,
                        ConfigureStreamsCallback callback) override;

  void ConstructDefaultRequestSettings(
      mojom::Camera3RequestTemplate type,
      ConstructDefaultRequestSettingsCallback callback) override;

  void ProcessCaptureRequest(mojom::Camera3CaptureRequestPtr request,
                             ProcessCaptureRequestCallback callback) override;

  void Dump(mojo::ScopedHandle fd) override;

  void Flush(FlushCallback callback) override;

  void RegisterBuffer(uint64_t buffer_id,
                      mojom::Camera3DeviceOps::BufferType type,
                      std::vector<mojo::ScopedHandle> fds,
                      uint32_t drm_format,
                      mojom::HalPixelFormat hal_pixel_format,
                      uint32_t width,
                      uint32_t height,
                      const std::vector<uint32_t>& strides,
                      const std::vector<uint32_t>& offsets,
                      RegisterBufferCallback callback) override;

  void Close(CloseCallback callback) override;

  void ConfigureStreamsAndGetAllocatedBuffers(
      mojom::Camera3StreamConfigurationPtr config,
      ConfigureStreamsAndGetAllocatedBuffersCallback callback) override;

  void SignalStreamFlush(const std::vector<uint64_t>& stream_ids) final;

  CameraDeviceAdapter* camera_device_adapter_;
};

}  // namespace cros

#endif  // CAMERA_HAL_ADAPTER_CAMERA3_DEVICE_OPS_DELEGATE_H_
