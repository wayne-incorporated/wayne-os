// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CAMERA_CAMERA3_TEST_CAMERA3_DEVICE_CONNECTOR_H_
#define CAMERA_CAMERA3_TEST_CAMERA3_DEVICE_CONNECTOR_H_

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <base/threading/thread_checker.h>
#include <gtest/gtest.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "camera/mojo/cros_camera_service.mojom.h"
#include "common/utils/cros_camera_mojo_utils.h"
#include "cros-camera/camera_thread.h"

namespace camera3_test {

class DeviceConnector {
 public:
  virtual ~DeviceConnector() = default;

  // Initialize the device.
  virtual int Initialize(const camera3_callback_ops_t* callback_ops,
                         uint32_t device_api_version) = 0;

  // Configure streams.
  virtual int ConfigureStreams(camera3_stream_configuration_t* stream_list) = 0;

  // Construct default request settings.
  virtual const camera_metadata_t* ConstructDefaultRequestSettings(
      int type) = 0;

  // Process capture request.
  virtual int ProcessCaptureRequest(
      camera3_capture_request_t* capture_request) = 0;

  // Flush all currently in-process captures and all buffers in the pipeline.
  virtual int Flush() = 0;
};

class HalDeviceConnector : public DeviceConnector {
 public:
  HalDeviceConnector(int cam_id, camera3_device_t* cam_device);

  HalDeviceConnector(const HalDeviceConnector&) = delete;
  HalDeviceConnector& operator=(const HalDeviceConnector&) = delete;

  ~HalDeviceConnector() override;

  // DeviceConnector implementation.
  int Initialize(const camera3_callback_ops_t* callback_ops,
                 uint32_t device_api_version) override;
  int ConfigureStreams(camera3_stream_configuration_t* stream_list) override;
  const camera_metadata_t* ConstructDefaultRequestSettings(int type) override;
  int ProcessCaptureRequest(
      camera3_capture_request_t* capture_request) override;
  int Flush() override;

 private:
  void InitializeOnThread(const camera3_callback_ops_t* callback_ops,
                          uint32_t device_api_version,
                          int* result);
  void ConfigureStreamsOnThread(camera3_stream_configuration_t* stream_list,
                                int* result);
  void ConstructDefaultRequestSettingsOnThread(
      int type, const camera_metadata_t** result);
  void ProcessCaptureRequestOnThread(camera3_capture_request_t* request,
                                     int* result);
  void CloseOnThread(int* result);

  camera3_device* cam_device_;
  uint32_t device_api_version_;

  // This thread is needed because of the Chrome OS camera HAL adapter
  // assumption that all the camera3_device_ops functions, except dump, should
  // be called on the same thread. Each device is accessed through a different
  // thread.
  cros::CameraThread dev_thread_;

  THREAD_CHECKER(thread_checker_);
};

class ClientDeviceConnector : public DeviceConnector,
                              public cros::mojom::Camera3CallbackOps {
 public:
  ClientDeviceConnector();

  ClientDeviceConnector(const ClientDeviceConnector&) = delete;
  ClientDeviceConnector& operator=(const ClientDeviceConnector&) = delete;

  ~ClientDeviceConnector() override;

  mojo::PendingReceiver<cros::mojom::Camera3DeviceOps> GetDeviceOpsReceiver();

  // DeviceConnector implementation.
  int Initialize(const camera3_callback_ops_t* callback_ops,
                 uint32_t device_api_version) override;
  int ConfigureStreams(camera3_stream_configuration_t* stream_list) override;
  const camera_metadata_t* ConstructDefaultRequestSettings(int type) override;
  int ProcessCaptureRequest(
      camera3_capture_request_t* capture_request) override;
  int Flush() override;

 private:
  void MakeDeviceOpsReceiverOnThread(
      mojo::PendingReceiver<cros::mojom::Camera3DeviceOps>* dev_ops_rec);

  void CloseOnThread(base::OnceCallback<void(int32_t)> cb);
  void OnClosedOnThread(base::OnceCallback<void(int32_t)> cb, int32_t result);
  void InitializeOnThread(const camera3_callback_ops_t* callback_ops,
                          uint32_t device_api_version,
                          base::OnceCallback<void(int32_t)> cb);
  void ConfigureStreamsOnThread(camera3_stream_configuration_t* stream_list,
                                base::OnceCallback<void(int32_t)> cb);
  void OnConfiguredStreams(
      base::OnceCallback<void(int32_t)> cb,
      int32_t result,
      cros::mojom::Camera3StreamConfigurationPtr updated_config);
  void ConstructDefaultRequestSettingsOnThread(
      int type, base::OnceCallback<void(const camera_metadata_t*)> cb);
  void OnConstructedDefaultRequestSettings(
      int type,
      base::OnceCallback<void(const camera_metadata_t*)> cb,
      cros::mojom::CameraMetadataPtr settings);
  void ProcessCaptureRequestOnThread(camera3_capture_request_t* request,
                                     base::OnceCallback<void(int32_t)> cb);
  cros::mojom::Camera3StreamBufferPtr PrepareStreamBufferPtr(
      const camera3_stream_buffer_t* buffer);
  void Notify(cros::mojom::Camera3NotifyMsgPtr message) override;
  void ProcessCaptureResult(
      cros::mojom::Camera3CaptureResultPtr result) override;
  void RequestStreamBuffers(
      std::vector<cros::mojom::Camera3BufferRequestPtr> buffer_reqs,
      RequestStreamBuffersCallback callback) override;
  void ReturnStreamBuffers(
      std::vector<cros::mojom::Camera3StreamBufferPtr> buffers) override;
  int DecodeStreamBufferPtr(
      const cros::mojom::Camera3StreamBufferPtr& buffer_ptr,
      camera3_stream_buffer_t* buffer);

  uint32_t device_api_version_;
  mojo::Remote<cros::mojom::Camera3DeviceOps> dev_ops_;
  mojo::Receiver<cros::mojom::Camera3CallbackOps> mojo_callback_ops_;
  const camera3_callback_ops_t* user_callback_ops_;
  cros::CameraThread dev_thread_;
  std::set<camera3_stream_t*> camera3_streams_;
  std::map<int, cros::internal::ScopedCameraMetadata> default_req_settings_map_;
  base::Lock buffer_handle_map_lock_;
  std::map<uint64_t, buffer_handle_t*> buffer_handle_map_;
};

}  // namespace camera3_test

#endif  // CAMERA_CAMERA3_TEST_CAMERA3_DEVICE_CONNECTOR_H_
