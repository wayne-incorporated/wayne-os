/*
 * Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_LIBCAMERA_CONNECTOR_CAMERA_CLIENT_OPS_H_
#define CAMERA_COMMON_LIBCAMERA_CONNECTOR_CAMERA_CLIENT_OPS_H_

#include <vector>

#include <base/containers/flat_map.h>
#include <base/functional/callback.h>
#include <base/synchronization/lock.h>
#include <base/threading/thread.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "camera/mojo/camera3.mojom.h"
#include "common/libcamera_connector/stream_buffer_manager.h"
#include "common/libcamera_connector/types.h"
#include "cros-camera/camera_service_connector.h"

namespace cros {

// CameraClientOps is an implementation of mojom::Camera3CallbackOps and
// manages mojom::Camera3DeviceOps as well. CameraClientOps is expected to be
// initialized every time before a capture session can be started.
//
// When starting a capture session,
//   1. Init() is called to initialize CameraClientOps and
//      mojom::Camera3DeviceOpsRequest is returned. Subsequent calls to the
//      member functions are expected to be run on the same sequence the
//      Init() call ran on.
//   2. The user of this class should then bind mojom::Camera3DeviceOpsRequest
//      before calling StartCapture()
//   3. When StartCapture() is called, it's expected that |device_ops_| is bound
//      CameraClientOps would proceed to start the capture loop and send capture
//      results via |result_callback_|.
//   4. When StopCapture() is called, the capture loop is stopped immediately.
//      To reuse this class, Init() needs to be called to re-initialize the
//      class.
//
//  Error handling: When a serious error is encountered when configuring the
//  capture session or the camera device reported a serious error,
//  CameraClientOps notifies the error to the user of this class with by sending
//  -ENODEV status in the result callback, and the user is expected to close the
//  camera device immediately and stop using CameraClientOps.
class CameraClientOps : public mojom::Camera3CallbackOps {
 public:
  static const int kStreamId = 0;

  using CaptureResultCallback =
      base::RepeatingCallback<void(const cros_cam_capture_result_t&)>;

  CameraClientOps();

  // Initializes the class and returns mojom::Camera3DeviceOpsRequest to be
  // bound. Subsequent calls to other member functions are expected to be run on
  // the same sequence the Init() call ran on.
  mojo::PendingReceiver<mojom::Camera3DeviceOps> Init(
      uint32_t device_api_version, CaptureResultCallback result_callback);

  // Starts the capture session.  StartCapture() initializes the device,
  // configures streams, and starts sending capture requests in a loop. Note
  // that |device_ops_| should be bound before the user makes this call.
  void StartCapture(int32_t camera_id,
                    const cros_cam_format_info_t* format,
                    int32_t jpeg_max_size);

  // Stops the capture session and calls |close_callback| when the device is
  // closed. The capture loop is immediately stopped, but capture results might
  // still be sent after this call.
  void StopCapture(IntOnceCallback close_callback);

  // Resets CameraClientOps. This halts all ongoing CameraClientOps operations
  // and resets the class to an uninitialized state (i.e., Init() can be called
  // to reinitialize the class).
  void Reset();

  // ProcessCaptureResult is an implementation of ProcessCaptureResult in
  // Camera3CallbackOps. It receives the result metadata and filled buffers from
  // the camera service.
  void ProcessCaptureResult(mojom::Camera3CaptureResultPtr result) override;

  // Notify is an implementation of Notify in Camera3CallbackOps. It receives
  // shutter messages and error notifications.
  void Notify(mojom::Camera3NotifyMsgPtr msg) override;

  // RequestStreamBuffers is an implementation of RequestStreamBuffers in
  // Camera3CallbackOps. It receives output buffer requests and a callback to
  // receive results.
  void RequestStreamBuffers(
      std::vector<mojom::Camera3BufferRequestPtr> buffer_reqs,
      RequestStreamBuffersCallback callback) override;

  // ReturnStreamBuffers is an implementation of ReturnStreamBuffers in
  // Camera3CallbackOps. It receives returned output buffers.
  void ReturnStreamBuffers(
      std::vector<mojom::Camera3StreamBufferPtr> buffers) override;

 private:
  void InitializeDevice();

  void OnInitializedDevice(int32_t result);

  void ConfigureStreams();

  void OnConfiguredStreams(
      int32_t result,
      mojom::Camera3StreamConfigurationPtr updated_config,
      base::flat_map<uint64_t, std::vector<mojom::Camera3StreamBufferPtr>>
          allocated_buffers);

  void ConstructDefaultRequestSettings();

  void OnConstructedDefaultRequestSettings(mojom::CameraMetadataPtr settings);

  void ConstructCaptureRequest();

  void ConstructCaptureRequestOnThread();

  void ProcessCaptureRequest(mojom::Camera3CaptureRequestPtr request);

  void OnProcessedCaptureRequest(int32_t result);

  void SendCaptureResult(int status, cros_cam_frame_t* frame);

  void OnClosedDevice(IntOnceCallback close_callback, int32_t result);

  // All public functions and IPC calls through |device_ops_| are expected to be
  // done on |ops_runner_|.
  scoped_refptr<base::SequencedTaskRunner> ops_runner_;

  // |capturing_| indicates whether device has been opened. We use |capturing_|
  // to prevent us from sending additional mojo IPC calls after calling
  // Camera3DeviceOps::Close(). See b/166725158 for context.
  bool capturing_;
  mojo::Remote<mojom::Camera3DeviceOps> device_ops_;
  mojo::Receiver<mojom::Camera3CallbackOps> camera3_callback_ops_;

  uint32_t device_api_version_;

  CaptureResultCallback result_callback_;

  int32_t request_camera_id_;
  cros_cam_format_info_t request_format_;
  int32_t jpeg_max_size_;

  StreamBufferManager buffer_manager_;
  mojom::Camera3StreamConfigurationPtr stream_config_;
  mojom::CameraMetadataPtr request_settings_;

  uint32_t frame_number_;
};

}  // namespace cros

#endif  // CAMERA_COMMON_LIBCAMERA_CONNECTOR_CAMERA_CLIENT_OPS_H_
