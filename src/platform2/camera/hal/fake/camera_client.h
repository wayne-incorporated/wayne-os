/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_FAKE_CAMERA_CLIENT_H_
#define CAMERA_HAL_FAKE_CAMERA_CLIENT_H_

#include <memory>
#include <vector>

#include "hal/fake/metadata_handler.h"
#include "hal/fake/request_handler.h"

#include <absl/status/status.h>
#include <base/containers/flat_map.h>
#include <base/sequence_checker.h>
#include <base/threading/thread.h>
#include <camera/camera_metadata.h>
#include <hardware/camera3.h>

#include "hal/fake/hal_spec.h"

namespace cros {

// CameraClient class is not thread-safe. There are three threads in this
// class.
// 1. Hal thread: Called from hal adapter. Constructor and OpenDevice are called
//    on hal thread.
// 2. Device ops thread: Called from hal adapter. Camera v3 Device Operations
//    (except dump) run on this thread. CloseDevice also runs on this thread.
// 3. Request thread: Owned by this class. Used to handle all requests. The
//    functions in RequestHandler run on request thread.
//
// Android framework synchronizes Constructor, OpenDevice, CloseDevice, and
// device ops. The following items are guaranteed by Android frameworks. Note
// that HAL adapter has more restrictions that all functions of device ops
// (except dump) run on the same thread.
// 1. Open, Initialize, and Close are not concurrent with any of the method in
//    device ops.
// 2. Dump can be called at any time.
// 3. ConfigureStreams is not concurrent with either ProcessCaptureRequest or
//    Flush.
// 4. Flush can be called concurrently with ProcessCaptureRequest.
// 5. ConstructDefaultRequestSettings may be called concurrently to any of the
//    device ops.
class CameraClient {
 public:
  CameraClient(int id,
               const android::CameraMetadata& static_metadata,
               const android::CameraMetadata& request_template,
               const hw_module_t* module,
               hw_device_t** hw_device,
               const CameraSpec& spec);
  CameraClient(const CameraClient&) = delete;
  CameraClient& operator=(const CameraClient&) = delete;
  ~CameraClient();

  // Camera Device Operations from CameraHal.
  int OpenDevice();
  int CloseDevice();

  int GetId() const { return id_; }

  // Camera v3 Device Operations (see <hardware/camera3.h>)
  int Initialize(const camera3_callback_ops_t* callback_ops);
  int ConfigureStreams(camera3_stream_configuration_t* stream_config);
  // |type| is camera3_request_template_t in camera3.h.
  const camera_metadata_t* ConstructDefaultRequestSettings(int type);
  int ProcessCaptureRequest(camera3_capture_request_t* request);
  void Dump(int fd);
  int Flush(const camera3_device_t* dev);

 private:
  // Start |request_thread_| and streaming.
  absl::Status StreamOn(const std::vector<camera3_stream_t*>& streams);

  // Stop streaming and |request_thread_|.
  void StreamOff();

  const int id_;

  // Camera device handle returned to framework for use.
  camera3_device_t camera3_device_;

  // Camera static characteristics.
  const android::CameraMetadata static_metadata_;

  // Camera request metadata template.
  const android::CameraMetadata request_template_;

  // Methods used to call back into the framework.
  const camera3_callback_ops_t* callback_ops_;

  // Metadata for latest request.
  android::CameraMetadata latest_request_metadata_;

  std::unique_ptr<RequestHandler> request_handler_;

  // Used to handle requests.
  base::Thread request_thread_;

  // Task runner for request thread.
  scoped_refptr<base::SequencedTaskRunner> request_task_runner_;

  // Spec for the camera client.
  CameraSpec spec_;

  // Metadata handler to save states about metadata.
  MetadataHandler metadata_handler_;

  // Use to check the constructor and OpenDevice are called on the same thread.
  SEQUENCE_CHECKER(sequence_checker_);

  // Use to check camera v3 device operations are called on the same thread.
  SEQUENCE_CHECKER(ops_sequence_checker_);
};

}  // namespace cros

#endif  // CAMERA_HAL_FAKE_CAMERA_CLIENT_H_
