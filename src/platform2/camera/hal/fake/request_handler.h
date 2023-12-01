/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_FAKE_REQUEST_HANDLER_H_
#define CAMERA_HAL_FAKE_REQUEST_HANDLER_H_

#include <memory>
#include <vector>

#include <absl/status/status.h>
#include <base/containers/flat_map.h>
#include <base/task/sequenced_task_runner.h>
#include <camera/camera_metadata.h>
#include <hardware/camera3.h>

#include "hal/fake/capture_request.h"
#include "hal/fake/fake_stream.h"
#include "hal/fake/hal_spec.h"

namespace cros {
// RequestHandler handles all capture request on a dedicated thread, and all
// the methods run on the same thread.
class RequestHandler {
 public:
  // Does not take ownership of |spec|, and the passed in |spec| must outlive
  // this object.
  RequestHandler(const int id,
                 const camera3_callback_ops_t* callback_ops,
                 const android::CameraMetadata& static_metadata,
                 const scoped_refptr<base::SequencedTaskRunner>& task_runner,
                 const CameraSpec& spec);
  ~RequestHandler();

  // Handle one request.
  void HandleRequest(std::unique_ptr<CaptureRequest> request);

  // Handle flush request. This function can be called on any thread.
  void HandleFlush(base::OnceCallback<void()> callback);

  // Start streaming and calls callback with resulting status.
  void StreamOn(const std::vector<camera3_stream_t*>& streams,
                base::OnceCallback<void(absl::Status)> callback);

  // Stop streaming and calls callback with resulting status.
  void StreamOff(base::OnceCallback<void(absl::Status)> callback);

 private:
  // Start streaming implementation.
  absl::Status StreamOnImpl(const std::vector<camera3_stream_t*>& streams);

  // Stop streaming implementation.
  absl::Status StreamOffImpl();

  // Do not wait buffer sync for aborted requests.
  void AbortGrallocBufferSync(CaptureRequest& request);

  // Handle aborted request.
  void HandleAbortedRequest(CaptureRequest& request);

  // Notify shutter event.
  void NotifyShutter(uint32_t frame_number, uint64_t timestamp);

  // Notify request error event.
  void NotifyRequestError(uint32_t frame_number);

  // Fill one result buffer.
  bool FillResultBuffer(camera3_stream_buffer_t& buffer);

  // Used to notify caller that all requests are handled.
  void FlushDone(base::OnceCallback<void()> callback);

  // id of the camera device.
  const int id_;

  // Methods used to call back into the framework.
  const camera3_callback_ops_t* callback_ops_;

  // Task runner for request thread.
  const scoped_refptr<base::SequencedTaskRunner> task_runner_;

  // Map from stream config to fake stream.
  base::flat_map<camera3_stream_t*, std::unique_ptr<FakeStream>> fake_streams_;

  // Camera static characteristics.
  const android::CameraMetadata static_metadata_;

  // Spec for the camera.
  CameraSpec spec_;

  // Timestamp for last response.
  uint64_t last_response_timestamp_ = 0;

  // Used to notify that flush is called from framework.
  bool flush_started_ GUARDED_BY(flush_lock_) = false;

  // Used to guard |flush_started_|.
  base::Lock flush_lock_;
};
}  // namespace cros

#endif  // CAMERA_HAL_FAKE_REQUEST_HANDLER_H_
