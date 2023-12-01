/*
 * Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_IP_REQUEST_QUEUE_H_
#define CAMERA_HAL_IP_REQUEST_QUEUE_H_

#include <deque>
#include <memory>

#include <base/synchronization/condition_variable.h>
#include <camera/camera_metadata.h>

#include <hardware/camera3.h>

namespace cros {

class CaptureRequest {
 public:
  CaptureRequest(const camera3_capture_request_t& request,
                 const android::CameraMetadata& metadata);
  CaptureRequest(const CaptureRequest&) = delete;
  CaptureRequest& operator=(const CaptureRequest&) = delete;

  ~CaptureRequest();

  const uint32_t GetFrameNumber() const;
  android::CameraMetadata* GetMetadata();
  const camera3_stream_buffer_t* GetOutputBuffer() const;

  void SetErrorBufferStatus();

 private:
  const uint32_t frame_number_;
  android::CameraMetadata metadata_;
  buffer_handle_t buffer_handle_;
  camera3_stream_buffer_t output_stream_buffer_;
};

// This class provides its own locking and is therefore thread-safe. It is
// intended to be used by a single producer and a single consumer.
class RequestQueue {
 public:
  RequestQueue();
  RequestQueue(const RequestQueue&) = delete;
  RequestQueue& operator=(const RequestQueue&) = delete;

  ~RequestQueue();

  // Must be called before using any other functionality of the RequestQueue.
  void SetCallbacks(const camera3_callback_ops_t* callback_ops);

  // Queues a request
  void Push(std::unique_ptr<CaptureRequest> request);

  // If no request is available this will block until one does become available.
  // This can return null if the queue is flushed. This shouldn't be called a
  // second time if the first call has not yet returned.
  std::unique_ptr<CaptureRequest> Pop();

  // Checks if a request is currently available.
  bool IsEmpty();

  // Waits until any requests that have already been popped are completed, then
  // cancels any other pending requests.
  void Flush();

  // Returns a popped request back to the queue, this should be called after the
  // request has been filled.
  void NotifyCapture(std::unique_ptr<CaptureRequest> request);

  // Returns a popped request back to the queue, but signals that an error has
  // occured and the request has not been filled.
  void NotifyError(std::unique_ptr<CaptureRequest> request);

 private:
  void NotifyShutter(uint32_t frame_number, uint64_t timestamp);
  void CancelRequestLocked(std::unique_ptr<CaptureRequest> request);
  void NotifyCaptureInternal(std::unique_ptr<CaptureRequest> request);

  // This lock protects the queue, associated flags/counters, and condition
  // variables.
  base::Lock lock_;
  std::deque<std::unique_ptr<CaptureRequest>> queue_;
  base::ConditionVariable new_request_available_;
  base::ConditionVariable request_filled_;
  int requests_being_filled_;
  bool flushing_;

  const camera3_callback_ops_t* callback_ops_;
};

}  // namespace cros

#endif  // CAMERA_HAL_IP_REQUEST_QUEUE_H_
