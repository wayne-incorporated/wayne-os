/*
 * Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <utility>

#include "hal/ip/metadata_handler.h"
#include "hal/ip/request_queue.h"

#include <sync/sync.h>

#include "cros-camera/common.h"

namespace cros {

CaptureRequest::CaptureRequest(const camera3_capture_request_t& request,
                               const android::CameraMetadata& metadata)
    : frame_number_(request.frame_number), metadata_(metadata) {
  output_stream_buffer_.stream = request.output_buffers[0].stream;
  buffer_handle_ = *(request.output_buffers[0].buffer);
  output_stream_buffer_.buffer = &buffer_handle_;
  output_stream_buffer_.status = CAMERA3_BUFFER_STATUS_OK;
  output_stream_buffer_.acquire_fence = request.output_buffers[0].acquire_fence;
  output_stream_buffer_.release_fence = -1;
}

CaptureRequest::~CaptureRequest() {}

const uint32_t CaptureRequest::GetFrameNumber() const {
  return frame_number_;
}

android::CameraMetadata* CaptureRequest::GetMetadata() {
  return &metadata_;
}

const camera3_stream_buffer_t* CaptureRequest::GetOutputBuffer() const {
  return &output_stream_buffer_;
}

void CaptureRequest::SetErrorBufferStatus() {
  output_stream_buffer_.release_fence = output_stream_buffer_.acquire_fence;
  output_stream_buffer_.status = CAMERA3_BUFFER_STATUS_ERROR;
}

RequestQueue::RequestQueue()
    : lock_(),
      queue_(),
      new_request_available_(&lock_),
      request_filled_(&lock_),
      requests_being_filled_(0),
      flushing_(false),
      callback_ops_(nullptr) {}

RequestQueue::~RequestQueue() {
  base::AutoLock l(lock_);
  queue_.clear();
}

void RequestQueue::Push(std::unique_ptr<CaptureRequest> request) {
  base::AutoLock l(lock_);
  if (flushing_) {
    CancelRequestLocked(std::move(request));
  } else {
    queue_.push_back(std::move(request));
    new_request_available_.Signal();
  }
}

std::unique_ptr<CaptureRequest> RequestQueue::Pop() {
  std::unique_ptr<CaptureRequest> request = nullptr;
  {
    base::AutoLock l(lock_);
    if (flushing_) {
      return nullptr;
    }
    while (queue_.empty()) {
      new_request_available_.Wait();
    }
    request = std::move(queue_.front());
    requests_being_filled_++;
    queue_.pop_front();
  }

  const camera3_stream_buffer_t* buffer = request->GetOutputBuffer();
  if (buffer->acquire_fence != -1) {
    if (sync_wait(buffer->acquire_fence, 300)) {
      LOGF(ERROR) << "Timed out waiting on camera buffer acquire fence";
    }
    close(buffer->acquire_fence);
  }

  struct timespec time;
  clock_gettime(CLOCK_MONOTONIC, &time);
  uint64_t timestamp = time.tv_sec * 1000000000LL + time.tv_nsec;
  NotifyShutter(request->GetFrameNumber(), timestamp);

  return request;
}

bool RequestQueue::IsEmpty() {
  base::AutoLock l(lock_);
  return queue_.empty();
}

void RequestQueue::Flush() {
  base::AutoLock l(lock_);
  flushing_ = true;
  while (requests_being_filled_ > 0) {
    request_filled_.Wait();
  }
  while (!queue_.empty()) {
    CancelRequestLocked(std::move(queue_.front()));
    queue_.pop_front();
  }
  flushing_ = false;
}

void RequestQueue::SetCallbacks(const camera3_callback_ops_t* callback_ops) {
  callback_ops_ = callback_ops;
}

void RequestQueue::NotifyShutter(uint32_t frame_number, uint64_t timestamp) {
  if (!callback_ops_) {
    LOGF(ERROR) << "Callbacks weren't set on the request queue.";
    return;
  }

  camera3_notify_msg_t msg = {};
  msg.type = CAMERA3_MSG_SHUTTER;
  msg.message.shutter.frame_number = frame_number;
  msg.message.shutter.timestamp = timestamp;
  callback_ops_->notify(callback_ops_, &msg);
}

void RequestQueue::NotifyCaptureInternal(
    std::unique_ptr<CaptureRequest> request) {
  if (!callback_ops_) {
    LOGF(ERROR) << "Callbacks weren't set on the request queue.";
    return;
  }

  android::CameraMetadata* metadata = request->GetMetadata();
  MetadataHandler::AddResultMetadata(metadata);
  camera3_capture_result_t result = {};
  result.frame_number = request->GetFrameNumber();
  result.result = metadata->getAndLock();
  result.num_output_buffers = 1;
  result.output_buffers = request->GetOutputBuffer();
  result.partial_result = 1;
  callback_ops_->process_capture_result(callback_ops_, &result);
  // request goes out of scope and gets deleted at the end of this function
}

void RequestQueue::NotifyCapture(std::unique_ptr<CaptureRequest> request) {
  NotifyCaptureInternal(std::move(request));
  base::AutoLock l(lock_);
  requests_being_filled_--;
  request_filled_.Signal();
}

void RequestQueue::CancelRequestLocked(
    std::unique_ptr<CaptureRequest> request) {
  if (!callback_ops_) {
    LOGF(ERROR) << "Callbacks weren't set on the request queue.";
    return;
  }
  camera3_notify_msg_t msg = {};
  msg.type = CAMERA3_MSG_ERROR;
  msg.message.error.frame_number = request->GetFrameNumber();
  msg.message.error.error_stream = nullptr;
  msg.message.error.error_code = CAMERA3_MSG_ERROR_REQUEST;
  callback_ops_->notify(callback_ops_, &msg);

  request->SetErrorBufferStatus();
  NotifyCaptureInternal(std::move(request));
}

void RequestQueue::NotifyError(std::unique_ptr<CaptureRequest> request) {
  base::AutoLock l(lock_);
  CancelRequestLocked(std::move(request));
  requests_being_filled_--;
  request_filled_.Signal();
}

}  // namespace cros
