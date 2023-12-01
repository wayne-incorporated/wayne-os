/*
 * Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hal/ip/request_queue.h"

#include <memory>
#include <utility>

#include <gtest/gtest.h>

namespace cros {
namespace {

class RequestQueueTest : public ::testing::Test {
 public:
  RequestQueueTest() {}

 protected:
  void SetUp() override {
    request_queue_ = std::make_unique<RequestQueue>();

    callbacks_this_.this_ = this;
    callbacks_this_.process_capture_result = &ProcessResult;
    callbacks_this_.notify = &Notify;

    request_queue_->SetCallbacks(&callbacks_this_);
  }

  void PushFrame(uint32_t frame_number) {
    android::CameraMetadata metadata;
    camera3_capture_request_t request = {};
    camera3_stream_buffer_t buffer = {};
    buffer_handle_t handle = {};
    buffer.buffer = &handle;
    buffer.acquire_fence = -1;
    request.output_buffers = &buffer;
    request.frame_number = frame_number;
    auto capture_request = std::make_unique<CaptureRequest>(request, metadata);

    request_queue_->Push(std::move(capture_request));
  }

  static void ProcessResult(const struct camera3_callback_ops* ops,
                            const camera3_capture_result_t* result) {
    RequestQueueTest* self = static_cast<const callbacks_this*>(ops)->this_;
    self->num_capture_callbacks_++;
  }

  static void Notify(const struct camera3_callback_ops* ops,
                     const camera3_notify_msg_t* msg) {
    RequestQueueTest* self = static_cast<const callbacks_this*>(ops)->this_;
    if (msg->type == CAMERA3_MSG_SHUTTER) {
      self->num_shutter_callbacks_++;
    }
    if (msg->type == CAMERA3_MSG_ERROR) {
      self->num_error_callbacks_++;
    }
  }

  struct callbacks_this : camera3_callback_ops_t {
    RequestQueueTest* this_;
  } callbacks_this_;
  std::unique_ptr<RequestQueue> request_queue_;
  uint32_t num_shutter_callbacks_ = 0;
  uint32_t num_capture_callbacks_ = 0;
  uint32_t num_error_callbacks_ = 0;
};

TEST_F(RequestQueueTest, OneFrame) {
  PushFrame(1);
  std::unique_ptr<CaptureRequest> request = request_queue_->Pop();
  ASSERT_EQ(request->GetFrameNumber(), 1);
  request_queue_->NotifyCapture(std::move(request));

  EXPECT_EQ(num_shutter_callbacks_, 1);
  EXPECT_EQ(num_capture_callbacks_, 1);
  EXPECT_EQ(num_error_callbacks_, 0);
}

TEST_F(RequestQueueTest, Empty) {
  ASSERT_TRUE(request_queue_->IsEmpty());
  PushFrame(1);
  ASSERT_FALSE(request_queue_->IsEmpty());
  std::unique_ptr<CaptureRequest> request = request_queue_->Pop();
  ASSERT_TRUE(request_queue_->IsEmpty());
  request_queue_->NotifyCapture(std::move(request));
  ASSERT_TRUE(request_queue_->IsEmpty());
}

TEST_F(RequestQueueTest, MultipleFrames) {
  PushFrame(1);
  PushFrame(2);
  std::unique_ptr<CaptureRequest> request = request_queue_->Pop();
  ASSERT_EQ(request->GetFrameNumber(), 1);
  std::unique_ptr<CaptureRequest> request2 = request_queue_->Pop();
  ASSERT_EQ(request2->GetFrameNumber(), 2);
  request_queue_->NotifyCapture(std::move(request));
  request_queue_->NotifyCapture(std::move(request2));

  EXPECT_EQ(num_shutter_callbacks_, 2);
  EXPECT_EQ(num_capture_callbacks_, 2);
  EXPECT_EQ(num_error_callbacks_, 0);
}

TEST_F(RequestQueueTest, Flush) {
  PushFrame(1);
  request_queue_->Flush();
  ASSERT_TRUE(request_queue_->IsEmpty());

  EXPECT_EQ(num_shutter_callbacks_, 0);
  EXPECT_EQ(num_capture_callbacks_, 1);
  EXPECT_EQ(num_error_callbacks_, 1);
}

TEST_F(RequestQueueTest, OneError) {
  PushFrame(1);
  std::unique_ptr<CaptureRequest> request = request_queue_->Pop();
  ASSERT_EQ(request->GetFrameNumber(), 1);
  request_queue_->NotifyError(std::move(request));

  EXPECT_EQ(num_shutter_callbacks_, 1);
  EXPECT_EQ(num_capture_callbacks_, 1);
  EXPECT_EQ(num_error_callbacks_, 1);
}

}  // namespace
}  // namespace cros
