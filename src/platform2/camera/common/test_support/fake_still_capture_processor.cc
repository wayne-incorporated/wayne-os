/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <sync/sync.h>

#include <utility>

#include <hardware/camera3.h>

#include "common/camera_hal3_helpers.h"
#include "common/test_support/fake_still_capture_processor.h"

namespace cros::tests {

void FakeStillCaptureProcessor::Initialize(
    const camera3_stream_t* const still_capture_stream,
    CaptureResultCallback result_callback) {
  ASSERT_NE(still_capture_stream, nullptr);
  ASSERT_EQ(still_capture_stream->format, HAL_PIXEL_FORMAT_BLOB);
  stream_ = still_capture_stream;
  result_callback_ = std::move(result_callback);
}

void FakeStillCaptureProcessor::Reset() {}

void FakeStillCaptureProcessor::QueuePendingOutputBuffer(
    int frame_number,
    camera3_stream_buffer_t output_buffer,
    const Camera3CaptureDescriptor& request) {
  EXPECT_EQ(result_descriptor_.count(frame_number), 0);
  result_descriptor_.insert({frame_number, ResultDescriptor()});
}

void FakeStillCaptureProcessor::QueuePendingAppsSegments(
    int frame_number,
    buffer_handle_t blob_buffer,
    base::ScopedFD release_fence) {
  ASSERT_EQ(result_descriptor_.count(frame_number), 1);
  if (release_fence.is_valid()) {
    ASSERT_EQ(sync_wait(release_fence.get(), 300), 0);
  }
  result_descriptor_[frame_number].has_apps_segments = true;
  MaybeProduceCaptureResult(frame_number);
}

void FakeStillCaptureProcessor::QueuePendingYuvImage(
    int frame_number,
    buffer_handle_t yuv_buffer,
    base::ScopedFD release_fence) {
  ASSERT_EQ(result_descriptor_.count(frame_number), 1);
  if (release_fence.is_valid()) {
    ASSERT_EQ(sync_wait(release_fence.get(), 1000), 0);
  }
  result_descriptor_[frame_number].has_yuv_buffer = true;
  MaybeProduceCaptureResult(frame_number);
}

void FakeStillCaptureProcessor::MaybeProduceCaptureResult(int frame_number) {
  if (result_descriptor_[frame_number].has_apps_segments &&
      result_descriptor_[frame_number].has_yuv_buffer) {
    camera3_stream_buffer_t stream_buffer = {
        .stream = const_cast<camera3_stream_t*>(stream_),
        .buffer = &fake_buffer_.self,
        .status = CAMERA3_BUFFER_STATUS_OK,
        .acquire_fence = -1,
        .release_fence = -1};
    result_callback_.Run(Camera3CaptureDescriptor(camera3_capture_result_t{
        .frame_number = static_cast<uint32_t>(frame_number),
        .num_output_buffers = 1,
        .output_buffers = &stream_buffer}));
  }
}

}  // namespace cros::tests
