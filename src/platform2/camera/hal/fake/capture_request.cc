/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hal/fake/capture_request.h"

namespace cros {

CaptureRequest::CaptureRequest(const camera3_capture_request_t& request,
                               const android::CameraMetadata& metadata)
    : frame_number_(request.frame_number),
      metadata_(metadata),
      buffer_handles_(request.num_output_buffers) {
  for (size_t i = 0; i < request.num_output_buffers; i++) {
    const camera3_stream_buffer_t* from = &request.output_buffers[i];

    buffer_handles_[i] = *from->buffer;

    camera3_stream_buffer_t to = {
        .stream = from->stream,
        .buffer = &buffer_handles_[i],
        .status = CAMERA3_BUFFER_STATUS_OK,
        .acquire_fence = from->acquire_fence,
        .release_fence = -1,
    };
    output_stream_buffers_.push_back(to);
  }
}

CaptureRequest::~CaptureRequest() = default;

}  // namespace cros
