/* Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hal/usb/capture_request.h"

namespace cros {

const int kBufferFenceReady = -1;

CaptureRequest::CaptureRequest(const camera3_capture_request& request,
                               const android::CameraMetadata& metadata)
    : frame_number_(request.frame_number), metadata_(metadata) {
  // We cannot merge the two loops because the address of elements in
  // buffer_handles_ may be changed when new element is push into the vector.
  for (size_t i = 0; i < request.num_output_buffers; i++) {
    buffer_handles_.push_back(*request.output_buffers[i].buffer);
  }

  for (size_t i = 0; i < request.num_output_buffers; i++) {
    const camera3_stream_buffer_t* from = &request.output_buffers[i];
    camera3_stream_buffer_t to;
    memset(&to, 0, sizeof(camera3_stream_buffer_t));

    to.stream = from->stream;
    to.buffer = &buffer_handles_[i];
    to.status = CAMERA3_BUFFER_STATUS_OK;
    to.acquire_fence = from->acquire_fence;
    to.release_fence = kBufferFenceReady;
    output_stream_buffers_.push_back(to);
  }
}

CaptureRequest::~CaptureRequest() {}

}  // namespace cros
