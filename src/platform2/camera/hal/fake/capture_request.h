/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_FAKE_CAPTURE_REQUEST_H_
#define CAMERA_HAL_FAKE_CAPTURE_REQUEST_H_

#include <vector>

#include <camera/camera_metadata.h>

#include "hardware/camera3.h"

namespace cros {
// CaptureRequest contains all information needed for a capture request.
class CaptureRequest {
 public:
  // Since |request.settings| can be null if the request metadata is the same
  // as previous request, |metadata| contains the latest request metadata
  // that is guaranteed to be not null.
  CaptureRequest(const camera3_capture_request_t& request,
                 const android::CameraMetadata& metadata);
  ~CaptureRequest();

  uint32_t GetFrameNumber() const { return frame_number_; }

  const android::CameraMetadata& GetMetadata() const { return metadata_; }

  std::vector<camera3_stream_buffer_t>& GetStreamBuffers() {
    return output_stream_buffers_;
  }

 private:
  const uint32_t frame_number_;

  const android::CameraMetadata metadata_;

  std::vector<camera3_stream_buffer_t> output_stream_buffers_;
  std::vector<buffer_handle_t> buffer_handles_;
};
}  // namespace cros

#endif  // CAMERA_HAL_FAKE_CAPTURE_REQUEST_H_
