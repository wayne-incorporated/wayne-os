/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_STILL_CAPTURE_PROCESSOR_H_
#define CAMERA_COMMON_STILL_CAPTURE_PROCESSOR_H_

#include <hardware/camera3.h>

#include <base/functional/callback.h>

#include "common/camera_hal3_helpers.h"

namespace cros {

// StillCaptureProcessor handles still capture image requests in a generic and
// asynchronous way.  The contents of a still capture image consist of two
// parts:
//   - The metadata (e.g. APPn segments in JPEG images)
//   - The compressed image data
// Both contents can be (and usually are) generated asynchronous to the main
// real-time video/preview streams.  StillCaptureProcessor can be used to avoid
// blocking the main capture loop and cause jitter on camera preview.
//
// StillCaptureProcessor accepts the still capture requests and the metadata /
// YUV data asynchronously, and produces the compressed image data using the HW
// encoder provided by platform or the default SW encoder.  When all the
// metadata and image data are ready, StillCaptureProcessor assembles the final
// still capture image buffer and returns the result to the camera client
// through asynchronous callback.
class StillCaptureProcessor {
 public:
  // Callback for the StillCaptureProcessor to return capture results to the
  // client asynchronously.
  using CaptureResultCallback =
      base::RepeatingCallback<void(Camera3CaptureDescriptor result)>;

  virtual ~StillCaptureProcessor() = default;

  // Initializes the StillCaptureProcessor with the still capture stream
  // configuration |still_capture_stream| and a callback |result_callback| that
  // will be used to return assembled buffer back to the camera client.
  virtual void Initialize(const camera3_stream_t* const still_capture_stream,
                          CaptureResultCallback result_callback) = 0;

  // Resets the associated still capture stream and flushes pending requests.
  virtual void Reset() = 0;

  // Queues a pending still capture request.  |frame_number| is the frame number
  // as in the HAL3 capture request for the still capture request.
  // |output_buffer| is the buffer that StillCaptureProcessor will need to fill
  // with the assembled image data.  |request_settings| are the parameters of
  // the capture reuquest.
  virtual void QueuePendingOutputBuffer(
      int frame_number,
      camera3_stream_buffer_t output_buffer,
      const Camera3CaptureDescriptor& request) = 0;

  // Queues the pending APPs segments for result |frame_number|, in
  // |blob_buffer|.
  virtual void QueuePendingAppsSegments(int frame_number,
                                        buffer_handle_t blob_buffer,
                                        base::ScopedFD release_fence) = 0;

  // Queues the pending YUV image data for result |frame_number|, in
  // |yuv_buffer|.  The |yuv_buffer| will be encoded to produce the compressed
  // image data, and also the thumbnail is requested.
  virtual void QueuePendingYuvImage(int frame_number,
                                    buffer_handle_t yuv_buffer,
                                    base::ScopedFD release_fence) = 0;
};

}  // namespace cros

#endif  // CAMERA_COMMON_STILL_CAPTURE_PROCESSOR_H_
