/* Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_USB_CACHED_FRAME_H_
#define CAMERA_HAL_USB_CACHED_FRAME_H_

#include <memory>
#include <vector>

#include <camera/camera_metadata.h>

#include "cros-camera/camera_face_detection.h"
#include "cros-camera/camera_metrics.h"
#include "cros-camera/common_types.h"
#include "cros-camera/jpeg_compressor.h"
#include "cros-camera/jpeg_decode_accelerator.h"
#include "hal/usb/image_processor.h"

namespace cros {

// CachedFrame contains a source FrameBuffer and a cached, converted
// FrameBuffer. The incoming frames would be converted to YU12, the default
// format of libyuv, to allow convenient processing.
class CachedFrame {
 public:
  explicit CachedFrame(const android::CameraMetadata& static_metadata);

  // Convert |in_frame| into |out_frames| with |rotate_degree|, cropping,
  // scaling, and format conversion. |rotate_degree| should be 0, 90, or 270.
  // When it returns 0, the |out_frames_status| will have the same size as
  // |out_frames| and record each output frame's conversion status.
  //
  // The |out_frames| don't need to be mapped before calling this function. They
  // will be mapped at a proper time for hardware and software access.
  int Convert(const android::CameraMetadata& static_metadata,
              const android::CameraMetadata& request_metadata,
              int rotate_degree,
              FrameBuffer& in_frame,
              const std::vector<std::unique_ptr<FrameBuffer>>& out_frames,
              std::vector<int>& out_frame_status,
              std::vector<human_sensing::CrosFace>* faces);

 private:
  int ConvertFromNV12(const android::CameraMetadata& static_metadata,
                      const android::CameraMetadata& request_metadata,
                      FrameBuffer& in_frame,
                      FrameBuffer& out_frame);

  int DecodeToNV12(FrameBuffer& in_frame, FrameBuffer& out_frame);

  int DecodeByJDA(FrameBuffer& in_frame, FrameBuffer& out_frame);

  int CompressNV12(const android::CameraMetadata& static_metadata,
                   const android::CameraMetadata& request_metadata,
                   FrameBuffer& in_frame,
                   FrameBuffer& out_frame);

  // |faces| stores the detected results. It will be empty if error.
  void DetectFaces(const FrameBuffer& input_nv12_frame,
                   std::vector<human_sensing::CrosFace>* faces);

  // When we have a landscape mounted camera and the current camera activity is
  // portrait, the frames shown in the activity would be stretched. Therefore,
  // we want to simulate a native portrait camera. That's why we want to crop,
  // rotate |rotate_degree| clockwise and scale the frame. HAL would not change
  // CameraInfo.orientation. Instead, framework would fake the
  // CameraInfo.orientation. Framework would then tell HAL how much the frame
  // needs to rotate clockwise by |rotate_degree|.
  int CropRotateScale(int rotate_degree, FrameBuffer& frame);

  // Cached temporary buffers for the capture pipeline. We use SHM buffer for
  // I420 format since it can be resized, and Gralloc buffer for NV12 format
  // since it will be fed to HW JDA/JEA.
  std::unique_ptr<SharedFrameBuffer> temp_i420_frame_;
  std::unique_ptr<SharedFrameBuffer> temp_i420_frame2_;
  std::unique_ptr<GrallocFrameBuffer> temp_nv12_frame_;
  std::unique_ptr<GrallocFrameBuffer> temp_nv12_frame2_;

  // ImageProcessor instance.
  std::unique_ptr<ImageProcessor> image_processor_;

  // JPEG decoder accelerator (JDA) instance
  std::unique_ptr<JpegDecodeAccelerator> jda_;

  // JPEG compressor instance
  std::unique_ptr<JpegCompressor> jpeg_compressor_;

  // Metrics that used to record things like decoding latency.
  std::unique_ptr<CameraMetrics> camera_metrics_;

  // Indicate if JDA started successfully
  bool jda_available_;

  // max resolution used for JDA
  Size jda_resolution_cap_;

  // Flag to disable SW decode fallback when HW decode failed
  bool force_jpeg_hw_decode_;

  // Face detection handler.
  std::unique_ptr<FaceDetector> face_detector_;
  std::vector<human_sensing::CrosFace> faces_;
  int frame_count_;
  Size active_array_size_;
};

}  // namespace cros

#endif  // CAMERA_HAL_USB_CACHED_FRAME_H_
