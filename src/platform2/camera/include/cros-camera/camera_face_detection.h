/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_INCLUDE_CROS_CAMERA_CAMERA_FACE_DETECTION_H_
#define CAMERA_INCLUDE_CROS_CAMERA_CAMERA_FACE_DETECTION_H_

#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

#include <base/functional/callback_forward.h>
#include <base/memory/unsafe_shared_memory_region.h>
#include <base/synchronization/lock.h>
#include <base/threading/thread.h>

#include "cros-camera/camera_buffer_manager.h"
#include "cros-camera/common_types.h"
#include "cros-camera/export.h"
#include "cros-camera/face_detector_client_cros_wrapper.h"

namespace cros {

enum class FaceDetectResult {
  kDetectOk,
  kDetectError,
  kBufferError,
  kTransformError,
  kTimeoutError,
};

// This class encapsulates Google3 FaceSSD library.
class CROS_CAMERA_EXPORT FaceDetector {
 public:
  using ResultCallback = base::OnceCallback<void(
      FaceDetectResult, std::vector<human_sensing::CrosFace>)>;

  static std::unique_ptr<FaceDetector> Create();

  ~FaceDetector();

  // Detects human faces. |buffer| should be in NV12 pixel format. The detected
  // results will be stored in |faces|. |human_sensing::CrosFace| includes a
  // bounding box and confidence information.
  //
  // Caller can iterate the vector as the pseudo code:
  //
  // for (const auto& face : faces) {
  //   // Bounding box of the detected face. (x1, y1) is top left corner and
  //   // (x2, y2) is bottom right corner.
  //   float x1 = face.bounding_box.x1, y1 = face.bounding_box.y1,
  //         x2 = face.bounding_box.x2, y2 = face.bounding_box.y2;
  //
  //   // Confidence of the detected face in range [0.0, 1.0]. High confidence
  //   // score corresponds to high likelihood that the detected region is human
  //   // face.
  //   float confidence = face.confidence;
  // }
  //
  // If |active_sensor_array_size| is specified, the coordinates of the bounding
  // boxes in |faces| will be mapped to the "pre-corrected" coordinate space
  // using |active_sensor_array_size| as the raw sensor area, matching the
  // requirement of Android HAL3 requirements. Otherwise, the coordinates of the
  // bounding boxes will be mapped to the dimension of |buffer|.
  FaceDetectResult Detect(
      buffer_handle_t buffer,
      std::vector<human_sensing::CrosFace>* faces,
      std::optional<Size> active_sensor_array_size = std::nullopt);

  // Same as above, detects human faces, but takes the input image as a
  // raw buffer pointer with stride and size. This method can be used when
  // the CameraBufferManager is not available, e.g. when the camera HAL is
  // inside a sandbox that does not allow access to the hardware nodes required
  // by the CameraBufferManager.
  // The |buffer_addr| is the pointer to the input image, a grayscale 8-bit
  // buffer. |input_stride| is the buffer row stride in bytes.
  // |input_size| describes the width and height of the image.
  FaceDetectResult Detect(
      const uint8_t* buffer_addr,
      int input_stride,
      Size input_size,
      std::vector<human_sensing::CrosFace>* faces,
      std::optional<Size> active_sensor_array_size = std::nullopt);

  // Same as the synchronous version but returning status and faces in
  // |result_callback|.  |buffer| is only used during the function call.
  // This method will block until it's done with converting |buffer| to the
  // input format for the face detector.  Caller of this method must make sure
  // |result_callback| won't inter-lock with the calling sequence/thread.
  void DetectAsync(buffer_handle_t buffer,
                   std::optional<Size> active_sensor_array_size,
                   ResultCallback result_callback);

  // Same as the synchronous version but returning status and faces in
  // |result_callback|.  |buffer_addr| is only used during the function call.
  // This method will block until it's done with converting |buffer| to the
  // input format for the face detector.  Caller of this method must make sure
  // |result_callback| won't inter-lock with the calling sequence/thread.
  void DetectAsync(const uint8_t* buffer_addr,
                   int input_stride,
                   Size input_size,
                   std::optional<Size> active_sensor_array_size,
                   ResultCallback result_callback);

  // For a given size |src| that's downscaled and/or cropped from |dst|, get the
  // transformation parameters that converts a coordinate (x, y) in
  // [0, src.width] x [0, src.height] to [0, dst.width] x [0, dst.height]:
  //
  //   x_dst = S * x_src + offset_x
  //   y_dst = S * y_src + offset_y
  //
  // Returns a float tuple (S, offset_x, offset_y).
  static std::optional<std::tuple<float, float, float>> GetCoordinateTransform(
      const Size src, const Size dst);

 private:
  explicit FaceDetector(
      std::unique_ptr<human_sensing::FaceDetectorClientCrosWrapper> wrapper);

  void DetectOnThread(const uint8_t* buffer_addr,
                      int input_stride,
                      Size input_size,
                      std::optional<Size> active_sensor_array_size,
                      ResultCallback result_callback,
                      base::OnceClosure buffer_release_callback);

  void PrepareBuffer(Size img_size);

  // Used to import gralloc buffer.
  CameraBufferManager* buffer_manager_;

  std::vector<uint8_t> scaled_buffer_;

  std::unique_ptr<human_sensing::FaceDetectorClientCrosWrapper> wrapper_;

  base::Thread thread_;
};

std::string LandmarkTypeToString(human_sensing::Landmark::Type type);

}  // namespace cros

#endif  // CAMERA_INCLUDE_CROS_CAMERA_CAMERA_FACE_DETECTION_H_
