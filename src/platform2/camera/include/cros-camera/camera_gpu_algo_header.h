/*
 * Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_INCLUDE_CROS_CAMERA_CAMERA_GPU_ALGO_HEADER_H_
#define CAMERA_INCLUDE_CROS_CAMERA_CAMERA_GPU_ALGO_HEADER_H_

namespace cros {

enum class CameraGPUAlgoCommand { PORTRAIT_MODE };

typedef struct {
  CameraGPUAlgoCommand command;
  union {
    struct {
      int32_t input_buffer_handle;
      int32_t output_buffer_handle;
      uint32_t width;
      uint32_t height;
      uint32_t orientation;
    } portrait_mode;
  } params;
} CameraGPUAlgoCmdHeader;

}  // namespace cros

#endif  // CAMERA_INCLUDE_CROS_CAMERA_CAMERA_GPU_ALGO_HEADER_H_
