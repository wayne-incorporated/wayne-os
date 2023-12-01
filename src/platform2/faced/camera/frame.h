// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FACED_CAMERA_FRAME_H_
#define FACED_CAMERA_FRAME_H_

#include <cstdint>
#include <string>

namespace faced {

// A single frame of data from the camera.
struct Frame {
  enum class Format {
    kUnknown,
    kYuvNv12,  // YUV NV12 format (https://wiki.videolan.org/YUV#NV12).
    kMjpeg,    // Motion JPEG frame.
  };

  Format format;
  uint32_t height;
  uint32_t width;
  std::string data;
};

}  // namespace faced

#endif  // FACED_CAMERA_FRAME_H_
