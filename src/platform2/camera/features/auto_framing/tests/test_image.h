/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_AUTO_FRAMING_TESTS_TEST_IMAGE_H_
#define CAMERA_FEATURES_AUTO_FRAMING_TESTS_TEST_IMAGE_H_

#include <cutils/native_handle.h>

#include <optional>
#include <utility>
#include <vector>

#include <base/files/file_path.h>

#include "cros-camera/common_types.h"

namespace cros::tests {

class TestImage {
 public:
  enum class PixelFormat {
    kUnknown,
    kNV12,
  };

  // The metadata corresponding to the raw image that is parsed in JSON format.
  // For example:
  // ```
  // {
  //   "width": 4032,
  //   "height": 3024,
  //   "pixel_format": "NV12",
  //   "face_rectangles": [[2029, 1216, 168, 209]]
  // }
  // ```
  struct Metadata {
    uint32_t width = 0;
    uint32_t height = 0;
    PixelFormat pixel_format = PixelFormat::kUnknown;
    std::vector<Rect<uint32_t>> face_rectangles;
  };

  // Creates an instance from |image_path|.  The metadata file path should be
  // |image_path| appended with ".json". For example, /path/to/image.nv12
  // contains the raw pixel data, and /path/to/image.nv12.json contains the
  // metadata in the format described above.
  static std::optional<TestImage> Create(const base::FilePath& image_path);

  uint32_t width() const;
  uint32_t height() const;
  Size size() const;
  PixelFormat pixel_format() const;
  uint32_t hal_format() const;
  uint32_t drm_format() const;
  const uint8_t* data() const;
  const std::vector<Rect<uint32_t>>& face_rectangles() const;

 private:
  TestImage(std::vector<uint8_t> image, Metadata metadata)
      : image_(std::move(image)), metadata_(std::move(metadata)) {}

  std::vector<uint8_t> image_;
  Metadata metadata_;
};

// Fills the content of |image| into |buffer| with scaling.  Only extracts a
// sub-region |crop| from |image| if provided.
bool WriteTestImageToBuffer(const TestImage& image,
                            buffer_handle_t buffer,
                            std::optional<Rect<uint32_t>> crop = std::nullopt);

}  // namespace cros::tests

#endif  // CAMERA_FEATURES_AUTO_FRAMING_TESTS_TEST_IMAGE_H_
