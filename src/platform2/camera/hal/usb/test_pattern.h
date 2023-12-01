/* Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_USB_TEST_PATTERN_H_
#define CAMERA_HAL_USB_TEST_PATTERN_H_

#include <memory>

#include <camera/camera_metadata.h>

#include "hal/usb/common_types.h"
#include "hal/usb/frame_buffer.h"

namespace cros {

// Generates YU12 test pattern.
// This class is not thread-safe. Please call the functions on the same thread.
class TestPattern {
 public:
  explicit TestPattern(Size sensor_pixel_array_size, Size resolution);
  TestPattern(const TestPattern&) = delete;
  TestPattern& operator=(const TestPattern&) = delete;

  ~TestPattern();

  // Sets pattern mode.
  bool SetTestPatternMode(int32_t pattern_mode);

  // Returns true if test pattern is enabled.
  bool IsTestPatternEnabled() const;

  // Returns the frame pointer since the ownership is kept in TestPattern.
  FrameBuffer* GetTestPattern();

 private:
  bool GenerateTestPattern();
  bool GenerateColorBar();
  bool GenerateColorBarFadeToGray();
  bool ConvertToYU12();

  Size sensor_pixel_array_size_;
  Size resolution_;
  int32_t pattern_mode_;
  std::unique_ptr<SharedFrameBuffer> pattern_image_rgb_;
  std::unique_ptr<SharedFrameBuffer> pattern_image_yuv_;
};

}  // namespace cros

#endif  // CAMERA_HAL_USB_TEST_PATTERN_H_
