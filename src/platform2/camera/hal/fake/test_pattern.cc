/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <tuple>
#include <vector>

#include <base/bits.h>
#include <base/logging.h>
#include <libyuv.h>
#include <linux/videodev2.h>

#include "hal/fake/fake_stream.h"
#include "hal/fake/frame_buffer/gralloc_frame_buffer.h"
#include "hal/fake/test_pattern.h"

#include "cros-camera/common.h"

namespace cros {

namespace {

std::unique_ptr<GrallocFrameBuffer> GenerateTestPatternColorBarsFadeToGray(
    Size size) {
  constexpr uint8_t kColorBar[8][3] = {
      //  R,    G,    B
      {0xFF, 0xFF, 0xFF},  // White
      {0xFF, 0xFF, 0x00},  // Yellow
      {0x00, 0xFF, 0xFF},  // Cyan
      {0x00, 0xFF, 0x00},  // Green
      {0xFF, 0x00, 0xFF},  // Magenta
      {0xFF, 0x00, 0x00},  // Red
      {0x00, 0x00, 0xFF},  // Blue
      {0x00, 0x00, 0x00},  // Black
  };

  // TODO(pihsun): Should this limits be enforced on reading config?
  if (size.width > kFrameMaxDimension || size.height > kFrameMaxDimension) {
    LOGF(WARNING) << "Image size too large for test pattern";
    return nullptr;
  }
  if (size.width < std::size(kColorBar)) {
    LOGF(WARNING) << "Image width too small for test pattern";
    return nullptr;
  }
  if (size.width % 2 != 0 || size.height % 2 != 0) {
    LOGF(WARNING) << "Image width and height should be even";
    return nullptr;
  }

  // TODO(pihsun): Use sensor size and scale.
  size_t argb_size = size.width * size.height * 4;
  std::unique_ptr<uint8_t[]> raw_buffer(new uint8_t[argb_size]);
  if (raw_buffer == nullptr) {
    LOGF(WARNING) << "Failed to create temporary buffer for test pattern";
    return nullptr;
  }

  uint8_t* data = raw_buffer.get();
  int color_bar_width = size.width / std::size(kColorBar);
  int color_bar_height = size.height < 128
                             ? size.height
                             : base::bits::AlignDown(size.height, 128u);
  for (size_t h = 0; h < size.height; h++) {
    float gray_factor =
        static_cast<float>(color_bar_height - (h % color_bar_height)) /
        static_cast<float>(color_bar_height);
    for (size_t w = 0; w < size.width; w++) {
      int index = (w / color_bar_width) % std::size(kColorBar);
      auto get_fade_color = [&](uint8_t base_color) {
        uint8_t color = base_color * gray_factor;
        if ((w / (color_bar_width / 2)) == 1) {
          color = (color & 0xF0) | (color >> 4);
        }
        return color;
      };
      *data++ = get_fade_color(kColorBar[index][2]);  // B
      *data++ = get_fade_color(kColorBar[index][1]);  // G
      *data++ = get_fade_color(kColorBar[index][0]);  // R
      *data++ = 0x00;                                 // A
    }
  }

  auto buffer =
      FrameBuffer::Create<GrallocFrameBuffer>(size, V4L2_PIX_FMT_NV12);
  if (buffer == nullptr) {
    LOGF(WARNING) << "Failed to create buffer for test pattern";
    return nullptr;
  }

  auto mapped_buffer = buffer->Map();
  if (mapped_buffer == nullptr) {
    LOGF(WARNING) << "Failed to map buffer for test pattern";
    return nullptr;
  }

  auto y_plane = mapped_buffer->plane(0);
  auto uv_plane = mapped_buffer->plane(1);

  int ret = libyuv::ARGBToNV12(
      raw_buffer.get(), /*src_stride_argb=*/size.width * 4, y_plane.addr,
      y_plane.stride, uv_plane.addr, uv_plane.stride, size.width, size.height);
  if (ret != 0) {
    LOGF(WARNING) << "ARGBToNV12() failed with " << ret;
    return nullptr;
  }

  return buffer;
}

}  // namespace

std::unique_ptr<GrallocFrameBuffer> GenerateTestPattern(
    Size size, camera_metadata_enum_android_sensor_test_pattern_mode mode) {
  switch (mode) {
    case ANDROID_SENSOR_TEST_PATTERN_MODE_COLOR_BARS_FADE_TO_GRAY:
      return GenerateTestPatternColorBarsFadeToGray(size);
    default:
      LOGF(WARNING) << "test pattern mode not implemented: " << mode;
      return nullptr;
  }
}

}  // namespace cros
