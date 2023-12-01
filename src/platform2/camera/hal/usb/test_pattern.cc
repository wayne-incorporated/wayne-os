/* Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <tuple>
#include <vector>

#include <linux/videodev2.h>

#include <libyuv.h>

#include "cros-camera/common.h"
#include "hal/usb/test_pattern.h"

namespace cros {

TestPattern::TestPattern(Size sensor_pixel_array_size, Size resolution)
    : sensor_pixel_array_size_(sensor_pixel_array_size),
      resolution_(resolution),
      pattern_mode_(ANDROID_SENSOR_TEST_PATTERN_MODE_OFF) {}

TestPattern::~TestPattern() {}

bool TestPattern::SetTestPatternMode(int32_t pattern_mode) {
  if (pattern_mode != pattern_mode_) {
    pattern_image_rgb_.reset();
    pattern_image_yuv_.reset();
    VLOGF(1) << "Set test pattern mode: " << pattern_mode;
  }

  switch (pattern_mode) {
    case ANDROID_SENSOR_TEST_PATTERN_MODE_OFF:
    case ANDROID_SENSOR_TEST_PATTERN_MODE_COLOR_BARS_FADE_TO_GRAY:
      pattern_mode_ = pattern_mode;
      break;
    default:
      LOGF(ERROR) << "Unsupported pattern mode: " << pattern_mode;
      return false;
  }
  return true;
}

bool TestPattern::IsTestPatternEnabled() const {
  return pattern_mode_ != ANDROID_SENSOR_TEST_PATTERN_MODE_OFF;
}

FrameBuffer* TestPattern::GetTestPattern() {
  if (pattern_image_yuv_ && pattern_image_yuv_->GetDataSize()) {
    return pattern_image_yuv_.get();
  }

  if (resolution_.width == 0 || resolution_.height == 0) {
    LOGF(ERROR) << "Invalid resolution: " << resolution_.width << "x"
                << resolution_.height;
    return nullptr;
  }
  if (!GenerateTestPattern()) {
    return nullptr;
  }
  return pattern_image_yuv_.get();
}

bool TestPattern::GenerateTestPattern() {
  switch (pattern_mode_) {
    case ANDROID_SENSOR_TEST_PATTERN_MODE_COLOR_BARS_FADE_TO_GRAY:
      return GenerateColorBarFadeToGray();
    default:
      return false;
  }
}

bool TestPattern::GenerateColorBar() {
  std::vector<std::tuple<uint8_t, uint8_t, uint8_t>> color_bar = {
      // Color map:   R   , G   , B
      std::make_tuple(0xFF, 0xFF, 0xFF),  // White
      std::make_tuple(0xFF, 0xFF, 0x00),  // Yellow
      std::make_tuple(0x00, 0xFF, 0xFF),  // Cyan
      std::make_tuple(0x00, 0xFF, 0x00),  // Green
      std::make_tuple(0xFF, 0x00, 0xFF),  // Magenta
      std::make_tuple(0xFF, 0x00, 0x00),  // Red
      std::make_tuple(0x00, 0x00, 0xFF),  // Blue
      std::make_tuple(0x00, 0x00, 0x00),  // Black
  };
  size_t argb_size =
      sensor_pixel_array_size_.width * sensor_pixel_array_size_.height * 4;
  pattern_image_rgb_.reset(new SharedFrameBuffer(argb_size));

  uint8_t* data = pattern_image_rgb_->GetData();
  int color_bar_width = sensor_pixel_array_size_.width / color_bar.size();
  for (size_t h = 0; h < sensor_pixel_array_size_.height; h++) {
    for (size_t w = 0; w < sensor_pixel_array_size_.width; w++) {
      int index = (w / color_bar_width) % color_bar.size();
      *data++ = std::get<2>(color_bar[index]);  // B
      *data++ = std::get<1>(color_bar[index]);  // G
      *data++ = std::get<0>(color_bar[index]);  // R
      *data++ = 0x00;                           // A
    }
  }

  return ConvertToYU12();
}

bool TestPattern::GenerateColorBarFadeToGray() {
  std::vector<std::tuple<uint8_t, uint8_t, uint8_t>> color_bar = {
      // Color map:   R   , G   , B
      std::make_tuple(0xFF, 0xFF, 0xFF),  // White
      std::make_tuple(0xFF, 0xFF, 0x00),  // Yellow
      std::make_tuple(0x00, 0xFF, 0xFF),  // Cyan
      std::make_tuple(0x00, 0xFF, 0x00),  // Green
      std::make_tuple(0xFF, 0x00, 0xFF),  // Magenta
      std::make_tuple(0xFF, 0x00, 0x00),  // Red
      std::make_tuple(0x00, 0x00, 0xFF),  // Blue
      std::make_tuple(0x00, 0x00, 0x00),  // Black
  };
  size_t argb_size =
      sensor_pixel_array_size_.width * sensor_pixel_array_size_.height * 4;
  pattern_image_rgb_.reset(new SharedFrameBuffer(argb_size));

  uint8_t* data = pattern_image_rgb_->GetData();
  int color_bar_width = sensor_pixel_array_size_.width / color_bar.size();
  int color_bar_height = sensor_pixel_array_size_.height / 128 * 128;
  if (color_bar_height == 0) {
    color_bar_height = sensor_pixel_array_size_.height;
  }
  for (size_t h = 0; h < sensor_pixel_array_size_.height; h++) {
    float gray_factor =
        static_cast<float>(color_bar_height - (h % color_bar_height)) /
        color_bar_height;
    for (size_t w = 0; w < sensor_pixel_array_size_.width; w++) {
      int index = (w / color_bar_width) % color_bar.size();
      auto get_fade_color = [&](uint8_t base_color) {
        uint8_t color = base_color * gray_factor;
        if ((w / (color_bar_width / 2)) % 2) {
          color = (color & 0xF0) | (color >> 4);
        }
        return color;
      };
      *data++ = get_fade_color(std::get<2>(color_bar[index]));  // B
      *data++ = get_fade_color(std::get<1>(color_bar[index]));  // G
      *data++ = get_fade_color(std::get<0>(color_bar[index]));  // R
      *data++ = 0x00;                                           // A
    }
  }

  return ConvertToYU12();
}

bool TestPattern::ConvertToYU12() {
  int cropped_width;
  int cropped_height;
  int crop_x = 0;
  int crop_y = 0;
  if (sensor_pixel_array_size_.width * resolution_.height >
      resolution_.width * sensor_pixel_array_size_.height) {
    cropped_width = sensor_pixel_array_size_.height * resolution_.width /
                    resolution_.height;
    cropped_height = sensor_pixel_array_size_.height;
    if (cropped_width % 2 == 1) {
      // Make cropped_width to the closest even number.
      cropped_width++;
    }
    crop_x = (sensor_pixel_array_size_.width - cropped_width) / 2;
  } else {
    cropped_width = sensor_pixel_array_size_.width;
    cropped_height =
        sensor_pixel_array_size_.width * resolution_.height / resolution_.width;
    if (cropped_height % 2 == 1) {
      // Make cropped_height to the closest even number.
      cropped_height++;
    }
    crop_y = (sensor_pixel_array_size_.height - cropped_height) / 2;
  }
  auto cropped_image_yuv =
      std::make_unique<SharedFrameBuffer>(cropped_width * cropped_height * 1.5);
  int ret = libyuv::ConvertToI420(
      pattern_image_rgb_->GetData(), pattern_image_rgb_->GetDataSize(),
      cropped_image_yuv->GetData(), cropped_width,
      cropped_image_yuv->GetData() + cropped_width * cropped_height,
      cropped_width / 2,
      cropped_image_yuv->GetData() + cropped_width * cropped_height * 5 / 4,
      cropped_width / 2, crop_x, crop_y, sensor_pixel_array_size_.width,
      sensor_pixel_array_size_.height, cropped_width, cropped_height,
      libyuv::RotationMode::kRotate0, libyuv::FourCC::FOURCC_ARGB);
  LOGF_IF(ERROR, ret) << "ConvertToI420() returns " << ret;
  pattern_image_rgb_.reset();
  if (!ret) {
    size_t yuv_size = resolution_.width * resolution_.height * 1.5;
    pattern_image_yuv_.reset(new SharedFrameBuffer(yuv_size));

    ret = libyuv::I420Scale(
        cropped_image_yuv->GetData(), cropped_width,
        cropped_image_yuv->GetData() + cropped_width * cropped_height,
        cropped_width / 2,
        cropped_image_yuv->GetData() + cropped_width * cropped_height * 5 / 4,
        cropped_width / 2, cropped_width, cropped_height,
        pattern_image_yuv_->GetData(), resolution_.width,
        pattern_image_yuv_->GetData() + resolution_.width * resolution_.height,
        resolution_.width / 2,
        pattern_image_yuv_->GetData() +
            resolution_.width * resolution_.height * 5 / 4,
        resolution_.width / 2, resolution_.width, resolution_.height,
        libyuv::FilterMode::kFilterNone);
    LOGF_IF(ERROR, ret) << "I420Scale() returns " << ret;
    if (!ret) {
      pattern_image_yuv_->SetFourcc(V4L2_PIX_FMT_YUV420);
      pattern_image_yuv_->SetWidth(resolution_.width);
      pattern_image_yuv_->SetHeight(resolution_.height);
      pattern_image_yuv_->SetDataSize(yuv_size);
    }
  }
  return ret == 0;
}

}  // namespace cros
