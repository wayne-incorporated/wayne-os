// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CAMERA_CAMERA3_TEST_CAMERA3_FRAME_FIXTURE_H_
#define CAMERA_CAMERA3_TEST_CAMERA3_FRAME_FIXTURE_H_

#include <memory>
#include <string>
#include <tuple>
#include <vector>

#include "camera3_test/camera3_stream_fixture.h"

namespace camera3_test {

class Camera3FrameFixture : public Camera3StreamFixture {
 public:
  // "kDefaultTimeoutMs" is matched with CTS "WAIT_FOR_RESULT_TIMEOUT_MS"
  const uint32_t kDefaultTimeoutMs = 3000;
  static const uint32_t kARGBPixelWidth = 4;

  explicit Camera3FrameFixture(int cam_id)
      : Camera3StreamFixture(cam_id),
        color_bars_test_patterns_(
            {{
                 // Android standard
                 // Color map:   R   , G   , B   , Start position
                 {0xFF, 0xFF, 0xFF, 0.0f},      // White
                 {0xFF, 0xFF, 0x00, 1.0f / 8},  // Yellow
                 {0x00, 0xFF, 0xFF, 2.0f / 8},  // Cyan
                 {0x00, 0xFF, 0x00, 3.0f / 8},  // Green
                 {0xFF, 0x00, 0xFF, 4.0f / 8},  // Magenta
                 {0xFF, 0x00, 0x00, 5.0f / 8},  // Red
                 {0x00, 0x00, 0xFF, 6.0f / 8},  // Blue
                 {0x00, 0x00, 0x00, 7.0f / 8},  // Black
             },
             {
                 // Ov02a10 color bars
                 {0x00, 0x00, 0xFF, 0.0f},
                 {0x00, 0xFF, 0x00, 1.0f / 8},
                 {0xFF, 0x00, 0x00, 2.0f / 8},
                 {0xC1, 0x8D, 0x07, 3.0f / 8},
                 {0x00, 0xFF, 0xFF, 4.0f / 8},
                 {0xFF, 0x00, 0xFF, 5.0f / 8},
                 {0xFF, 0xFF, 0x00, 6.0f / 8},
                 {0xFF, 0xFF, 0xFF, 7.0f / 8},
             },
             {
                 // OV5670 color bars
                 {0xFF, 0xFF, 0xFF, 0.0f},
                 {0xC8, 0xC8, 0xC8, 1.0f / 16},
                 {0x96, 0x96, 0x96, 2.0f / 16},
                 {0x64, 0x64, 0x64, 3.0f / 16},
                 {0x32, 0x32, 0x32, 4.0f / 16},
                 {0x00, 0x00, 0x00, 5.0f / 16},
                 {0xFF, 0x00, 0x00, 6.0f / 16},
                 {0xFF, 0x32, 0x00, 7.0f / 16},
                 {0xFF, 0x00, 0xE6, 8.0f / 16},
                 {0x00, 0xFF, 0x00, 9.0f / 16},
                 {0x00, 0xFF, 0x00, 10.0f / 16},
                 {0x00, 0xFF, 0x00, 11.0f / 16},
                 {0x00, 0x00, 0xFF, 12.0f / 16},
                 {0xD2, 0x00, 0xFF, 13.0f / 16},
                 {0x00, 0xA0, 0xFF, 14.0f / 16},
                 {0xFF, 0xFF, 0xFF, 15.0f / 16},
             },
             {
                 // OV5695 color bars
                 {0xFF, 0xFF, 0xFF, 0.0f},     // White
                 {0xFF, 0xFF, 0x00, 0.1146f},  // Yellow
                 {0x00, 0xFF, 0xFF, 0.2379f},  // Cyan
                 {0x00, 0xFF, 0x00, 0.3612f},  // Green
                 {0xFF, 0x00, 0xFF, 0.4845f},  // Magenta
                 {0xFF, 0x00, 0x00, 0.6078f},  // Red
                 {0x00, 0x00, 0xFF, 0.7311f},  // Blue
                 {0x00, 0x00, 0x00, 0.8544f},  // Black
             },
             {
                 // IMX258 color bars
                 {0xFF, 0xFF, 0xFF, 0.0f},      // White
                 {0x00, 0xFF, 0xFF, 1.0f / 8},  // Cyan
                 {0xFF, 0xFF, 0x00, 2.0f / 8},  // Yellow
                 {0x00, 0xFF, 0x00, 3.0f / 8},  // Green
                 {0xFF, 0x00, 0xFF, 4.0f / 8},  // Magenta
                 {0x00, 0x00, 0xFF, 5.0f / 8},  // Blue
                 {0xFF, 0x00, 0x00, 6.0f / 8},  // Red
                 {0x00, 0x00, 0x00, 7.0f / 8},  // Black
             },
             {
                 // OV5675 color bars
                 {0xFF, 0xFF, 0xFF, 0.0f},     // White
                 {0x00, 0xFF, 0xFF, 0.1226f},  // Cyan
                 {0xFF, 0xFF, 0x00, 0.2471f},  // Yellow
                 {0x00, 0xFF, 0x00, 0.3679f},  // Green
                 {0xFF, 0x00, 0xFF, 0.4906f},  // Magenta
                 {0x00, 0x00, 0xFF, 0.6132f},  // Blue
                 {0xFF, 0x00, 0x00, 0.7358f},  // Red
                 {0x00, 0x00, 0x00, 0.8585f},  // Black
             }}),
        supported_color_bars_test_pattern_modes_(
            {ANDROID_SENSOR_TEST_PATTERN_MODE_COLOR_BARS_FADE_TO_GRAY,
             ANDROID_SENSOR_TEST_PATTERN_MODE_COLOR_BARS}) {}
  Camera3FrameFixture(const Camera3FrameFixture&) = delete;
  Camera3FrameFixture& operator=(const Camera3FrameFixture&) = delete;

 protected:
  // Create and process capture request of given metadata |metadata|. The frame
  // number of the created request is returned if |frame_number| is not null.
  int CreateCaptureRequestByMetadata(const ScopedCameraMetadata& metadata,
                                     uint32_t* frame_number);

  // Create and process capture request of given template |type|. The frame
  // number of the created request is returned if |frame_number| is not null.
  int CreateCaptureRequestByTemplate(int type, uint32_t* frame_number);

  // Wait for shutter and capture result with timeout
  void WaitShutterAndCaptureResult(const struct timespec& timeout);

  // Get available color bars test pattern modes
  std::vector<int32_t> GetAvailableColorBarsTestPatternModes();

  enum class ImageFormat {
    IMAGE_FORMAT_ARGB,
    IMAGE_FORMAT_I420,
    IMAGE_FORMAT_END
  };

  struct ImagePlane {
    ImagePlane(uint32_t stride, uint32_t size, uint8_t* addr);

    uint32_t stride;
    uint32_t size;
    uint8_t* addr;
  };

  struct Image {
    Image(uint32_t w, uint32_t h, ImageFormat f);
    int SaveToFile(const std::string filename) const;

    uint32_t width;
    uint32_t height;
    ImageFormat format;
    std::vector<uint8_t> data;
    uint32_t size;
    std::vector<ImagePlane> planes;
  };

  typedef std::unique_ptr<struct Image> ScopedImage;

  // Convert the buffer to given format and return a new buffer in the Image
  // structure. The input buffer is freed.
  ScopedImage ConvertToImage(cros::ScopedBufferHandle buffer,
                             uint32_t width,
                             uint32_t height,
                             ImageFormat format);

  // Convert the buffer to given format, rotate the image by rotation and return
  // a new buffer in the Image structure. The input buffer is freed.
  ScopedImage ConvertToImageAndRotate(cros::ScopedBufferHandle buffer,
                                      uint32_t width,
                                      uint32_t height,
                                      ImageFormat format,
                                      int32_t rotation);

  // Generate a new I420 image of color bar pattern
  ScopedImage GenerateColorBarsPattern(
      uint32_t width,
      uint32_t height,
      const std::vector<std::tuple<uint8_t, uint8_t, uint8_t, float>>&
          color_bars_pattern,
      int32_t color_bars_pattern_mode,
      uint32_t sensor_pixel_array_width,
      uint32_t sensor_pixel_array_height);

  // Crop, rotate and scale the input image and return a new I420 image. The
  // input image is freed.
  ScopedImage CropRotateScale(ScopedImage input_image,
                              int32_t rotation_degrees,
                              uint32_t width,
                              uint32_t height);

  // Computes the structural similarity of given images. Given images must
  // be of the I420 format; otherwise, a value of 0.0 is returned. When given
  // images are very similar, it usually returns a score no less than 0.8.
  double ComputeSsim(const Image& buffer_a, const Image& buffer_b);

  std::vector<std::vector<std::tuple<uint8_t, uint8_t, uint8_t, float>>>
      color_bars_test_patterns_;

 private:
  // Create and process capture request of given metadata |metadata|. The frame
  // number of the created request is returned if |frame_number| is not null.
  int32_t CreateCaptureRequest(const camera_metadata_t& metadata,
                               uint32_t* frame_number);

  std::vector<int32_t> supported_color_bars_test_pattern_modes_;
};

void GetTimeOfTimeout(int32_t ms, struct timespec* ts);

}  // namespace camera3_test

#endif  // CAMERA_CAMERA3_TEST_CAMERA3_FRAME_FIXTURE_H_
