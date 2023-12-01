// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "camera3_test/camera3_frame_fixture.h"

#include <linux/videodev2.h>
#include <semaphore.h>
#include <stdio.h>

#include <iterator>
#include <limits>
#include <list>
#include <unordered_map>
#include <unordered_set>

#include <base/command_line.h>
#include <base/files/file_util.h>
#include <base/notreached.h>
#include <base/strings/string_split.h>
#include <jpeglib.h>
#include <libyuv.h>

#include "camera3_test/camera3_perf_log.h"
#include "cros-camera/common.h"

namespace camera3_test {

int32_t Camera3FrameFixture::CreateCaptureRequest(
    const camera_metadata_t& metadata, uint32_t* frame_number) {
  // Allocate output buffers
  std::vector<camera3_stream_buffer_t> output_buffers;
  if (cam_device_.AllocateOutputStreamBuffers(&output_buffers)) {
    ADD_FAILURE() << "Failed to allocate buffers for capture request";
    return -EINVAL;
  }

  camera3_capture_request_t capture_request = {
      .frame_number = UINT32_MAX,
      .settings = &metadata,
      .input_buffer = NULL,
      .num_output_buffers = static_cast<uint32_t>(output_buffers.size()),
      .output_buffers = output_buffers.data(),
      .num_physcam_settings = 0};

  // Process capture request
  int32_t ret = cam_device_.ProcessCaptureRequest(&capture_request);
  if (ret == 0 && frame_number) {
    *frame_number = capture_request.frame_number;
  }
  return ret;
}

int32_t Camera3FrameFixture::CreateCaptureRequestByMetadata(
    const ScopedCameraMetadata& metadata, uint32_t* frame_number) {
  return CreateCaptureRequest(*metadata, frame_number);
}

int32_t Camera3FrameFixture::CreateCaptureRequestByTemplate(
    int32_t type, uint32_t* frame_number) {
  const camera_metadata_t* default_settings;
  default_settings = cam_device_.ConstructDefaultRequestSettings(type);
  if (!default_settings) {
    ADD_FAILURE() << "Camera default settings are NULL";
    return -EINVAL;
  }

  return CreateCaptureRequest(*default_settings, frame_number);
}

void Camera3FrameFixture::WaitShutterAndCaptureResult(
    const struct timespec& timeout) {
  ASSERT_EQ(0, cam_device_.WaitShutter(timeout))
      << "Timeout waiting for shutter callback";
  ASSERT_EQ(0, cam_device_.WaitCaptureResult(timeout))
      << "Timeout waiting for capture result callback";
}

std::vector<int32_t>
Camera3FrameFixture::GetAvailableColorBarsTestPatternModes() {
  std::vector<int32_t> test_pattern_modes;
  if (cam_device_.GetStaticInfo()->GetAvailableTestPatternModes(
          &test_pattern_modes) != 0) {
    ADD_FAILURE() << "Failed to get sensor available test pattern modes";
    return std::vector<int32_t>();
  }
  std::vector<int32_t> result;
  for (const auto& it : supported_color_bars_test_pattern_modes_) {
    if (std::find(test_pattern_modes.begin(), test_pattern_modes.end(), it) !=
        test_pattern_modes.end()) {
      result.push_back(it);
    }
  }
  return result;
}

Camera3FrameFixture::ImagePlane::ImagePlane(uint32_t stride,
                                            uint32_t size,
                                            uint8_t* addr)
    : stride(stride), size(size), addr(addr) {}

#define DIV_ROUND_UP(n, d) (((n) + (d)-1) / (d))
Camera3FrameFixture::Image::Image(uint32_t w, uint32_t h, ImageFormat f)
    : width(w), height(h), format(f) {
  if (format == ImageFormat::IMAGE_FORMAT_ARGB) {
    size = w * h * kARGBPixelWidth;
    data.resize(size);
    planes.emplace_back(w * kARGBPixelWidth, size, data.data());
  } else if (format == ImageFormat::IMAGE_FORMAT_I420) {
    uint32_t cstride = DIV_ROUND_UP(w, 2);
    size = w * h + cstride * DIV_ROUND_UP(h, 2) * 2;
    uint32_t uv_plane_size = cstride * DIV_ROUND_UP(h, 2);
    data.resize(size);
    planes.emplace_back(w, w * h, data.data());  // y
    planes.emplace_back(cstride, uv_plane_size,
                        planes.back().addr + planes.back().size);  // u
    planes.emplace_back(cstride, uv_plane_size,
                        planes.back().addr + planes.back().size);  // v
  }
}

int Camera3FrameFixture::Image::SaveToFile(const std::string filename) const {
  const char* suffix =
      (format == ImageFormat::IMAGE_FORMAT_ARGB) ? ".argb" : ".i420";
  base::FilePath file_path(filename + suffix);
  if (base::WriteFile(file_path, reinterpret_cast<const char*>(data.data()),
                      size) != size) {
    LOGF(ERROR) << "Failed to write file " << filename << suffix;
    return -EINVAL;
  }
  return 0;
}

Camera3FrameFixture::ScopedImage Camera3FrameFixture::ConvertToImage(
    cros::ScopedBufferHandle buffer,
    uint32_t width,
    uint32_t height,
    ImageFormat format) {
  if (!buffer || format >= ImageFormat::IMAGE_FORMAT_END) {
    LOGF(ERROR) << "Invalid input buffer or format";
    return ScopedImage(nullptr);
  }
  buffer_handle_t handle = *buffer;
  auto hnd = camera_buffer_handle_t::FromBufferHandle(handle);
  if (!hnd || hnd->buffer_id == 0) {
    LOGF(ERROR) << "Invalid input buffer handle";
    return ScopedImage(nullptr);
  }
  ScopedImage out_buffer(new Image(width, height, format));
  auto gralloc = Camera3TestGralloc::GetInstance();
  if (gralloc->GetFormat(handle) == HAL_PIXEL_FORMAT_BLOB) {
    size_t jpeg_max_size = cam_device_.GetStaticInfo()->GetJpegMaxSize();
    void* buf_addr = nullptr;
    if (gralloc->Lock(handle, 0, 0, 0, jpeg_max_size, 1, &buf_addr) != 0 ||
        !buf_addr) {
      LOGF(ERROR) << "Failed to lock input buffer";
      return ScopedImage(nullptr);
    }
    auto jpeg_blob = reinterpret_cast<camera3_jpeg_blob_t*>(
        static_cast<uint8_t*>(buf_addr) + jpeg_max_size -
        sizeof(camera3_jpeg_blob_t));
    if (static_cast<void*>(jpeg_blob) < buf_addr ||
        jpeg_blob->jpeg_blob_id != CAMERA3_JPEG_BLOB_ID) {
      gralloc->Unlock(handle);
      LOGF(ERROR) << "Invalid JPEG BLOB ID";
      return ScopedImage(nullptr);
    }
    if ((format == ImageFormat::IMAGE_FORMAT_I420 &&
         libyuv::MJPGToI420(
             static_cast<uint8_t*>(buf_addr), jpeg_blob->jpeg_size,
             out_buffer->planes[0].addr, out_buffer->planes[0].stride,
             out_buffer->planes[1].addr, out_buffer->planes[1].stride,
             out_buffer->planes[2].addr, out_buffer->planes[2].stride, width,
             height, width, height) != 0) ||
        (format == ImageFormat::IMAGE_FORMAT_ARGB &&
         libyuv::MJPGToARGB(static_cast<uint8_t*>(buf_addr),
                            jpeg_blob->jpeg_size, out_buffer->planes[0].addr,
                            out_buffer->planes[0].stride, width, height, width,
                            height) != 0)) {
      LOGF(ERROR) << "Failed to convert image from JPEG";
      out_buffer.reset();
    }
    gralloc->Unlock(handle);
  } else {
    struct android_ycbcr in_ycbcr_info;
    if (gralloc->LockYCbCr(handle, 0, 0, 0, width, height, &in_ycbcr_info) !=
        0) {
      LOGF(ERROR) << "Failed to lock input buffer";
      return ScopedImage(nullptr);
    }
    uint32_t v4l2_format =
        cros::CameraBufferManager::GetV4L2PixelFormat(handle);
    switch (v4l2_format) {
      case V4L2_PIX_FMT_NV12:
      case V4L2_PIX_FMT_NV12M:
        if ((format == ImageFormat::IMAGE_FORMAT_I420 &&
             libyuv::NV12ToI420(
                 static_cast<uint8_t*>(in_ycbcr_info.y), in_ycbcr_info.ystride,
                 static_cast<uint8_t*>(in_ycbcr_info.cb), in_ycbcr_info.cstride,
                 out_buffer->planes[0].addr, out_buffer->planes[0].stride,
                 out_buffer->planes[1].addr, out_buffer->planes[1].stride,
                 out_buffer->planes[2].addr, out_buffer->planes[2].stride,
                 width, height) != 0) ||
            (format == ImageFormat::IMAGE_FORMAT_ARGB &&
             libyuv::NV12ToARGB(
                 static_cast<uint8_t*>(in_ycbcr_info.y), in_ycbcr_info.ystride,
                 static_cast<uint8_t*>(in_ycbcr_info.cb), in_ycbcr_info.cstride,
                 out_buffer->planes[0].addr, out_buffer->planes[0].stride,
                 width, height) != 0)) {
          LOGF(ERROR) << "Failed to convert image from NV12";
          out_buffer.reset();
        }
        break;
      case V4L2_PIX_FMT_NV21:
      case V4L2_PIX_FMT_NV21M:
        if ((format == ImageFormat::IMAGE_FORMAT_I420 &&
             libyuv::NV21ToI420(
                 static_cast<uint8_t*>(in_ycbcr_info.y), in_ycbcr_info.ystride,
                 static_cast<uint8_t*>(in_ycbcr_info.cr), in_ycbcr_info.cstride,
                 out_buffer->planes[0].addr, out_buffer->planes[0].stride,
                 out_buffer->planes[1].addr, out_buffer->planes[1].stride,
                 out_buffer->planes[2].addr, out_buffer->planes[2].stride,
                 width, height) != 0) ||
            (format == ImageFormat::IMAGE_FORMAT_ARGB &&
             libyuv::NV21ToARGB(
                 static_cast<uint8_t*>(in_ycbcr_info.y), in_ycbcr_info.ystride,
                 static_cast<uint8_t*>(in_ycbcr_info.cr), in_ycbcr_info.cstride,
                 out_buffer->planes[0].addr, out_buffer->planes[0].stride,
                 width, height) != 0)) {
          LOGF(ERROR) << "Failed to convert image from NV21";
          out_buffer.reset();
        }
        break;
      case V4L2_PIX_FMT_YUV420:
      case V4L2_PIX_FMT_YUV420M:
      case V4L2_PIX_FMT_YVU420:
      case V4L2_PIX_FMT_YVU420M:
        if ((format == ImageFormat::IMAGE_FORMAT_I420 &&
             libyuv::I420Copy(
                 static_cast<uint8_t*>(in_ycbcr_info.y), in_ycbcr_info.ystride,
                 static_cast<uint8_t*>(in_ycbcr_info.cb), in_ycbcr_info.cstride,
                 static_cast<uint8_t*>(in_ycbcr_info.cr), in_ycbcr_info.cstride,
                 out_buffer->planes[0].addr, out_buffer->planes[0].stride,
                 out_buffer->planes[1].addr, out_buffer->planes[1].stride,
                 out_buffer->planes[2].addr, out_buffer->planes[2].stride,
                 width, height) != 0) ||
            (format == ImageFormat::IMAGE_FORMAT_ARGB &&
             libyuv::I420ToARGB(
                 static_cast<uint8_t*>(in_ycbcr_info.y), in_ycbcr_info.ystride,
                 static_cast<uint8_t*>(in_ycbcr_info.cb), in_ycbcr_info.cstride,
                 static_cast<uint8_t*>(in_ycbcr_info.cr), in_ycbcr_info.cstride,
                 out_buffer->planes[0].addr, out_buffer->planes[0].stride,
                 width, height) != 0)) {
          LOGF(ERROR) << "Failed to convert image from YUV420 or YVU420";
          out_buffer.reset();
        }
        break;
      default:
        LOGF(ERROR) << "Unsupported format " << FormatToString(v4l2_format);
        out_buffer.reset();
    }
    gralloc->Unlock(handle);
  }
  return out_buffer;
}

Camera3FrameFixture::ScopedImage Camera3FrameFixture::ConvertToImageAndRotate(
    cros::ScopedBufferHandle buffer,
    uint32_t width,
    uint32_t height,
    ImageFormat format,
    int32_t rotation) {
  ScopedImage image = ConvertToImage(std::move(buffer), width, height, format);
  if (image == nullptr) {
    LOGF(ERROR) << "Failed to convert image before rotate";
    return image;
  }
  if (format != ImageFormat::IMAGE_FORMAT_I420) {
    LOGF(ERROR) << "Do not support rotate image with format: "
                << static_cast<int>(format);
    return image;
  }

  int new_width = width;
  int new_height = height;
  libyuv::RotationMode rotationMode;

  if (rotation % 180 == 90) {
    std::swap(new_width, new_height);
  }

  switch (rotation) {
    case 90:
      rotationMode = libyuv::kRotate90;
      break;
    case 180:
      rotationMode = libyuv::kRotate180;
      break;
    case 270:
      rotationMode = libyuv::kRotate270;
      break;
    default:
      rotationMode = libyuv::kRotate0;
      break;
  }

  ScopedImage rotated_image(
      new Image(new_width, new_height, ImageFormat::IMAGE_FORMAT_I420));
  libyuv::I420Rotate(
      image->planes[0].addr, image->planes[0].stride, image->planes[1].addr,
      image->planes[1].stride, image->planes[2].addr, image->planes[2].stride,
      rotated_image->planes[0].addr, rotated_image->planes[0].stride,
      rotated_image->planes[1].addr, rotated_image->planes[1].stride,
      rotated_image->planes[2].addr, rotated_image->planes[2].stride, width,
      height, rotationMode);
  return rotated_image;
}

Camera3FrameFixture::ScopedImage Camera3FrameFixture::GenerateColorBarsPattern(
    uint32_t width,
    uint32_t height,
    const std::vector<std::tuple<uint8_t, uint8_t, uint8_t, float>>&
        color_bars_pattern,
    int32_t color_bars_pattern_mode,
    uint32_t sensor_pixel_array_width,
    uint32_t sensor_pixel_array_height) {
  if (std::find(supported_color_bars_test_pattern_modes_.begin(),
                supported_color_bars_test_pattern_modes_.end(),
                color_bars_pattern_mode) ==
      supported_color_bars_test_pattern_modes_.end()) {
    return nullptr;
  }
  ScopedImage argb_image(new Image(sensor_pixel_array_width,
                                   sensor_pixel_array_height,
                                   ImageFormat::IMAGE_FORMAT_ARGB));
  uint8_t* pdata = argb_image->planes[0].addr;
  int color_bar_height = sensor_pixel_array_height / 128 * 128;
  if (color_bar_height == 0) {
    color_bar_height = sensor_pixel_array_height;
  }
  for (size_t h = 0; h < sensor_pixel_array_height; h++) {
    float gray_factor =
        static_cast<float>(color_bar_height - (h % color_bar_height)) /
        color_bar_height;
    int index = 0;
    for (size_t w = 0; w < sensor_pixel_array_width; w++) {
      if (index + 1 < color_bars_pattern.size() &&
          w > sensor_pixel_array_width *
                  std::get<3>(color_bars_pattern[index + 1])) {
        index++;
      }
      auto get_fade_color = [&](uint8_t base_color) {
        if (color_bars_pattern_mode ==
            ANDROID_SENSOR_TEST_PATTERN_MODE_COLOR_BARS) {
          return base_color;
        }
        uint8_t color = base_color * gray_factor;
        const int start = std::get<3>(color_bars_pattern[index]);
        const int end = (index + 1 == color_bars_pattern.size())
                            ? 1.0f
                            : std::get<3>(color_bars_pattern[index + 1]);
        if (w > (start + end) / 2 * sensor_pixel_array_width) {
          color = (color & 0xF0) | (color >> 4);
        }
        return color;
      };
      *pdata++ = get_fade_color(std::get<2>(color_bars_pattern[index]));  // B
      *pdata++ = get_fade_color(std::get<1>(color_bars_pattern[index]));  // G
      *pdata++ = get_fade_color(std::get<0>(color_bars_pattern[index]));  // R
      *pdata++ = 0x00;
    }
  }

  return CropRotateScale(std::move(argb_image), 0, width, height);
}

Camera3FrameFixture::ScopedImage Camera3FrameFixture::CropRotateScale(
    ScopedImage input_image,
    int32_t rotation_degrees,
    uint32_t width,
    uint32_t height) {
  if (input_image->format != ImageFormat::IMAGE_FORMAT_ARGB &&
      input_image->format != ImageFormat::IMAGE_FORMAT_I420) {
    ADD_FAILURE() << "Unsupported image format";
    return nullptr;
  }
  libyuv::RotationMode rotation_mode = libyuv::RotationMode::kRotate0;
  switch (rotation_degrees) {
    case 0:
      break;
    case 90:
      rotation_mode = libyuv::RotationMode::kRotate90;
      break;
    case 270:
      rotation_mode = libyuv::RotationMode::kRotate270;
      break;
    default:
      LOGF(ERROR) << "Invalid rotation degree: " << rotation_degrees;
      return nullptr;
  }
  int cropped_width;
  int cropped_height;
  int crop_x = 0;
  int crop_y = 0;
  if (rotation_mode == libyuv::RotationMode::kRotate0) {
    if (input_image->width * height > width * input_image->height) {
      cropped_width = input_image->height * width / height;
      cropped_height = input_image->height;
      if (cropped_width % 2 == 1) {
        // Make cropped_width to the closest even number.
        cropped_width++;
      }
      crop_x = (input_image->width - cropped_width) / 2;
    } else {
      cropped_width = input_image->width;
      cropped_height = input_image->width * height / width;
      if (cropped_height % 2 == 1) {
        // Make cropped_height to the closest even number.
        cropped_height++;
      }
      crop_y = (input_image->height - cropped_height) / 2;
    }
  } else {
    if (input_image->width * width > input_image->height * height) {
      cropped_width = input_image->height * height / width;
      cropped_height = input_image->height;
      if (cropped_width % 2 == 1) {
        // Make cropped_width to the closest even number.
        cropped_width++;
      }
      crop_x = (input_image->width - cropped_width) / 2;
    } else {
      cropped_width = input_image->width;
      cropped_height = input_image->width * width / height;
      if (cropped_height % 2 == 1) {
        // Make cropped_height to the closest even number.
        cropped_height++;
      }
      crop_y = (input_image->height - cropped_height) / 2;
    }
  }
  ScopedImage cropped_image(new Image(
      rotation_mode == libyuv::RotationMode::kRotate0 ? cropped_width
                                                      : cropped_height,
      rotation_mode == libyuv::RotationMode::kRotate0 ? cropped_height
                                                      : cropped_width,
      ImageFormat::IMAGE_FORMAT_I420));
  int res = libyuv::ConvertToI420(
      input_image->planes[0].addr, input_image->size,
      cropped_image->planes[0].addr, cropped_image->planes[0].stride,
      cropped_image->planes[1].addr, cropped_image->planes[1].stride,
      cropped_image->planes[2].addr, cropped_image->planes[2].stride, crop_x,
      crop_y, input_image->width, input_image->height, cropped_width,
      cropped_height, rotation_mode,
      input_image->format == ImageFormat::IMAGE_FORMAT_ARGB
          ? libyuv::FourCC::FOURCC_ARGB
          : libyuv::FourCC::FOURCC_I420);
  if (res) {
    ADD_FAILURE() << "ConvertToI420 failed: " << res;
    return nullptr;
  }
  ScopedImage i420_image(
      new Image(width, height, ImageFormat::IMAGE_FORMAT_I420));
  res = libyuv::I420Scale(
      cropped_image->planes[0].addr, cropped_image->planes[0].stride,
      cropped_image->planes[1].addr, cropped_image->planes[1].stride,
      cropped_image->planes[2].addr, cropped_image->planes[2].stride,
      cropped_image->width, cropped_image->height, i420_image->planes[0].addr,
      i420_image->planes[0].stride, i420_image->planes[1].addr,
      i420_image->planes[1].stride, i420_image->planes[2].addr,
      i420_image->planes[2].stride, width, height,
      libyuv::FilterMode::kFilterNone);
  if (res) {
    ADD_FAILURE() << "I420Scale failed: " << res;
    return nullptr;
  }
  return i420_image;
}

double Camera3FrameFixture::ComputeSsim(const Image& buffer_a,
                                        const Image& buffer_b) {
  if (buffer_a.format != ImageFormat::IMAGE_FORMAT_I420 ||
      buffer_b.format != ImageFormat::IMAGE_FORMAT_I420 ||
      buffer_a.width != buffer_b.width || buffer_a.height != buffer_b.height) {
    LOGF(ERROR) << "Images are not of I420 format or resolutions do not match";
    return 0.0;
  }
  return libyuv::I420Ssim(buffer_a.planes[0].addr, buffer_a.planes[0].stride,
                          buffer_a.planes[1].addr, buffer_a.planes[1].stride,
                          buffer_a.planes[2].addr, buffer_a.planes[2].stride,
                          buffer_b.planes[0].addr, buffer_b.planes[0].stride,
                          buffer_b.planes[1].addr, buffer_b.planes[1].stride,
                          buffer_b.planes[2].addr, buffer_b.planes[2].stride,
                          buffer_a.width, buffer_a.height);
}

// Get real-time clock time after waiting for given timeout
void GetTimeOfTimeout(int32_t ms, struct timespec* ts) {
  memset(ts, 0, sizeof(*ts));
  if (clock_gettime(CLOCK_REALTIME, ts)) {
    LOGF(ERROR) << "Failed to get clock time";
  }
  ts->tv_sec += ms / 1000;
  ts->tv_nsec += (ms % 1000) * 1000;
}

// Test parameters:
// - Camera ID
// - Template ID
// - Frame format
// - If true, capture with the maximum resolution supported for this format;
// otherwise, capture the minimum one.
class Camera3SingleFrameTest
    : public Camera3FrameFixture,
      public ::testing::WithParamInterface<
          std::tuple<int32_t, int32_t, int32_t, bool>> {
 public:
  Camera3SingleFrameTest() : Camera3FrameFixture(std::get<0>(GetParam())) {}
};

TEST_P(Camera3SingleFrameTest, GetFrame) {
  int32_t format = std::get<1>(GetParam());
  int32_t type = std::get<2>(GetParam());
  if (!cam_device_.IsTemplateSupported(type)) {
    return;
  }

  if (cam_device_.GetStaticInfo()->IsFormatAvailable(format)) {
    ResolutionInfo resolution(0, 0);
    if (std::get<3>(GetParam())) {
      ASSERT_EQ(0, GetMaxResolution(format, &resolution, true))
          << "Failed to get max resolution for format " << format;
    } else {
      ASSERT_EQ(0, GetMinResolution(format, &resolution, true))
          << "Failed to get min resolution for format " << format;
    }
    VLOGF(1) << "Device " << cam_id_;
    VLOGF(1) << "Format 0x" << std::hex << format;
    VLOGF(1) << "Resolution " << resolution.Width() << "x"
             << resolution.Height();

    cam_device_.AddOutputStream(format, resolution.Width(), resolution.Height(),
                                CAMERA3_STREAM_ROTATION_0);
    ASSERT_EQ(0, cam_device_.ConfigureStreams(nullptr))
        << "Configuring stream fails";

    ASSERT_EQ(0, CreateCaptureRequestByTemplate(type, nullptr))
        << "Creating capture request fails";

    struct timespec timeout;
    GetTimeOfTimeout(kDefaultTimeoutMs, &timeout);
    WaitShutterAndCaptureResult(timeout);
  }
}

// Test parameters:
// - Camera ID
// - Template ID
// - Number of frames to capture
class Camera3MultiFrameTest : public Camera3FrameFixture,
                              public ::testing::WithParamInterface<
                                  std::tuple<int32_t, int32_t, int32_t>> {
 public:
  Camera3MultiFrameTest() : Camera3FrameFixture(std::get<0>(GetParam())) {}
};

TEST_P(Camera3MultiFrameTest, GetFrame) {
  cam_device_.AddOutputStream(default_format_, default_width_, default_height_,
                              CAMERA3_STREAM_ROTATION_0);
  std::vector<const camera3_stream_t*> streams;
  ASSERT_EQ(0, cam_device_.ConfigureStreams(&streams))
      << "Configuring stream fails";
  ASSERT_EQ(1, streams.size());
  int32_t stream_queue_depth = static_cast<int32_t>(streams[0]->max_buffers);

  int32_t type = std::get<1>(GetParam());
  if (!cam_device_.IsTemplateSupported(type)) {
    return;
  }

  int32_t num_frames = std::get<2>(GetParam());
  struct timespec timeout;
  for (int32_t i = 0; i < num_frames; i++) {
    GetTimeOfTimeout(kDefaultTimeoutMs, &timeout);
    if (i >= stream_queue_depth) {
      WaitShutterAndCaptureResult(timeout);
    }
    EXPECT_EQ(0, CreateCaptureRequestByTemplate(type, nullptr))
        << "Creating capture request fails";
  }

  for (int32_t i = 0; i < std::min(num_frames, stream_queue_depth); i++) {
    WaitShutterAndCaptureResult(timeout);
  }
}

// Test parameters:
// - Camera ID
class Camera3MixedTemplateMultiFrameTest
    : public Camera3FrameFixture,
      public ::testing::WithParamInterface<int32_t> {
 public:
  Camera3MixedTemplateMultiFrameTest() : Camera3FrameFixture(GetParam()) {}
};

TEST_P(Camera3MixedTemplateMultiFrameTest, GetFrame) {
  cam_device_.AddOutputStream(default_format_, default_width_, default_height_,
                              CAMERA3_STREAM_ROTATION_0);
  ASSERT_EQ(0, cam_device_.ConfigureStreams(nullptr))
      << "Configuring stream fails";

  int32_t types[] = {CAMERA3_TEMPLATE_PREVIEW, CAMERA3_TEMPLATE_STILL_CAPTURE,
                     CAMERA3_TEMPLATE_VIDEO_RECORD,
                     CAMERA3_TEMPLATE_VIDEO_SNAPSHOT};
  for (const auto& type : types) {
    EXPECT_EQ(0, CreateCaptureRequestByTemplate(type, nullptr))
        << "Creating capture request fails";
  }

  struct timespec timeout;
  for (size_t i = 0; i < std::size(types); ++i) {
    GetTimeOfTimeout(kDefaultTimeoutMs, &timeout);
    WaitShutterAndCaptureResult(timeout);
  }
}

// Test parameters:
// - Camera ID
// - Template ID
// - Number of frames to capture
class Camera3FlushRequestsTest : public Camera3FrameFixture,
                                 public ::testing::WithParamInterface<
                                     std::tuple<int32_t, int32_t, int32_t>> {
 public:
  Camera3FlushRequestsTest()
      : Camera3FrameFixture(std::get<0>(GetParam())), num_capture_results_(0) {}

  void SetUp() override;

 protected:
  // Callback functions from HAL device
  virtual void ProcessCaptureResult(const camera3_capture_result* result);

  // Callback functions from HAL device
  virtual void Notify(const camera3_notify_msg* msg);

  // Number of received capture results with all output buffers returned
  int32_t num_capture_results_;

  sem_t flush_result_sem_;

 private:
  void CheckAllResultReceived(uint32_t frame_number);

  // Number of configured streams
  static const int32_t kNumberOfConfiguredStreams;

  // Store number of output buffers returned in capture results with frame
  // number as the key
  std::unordered_map<uint32_t, int32_t> num_capture_result_buffers_;

  // Store frame numbers of which all partial results are received
  std::unordered_set<uint32_t> metadata_complete_frame_numbers_;

  // Store the frames numbers that had been notified with
  // CAMERA3_MSG_ERROR_REQUEST.
  std::unordered_set<uint32_t> notified_error_frames_;
};

const int32_t Camera3FlushRequestsTest::kNumberOfConfiguredStreams = 1;

void Camera3FlushRequestsTest::SetUp() {
  Camera3FrameFixture::SetUp();
  cam_device_.RegisterProcessCaptureResultCallback(base::BindRepeating(
      &Camera3FlushRequestsTest::ProcessCaptureResult, base::Unretained(this)));
  cam_device_.RegisterNotifyCallback(base::BindRepeating(
      &Camera3FlushRequestsTest::Notify, base::Unretained(this)));
  sem_init(&flush_result_sem_, 0, 0);
}

void Camera3FlushRequestsTest::CheckAllResultReceived(uint32_t frame_number) {
  if (num_capture_result_buffers_[frame_number] == kNumberOfConfiguredStreams &&
      (notified_error_frames_.find(frame_number) !=
           notified_error_frames_.end() ||
       metadata_complete_frame_numbers_.find(frame_number) !=
           metadata_complete_frame_numbers_.end())) {
    num_capture_results_++;
    sem_post(&flush_result_sem_);
  }
}

void Camera3FlushRequestsTest::ProcessCaptureResult(
    const camera3_capture_result* result) {
  ASSERT_NE(nullptr, result) << "Capture result is null";

  EXPECT_EQ(result->result != nullptr, result->partial_result != 0)
      << "Inconsistent partial metadata";

  if (result->result &&
      result->partial_result ==
          cam_device_.GetStaticInfo()->GetPartialResultCount()) {
    metadata_complete_frame_numbers_.insert(result->frame_number);
  }

  num_capture_result_buffers_[result->frame_number] +=
      result->num_output_buffers;

  CheckAllResultReceived(result->frame_number);
}

void Camera3FlushRequestsTest::Notify(const camera3_notify_msg* msg) {
  // TODO(shik): support the partial failure cases

  if (msg->type == CAMERA3_MSG_ERROR) {
    const camera3_error_msg_t& error = msg->message.error;
    if (error.error_code == CAMERA3_MSG_ERROR_REQUEST ||
        error.error_code == CAMERA3_MSG_ERROR_RESULT) {
      notified_error_frames_.insert(error.frame_number);
    }
    CheckAllResultReceived(error.frame_number);
  }
}

TEST_P(Camera3FlushRequestsTest, GetFrame) {
  // TODO(hywu): spawn a thread to test simultaneous process_capture_request
  // and flush

  // The number of configured streams must match the value of
  // |kNumberOfConfiguredStreams|.
  cam_device_.AddOutputStream(default_format_, default_width_, default_height_,
                              CAMERA3_STREAM_ROTATION_0);
  ASSERT_EQ(0, cam_device_.ConfigureStreams(nullptr))
      << "Configuring stream fails";

  int32_t type = std::get<1>(GetParam());
  if (!cam_device_.IsTemplateSupported(type)) {
    return;
  }

  const int32_t num_frames = std::get<2>(GetParam());
  for (int32_t i = 0; i < num_frames; i++) {
    EXPECT_EQ(0, CreateCaptureRequestByTemplate(type, nullptr))
        << "Creating capture request fails";
  }

  ASSERT_EQ(0, cam_device_.Flush()) << "Flushing capture requests fails";

  // flush() should only return when there are no more outstanding buffers or
  // requests left in the HAL
  EXPECT_EQ(num_frames, num_capture_results_)
      << "There are requests left in the HAL after flushing";

  struct timespec timeout;
  for (int32_t i = 0; i < num_frames; i++) {
    GetTimeOfTimeout(kDefaultTimeoutMs, &timeout);
    ASSERT_EQ(0, sem_timedwait(&flush_result_sem_, &timeout));
  }
}

// Test parameters:
// - Camera ID
class Camera3MultiStreamFrameTest
    : public Camera3FrameFixture,
      public ::testing::WithParamInterface<int32_t> {
 public:
  Camera3MultiStreamFrameTest() : Camera3FrameFixture(GetParam()) {}
};

TEST_P(Camera3MultiStreamFrameTest, GetFrame) {
  // Preview stream with large size no bigger than 1080p
  ResolutionInfo limit_resolution(1920, 1080);
  ResolutionInfo preview_resolution(0, 0);
  ASSERT_EQ(0, GetMaxResolution(HAL_PIXEL_FORMAT_YCbCr_420_888,
                                &preview_resolution, true))
      << "Failed to get max resolution for implementation defined format";
  preview_resolution = CapResolution(preview_resolution, limit_resolution);
  cam_device_.AddOutputStream(
      HAL_PIXEL_FORMAT_YCbCr_420_888, preview_resolution.Width(),
      preview_resolution.Height(), CAMERA3_STREAM_ROTATION_0);

  // Second preview stream
  cam_device_.AddOutputStream(
      HAL_PIXEL_FORMAT_YCbCr_420_888, preview_resolution.Width(),
      preview_resolution.Height(), CAMERA3_STREAM_ROTATION_0);

  // Capture stream with largest size
  ResolutionInfo capture_resolution(0, 0);
  ASSERT_EQ(0,
            GetMaxResolution(HAL_PIXEL_FORMAT_BLOB, &capture_resolution, true))
      << "Failed to get max resolution for YCbCr 420 format";
  cam_device_.AddOutputStream(HAL_PIXEL_FORMAT_BLOB, capture_resolution.Width(),
                              capture_resolution.Height(),
                              CAMERA3_STREAM_ROTATION_0);

  ASSERT_EQ(0, cam_device_.ConfigureStreams(nullptr))
      << "Configuring stream fails";

  ASSERT_EQ(0,
            CreateCaptureRequestByTemplate(CAMERA3_TEMPLATE_PREVIEW, nullptr))
      << "Creating capture request fails";

  struct timespec timeout;
  GetTimeOfTimeout(kDefaultTimeoutMs, &timeout);
  WaitShutterAndCaptureResult(timeout);
}

// Test parameters:
// - Camera ID
class Camera3InvalidRequestTest : public Camera3FrameFixture,
                                  public ::testing::WithParamInterface<int> {
 public:
  Camera3InvalidRequestTest() : Camera3FrameFixture(GetParam()) {}
};

TEST_P(Camera3InvalidRequestTest, NullOrUnconfiguredRequest) {
  // Reference:
  // camera2/cts/CameraDeviceTest.java#testInvalidCapture
  EXPECT_NE(0, cam_device_.ProcessCaptureRequest(nullptr))
      << "Capturing with null request should fail";

  const camera_metadata_t* default_settings;
  default_settings =
      cam_device_.ConstructDefaultRequestSettings(CAMERA3_TEMPLATE_PREVIEW);
  std::vector<camera3_stream_buffer_t> output_buffers;
  std::vector<camera3_stream_t> streams(1);
  streams[0].stream_type = CAMERA3_STREAM_OUTPUT;
  streams[0].width = static_cast<uint32_t>(default_width_);
  streams[0].height = static_cast<uint32_t>(default_height_);
  streams[0].format = default_format_;
  std::vector<const camera3_stream_t*> stream_ptrs(1, &streams[0]);
  ASSERT_EQ(0, cam_device_.AllocateOutputBuffersByStreams(stream_ptrs,
                                                          &output_buffers))
      << "Failed to allocate buffers for capture request";
  camera3_capture_request_t capture_request = {
      .frame_number = 0,
      .settings = default_settings,
      .input_buffer = NULL,
      .num_output_buffers = static_cast<uint32_t>(output_buffers.size()),
      .output_buffers = output_buffers.data(),
      .num_physcam_settings = 0};
  EXPECT_NE(0, cam_device_.ProcessCaptureRequest(&capture_request))
      << "Capturing with stream unconfigured should fail";
}

// Test parameters:
// - Camera ID
// - Number of frames to capture
class Camera3SimpleCaptureFrames
    : public Camera3FrameFixture,
      public ::testing::WithParamInterface<std::tuple<int32_t, int32_t>> {
 public:
  Camera3SimpleCaptureFrames()
      : Camera3FrameFixture(std::get<0>(GetParam())),
        num_frames_(std::get<1>(GetParam())) {}

 protected:
  // Process result metadata and/or output buffers
  void ProcessResultMetadataOutputBuffers(
      uint32_t frame_number,
      ScopedCameraMetadata metadata,
      std::vector<cros::ScopedBufferHandle> buffers) override;

  // Validate capture result keys
  void ValidateCaptureResultKeys(const ScopedCameraMetadata& request_metadata);

  // Get waiver keys per camera device hardware level and capability
  void GetWaiverKeys(std::set<int32_t>* waiver_keys) const;

  // Process partial metadata
  void ProcessPartialMetadata(
      std::vector<ScopedCameraMetadata>* partial_metadata) override;

  // Validate partial results
  void ValidatePartialMetadata();

  const int32_t num_frames_;

  // Store result metadata in the first-in-first-out order
  std::list<ScopedCameraMetadata> result_metadata_;

  // Store partial metadata in the first-in-first-out order
  std::list<std::vector<ScopedCameraMetadata>> partial_metadata_list_;

  static const int32_t kCaptureResultKeys[69];
};

void Camera3SimpleCaptureFrames::ProcessResultMetadataOutputBuffers(
    uint32_t frame_number,
    ScopedCameraMetadata metadata,
    std::vector<cros::ScopedBufferHandle> buffers) {
  result_metadata_.push_back(std::move(metadata));
}

void Camera3SimpleCaptureFrames::ValidateCaptureResultKeys(
    const ScopedCameraMetadata& request_metadata) {
  std::set<int32_t> waiver_keys;
  GetWaiverKeys(&waiver_keys);
  while (!result_metadata_.empty()) {
    camera_metadata_t* metadata = result_metadata_.front().get();
    for (auto key : kCaptureResultKeys) {
      if (waiver_keys.find(key) != waiver_keys.end()) {
        continue;
      }
      // Check the critical tags here.
      switch (key) {
        case ANDROID_CONTROL_AE_MODE:
        case ANDROID_CONTROL_AF_MODE:
        case ANDROID_CONTROL_AWB_MODE:
        case ANDROID_CONTROL_MODE:
        case ANDROID_STATISTICS_FACE_DETECT_MODE:
        case ANDROID_NOISE_REDUCTION_MODE:
          camera_metadata_ro_entry_t request_entry;
          if (find_camera_metadata_ro_entry(request_metadata.get(), key,
                                            &request_entry)) {
            ADD_FAILURE() << "Metadata " << get_camera_metadata_tag_name(key)
                          << " is unavailable in capture request";
            continue;
          }
          camera_metadata_ro_entry_t result_entry;
          if (find_camera_metadata_ro_entry(metadata, key, &result_entry)) {
            ADD_FAILURE() << "Metadata " << get_camera_metadata_tag_name(key)
                          << " is not present in capture result";
            continue;
          }
          EXPECT_EQ(request_entry.data.i32[0], result_entry.data.i32[0])
              << "Wrong value of metadata " << get_camera_metadata_tag_name(key)
              << " in capture result";
          break;
        case ANDROID_REQUEST_PIPELINE_DEPTH:
          break;
        default:
          // Only do non-null check for the rest of keys.
          camera_metadata_ro_entry_t entry;
          EXPECT_EQ(0, find_camera_metadata_ro_entry(metadata, key, &entry))
              << "Metadata " << get_camera_metadata_tag_name(key)
              << " is unavailable in capture result";
          break;
      }
    }
    result_metadata_.pop_front();
  }
}

const int32_t Camera3SimpleCaptureFrames::kCaptureResultKeys[] = {
    ANDROID_COLOR_CORRECTION_MODE,
    ANDROID_COLOR_CORRECTION_TRANSFORM,
    ANDROID_COLOR_CORRECTION_GAINS,
    ANDROID_COLOR_CORRECTION_ABERRATION_MODE,
    ANDROID_CONTROL_AE_ANTIBANDING_MODE,
    ANDROID_CONTROL_AE_EXPOSURE_COMPENSATION,
    ANDROID_CONTROL_AE_LOCK,
    ANDROID_CONTROL_AE_MODE,
    ANDROID_CONTROL_AE_REGIONS,
    ANDROID_CONTROL_AF_REGIONS,
    ANDROID_CONTROL_AWB_REGIONS,
    ANDROID_CONTROL_AE_TARGET_FPS_RANGE,
    ANDROID_CONTROL_AE_PRECAPTURE_TRIGGER,
    ANDROID_CONTROL_AF_MODE,
    ANDROID_CONTROL_AF_TRIGGER,
    ANDROID_CONTROL_AWB_LOCK,
    ANDROID_CONTROL_AWB_MODE,
    ANDROID_CONTROL_CAPTURE_INTENT,
    ANDROID_CONTROL_EFFECT_MODE,
    ANDROID_CONTROL_MODE,
    ANDROID_CONTROL_SCENE_MODE,
    ANDROID_CONTROL_VIDEO_STABILIZATION_MODE,
    ANDROID_CONTROL_AE_STATE,
    ANDROID_CONTROL_AF_STATE,
    ANDROID_CONTROL_AWB_STATE,
    ANDROID_EDGE_MODE,
    ANDROID_FLASH_MODE,
    ANDROID_FLASH_STATE,
    ANDROID_HOT_PIXEL_MODE,
    ANDROID_JPEG_ORIENTATION,
    ANDROID_JPEG_QUALITY,
    ANDROID_JPEG_THUMBNAIL_QUALITY,
    ANDROID_JPEG_THUMBNAIL_SIZE,
    ANDROID_LENS_APERTURE,
    ANDROID_LENS_FILTER_DENSITY,
    ANDROID_LENS_FOCAL_LENGTH,
    ANDROID_LENS_FOCUS_DISTANCE,
    ANDROID_LENS_OPTICAL_STABILIZATION_MODE,
    ANDROID_LENS_POSE_ROTATION,
    ANDROID_LENS_POSE_TRANSLATION,
    ANDROID_LENS_FOCUS_RANGE,
    ANDROID_LENS_STATE,
    ANDROID_LENS_INTRINSIC_CALIBRATION,
    ANDROID_LENS_RADIAL_DISTORTION,
    ANDROID_NOISE_REDUCTION_MODE,
    ANDROID_REQUEST_PIPELINE_DEPTH,
    ANDROID_SCALER_CROP_REGION,
    ANDROID_SENSOR_EXPOSURE_TIME,
    ANDROID_SENSOR_FRAME_DURATION,
    ANDROID_SENSOR_SENSITIVITY,
    ANDROID_SENSOR_TIMESTAMP,
    ANDROID_SENSOR_NEUTRAL_COLOR_POINT,
    ANDROID_SENSOR_NOISE_PROFILE,
    ANDROID_SENSOR_GREEN_SPLIT,
    ANDROID_SENSOR_TEST_PATTERN_DATA,
    ANDROID_SENSOR_TEST_PATTERN_MODE,
    ANDROID_SENSOR_ROLLING_SHUTTER_SKEW,
    ANDROID_SHADING_MODE,
    ANDROID_STATISTICS_FACE_DETECT_MODE,
    ANDROID_STATISTICS_HOT_PIXEL_MAP_MODE,
    ANDROID_STATISTICS_LENS_SHADING_CORRECTION_MAP,
    ANDROID_STATISTICS_SCENE_FLICKER,
    ANDROID_STATISTICS_HOT_PIXEL_MAP,
    ANDROID_STATISTICS_LENS_SHADING_MAP_MODE,
    ANDROID_TONEMAP_MODE,
    ANDROID_TONEMAP_GAMMA,
    ANDROID_TONEMAP_PRESET_CURVE,
    ANDROID_BLACK_LEVEL_LOCK,
    ANDROID_REPROCESS_EFFECTIVE_EXPOSURE_FACTOR};

void Camera3SimpleCaptureFrames::GetWaiverKeys(
    std::set<int32_t>* waiver_keys) const {
  // Global waiver keys
  waiver_keys->insert(ANDROID_JPEG_ORIENTATION);
  waiver_keys->insert(ANDROID_JPEG_QUALITY);
  waiver_keys->insert(ANDROID_JPEG_THUMBNAIL_QUALITY);
  waiver_keys->insert(ANDROID_JPEG_THUMBNAIL_SIZE);

  // Keys only present when corresponding control is on are being verified in
  // its own functional test
  // Only present in certain tonemap mode
  waiver_keys->insert(ANDROID_TONEMAP_CURVE_BLUE);
  waiver_keys->insert(ANDROID_TONEMAP_CURVE_GREEN);
  waiver_keys->insert(ANDROID_TONEMAP_CURVE_RED);
  waiver_keys->insert(ANDROID_TONEMAP_GAMMA);
  waiver_keys->insert(ANDROID_TONEMAP_PRESET_CURVE);
  // Only present when test pattern mode is SOLID_COLOR.
  waiver_keys->insert(ANDROID_SENSOR_TEST_PATTERN_DATA);
  // Only present when STATISTICS_LENS_SHADING_MAP_MODE is ON
  waiver_keys->insert(ANDROID_STATISTICS_LENS_SHADING_CORRECTION_MAP);
  // Only present when STATISTICS_INFO_AVAILABLE_HOT_PIXEL_MAP_MODES is ON
  waiver_keys->insert(ANDROID_STATISTICS_HOT_PIXEL_MAP);
  // Only present when face detection is on
  waiver_keys->insert(ANDROID_STATISTICS_FACE_IDS);
  waiver_keys->insert(ANDROID_STATISTICS_FACE_LANDMARKS);
  waiver_keys->insert(ANDROID_STATISTICS_FACE_RECTANGLES);
  waiver_keys->insert(ANDROID_STATISTICS_FACE_SCORES);
  // Only present in reprocessing capture result.
  waiver_keys->insert(ANDROID_REPROCESS_EFFECTIVE_EXPOSURE_FACTOR);

  // Keys not required if RAW is not supported
  if (!cam_device_.GetStaticInfo()->IsCapabilitySupported(
          ANDROID_REQUEST_AVAILABLE_CAPABILITIES_RAW)) {
    waiver_keys->insert(ANDROID_SENSOR_NEUTRAL_COLOR_POINT);
    waiver_keys->insert(ANDROID_SENSOR_GREEN_SPLIT);
    waiver_keys->insert(ANDROID_SENSOR_NOISE_PROFILE);
  }

  // Keys for depth output capability
  if (!cam_device_.GetStaticInfo()->IsCapabilitySupported(
          ANDROID_REQUEST_AVAILABLE_CAPABILITIES_DEPTH_OUTPUT)) {
    waiver_keys->insert(ANDROID_LENS_POSE_ROTATION);
    waiver_keys->insert(ANDROID_LENS_POSE_TRANSLATION);
    waiver_keys->insert(ANDROID_LENS_INTRINSIC_CALIBRATION);
    waiver_keys->insert(ANDROID_LENS_RADIAL_DISTORTION);
  }

  if (cam_device_.GetStaticInfo()->GetAeMaxRegions() == 0) {
    waiver_keys->insert(ANDROID_CONTROL_AE_REGIONS);
  }
  if (cam_device_.GetStaticInfo()->GetAwbMaxRegions() == 0) {
    waiver_keys->insert(ANDROID_CONTROL_AWB_REGIONS);
  }
  if (cam_device_.GetStaticInfo()->GetAfMaxRegions() == 0) {
    waiver_keys->insert(ANDROID_CONTROL_AF_REGIONS);
  }

  if (cam_device_.GetStaticInfo()->IsHardwareLevelAtLeastFull()) {
    return;
  }

  // Keys to waive for limited devices
  if (!cam_device_.GetStaticInfo()->IsKeyAvailable(
          ANDROID_COLOR_CORRECTION_MODE)) {
    waiver_keys->insert(ANDROID_COLOR_CORRECTION_GAINS);
    waiver_keys->insert(ANDROID_COLOR_CORRECTION_MODE);
    waiver_keys->insert(ANDROID_COLOR_CORRECTION_TRANSFORM);
  }

  if (!cam_device_.GetStaticInfo()->IsKeyAvailable(
          ANDROID_COLOR_CORRECTION_ABERRATION_MODE)) {
    waiver_keys->insert(ANDROID_COLOR_CORRECTION_ABERRATION_MODE);
  }

  if (!cam_device_.GetStaticInfo()->IsKeyAvailable(ANDROID_TONEMAP_MODE)) {
    waiver_keys->insert(ANDROID_TONEMAP_MODE);
  }

  if (!cam_device_.GetStaticInfo()->IsKeyAvailable(ANDROID_EDGE_MODE)) {
    waiver_keys->insert(ANDROID_EDGE_MODE);
  }

  if (!cam_device_.GetStaticInfo()->IsKeyAvailable(ANDROID_HOT_PIXEL_MODE)) {
    waiver_keys->insert(ANDROID_HOT_PIXEL_MODE);
  }

  if (!cam_device_.GetStaticInfo()->IsKeyAvailable(
          ANDROID_NOISE_REDUCTION_MODE)) {
    waiver_keys->insert(ANDROID_NOISE_REDUCTION_MODE);
  }

  if (!cam_device_.GetStaticInfo()->IsKeyAvailable(ANDROID_SHADING_MODE)) {
    waiver_keys->insert(ANDROID_SHADING_MODE);
  }

  // Keys not required if neither MANUAL_SENSOR nor READ_SENSOR_SETTINGS is
  // supported
  if (!cam_device_.GetStaticInfo()->IsCapabilitySupported(
          ANDROID_REQUEST_AVAILABLE_CAPABILITIES_MANUAL_SENSOR)) {
    waiver_keys->insert(ANDROID_SENSOR_EXPOSURE_TIME);
    waiver_keys->insert(ANDROID_SENSOR_FRAME_DURATION);
    waiver_keys->insert(ANDROID_SENSOR_SENSITIVITY);
    waiver_keys->insert(ANDROID_BLACK_LEVEL_LOCK);
    waiver_keys->insert(ANDROID_LENS_FOCUS_RANGE);
    waiver_keys->insert(ANDROID_LENS_FOCUS_DISTANCE);
    waiver_keys->insert(ANDROID_LENS_STATE);
    waiver_keys->insert(ANDROID_LENS_APERTURE);
    waiver_keys->insert(ANDROID_LENS_FILTER_DENSITY);
  }
}

void Camera3SimpleCaptureFrames::ProcessPartialMetadata(
    std::vector<ScopedCameraMetadata>* partial_metadata) {
  partial_metadata_list_.resize(partial_metadata_list_.size() + 1);
  for (auto& it : *partial_metadata) {
    partial_metadata_list_.back().push_back(std::move(it));
  }
}

void Camera3SimpleCaptureFrames::ValidatePartialMetadata() {
  for (const auto& it : partial_metadata_list_) {
    // Number of partial results is less than or equal to
    // REQUEST_PARTIAL_RESULT_COUNT
    EXPECT_GE(cam_device_.GetStaticInfo()->GetPartialResultCount(), it.size())
        << "Number of received partial results is wrong";

    // Each key appeared in partial results must be unique across all partial
    // results
    for (size_t i = 0; i < it.size(); i++) {
      size_t entry_count = get_camera_metadata_entry_count(it[i].get());
      for (size_t entry_index = 0; entry_index < entry_count; entry_index++) {
        camera_metadata_ro_entry_t entry;
        ASSERT_EQ(
            0, get_camera_metadata_ro_entry(it[i].get(), entry_index, &entry));
        int32_t key = entry.tag;
        for (size_t j = i + 1; j < it.size(); j++) {
          EXPECT_NE(0, find_camera_metadata_ro_entry(it[j].get(), key, &entry))
              << "Key " << get_camera_metadata_tag_name(key)
              << " appears in multiple partial results";
        }
      }
    }
  }
}

TEST_P(Camera3SimpleCaptureFrames, Camera3ResultAllKeysTest) {
  // Reference:
  // camera2/cts/CaptureResultTest.java#testCameraCaptureResultAllKeys
  cam_device_.AddOutputStream(default_format_, default_width_, default_height_,
                              CAMERA3_STREAM_ROTATION_0);
  ASSERT_EQ(0, cam_device_.ConfigureStreams(nullptr))
      << "Configuring stream fails";
  ScopedCameraMetadata metadata(clone_camera_metadata(
      cam_device_.ConstructDefaultRequestSettings(CAMERA3_TEMPLATE_PREVIEW)));

  for (int32_t i = 0; i < num_frames_; i++) {
    ASSERT_EQ(0, CreateCaptureRequestByMetadata(metadata, nullptr))
        << "Creating capture request fails";
  }

  struct timespec timeout;
  for (int32_t i = 0; i < num_frames_; i++) {
    GetTimeOfTimeout(kDefaultTimeoutMs, &timeout);
    WaitShutterAndCaptureResult(timeout);
  }

  ValidateCaptureResultKeys(metadata);
}

TEST_P(Camera3SimpleCaptureFrames, Camera3PartialResultTest) {
  // Reference:
  // camera2/cts/CaptureResultTest.java#testPartialResult
  // Skip the test if partial result is not supported
  if (cam_device_.GetStaticInfo()->GetPartialResultCount() == 1) {
    return;
  }

  cam_device_.AddOutputStream(default_format_, default_width_, default_height_,
                              CAMERA3_STREAM_ROTATION_0);
  ASSERT_EQ(0, cam_device_.ConfigureStreams(nullptr))
      << "Configuring stream fails";

  for (int32_t i = 0; i < num_frames_; i++) {
    ASSERT_EQ(0,
              CreateCaptureRequestByTemplate(CAMERA3_TEMPLATE_PREVIEW, nullptr))
        << "Creating capture request fails";
  }

  struct timespec timeout;
  for (int32_t i = 0; i < num_frames_; i++) {
    GetTimeOfTimeout(kDefaultTimeoutMs, &timeout);
    WaitShutterAndCaptureResult(timeout);
  }

  ValidatePartialMetadata();
}

// Test parameters:
// - Camera ID
class Camera3ResultTimestampsTest
    : public Camera3FrameFixture,
      public ::testing::WithParamInterface<int32_t> {
 public:
  Camera3ResultTimestampsTest() : Camera3FrameFixture(GetParam()) {}

  void SetUp() override;

 protected:
  virtual void Notify(const camera3_notify_msg* msg);

  // Process result metadata and/or output buffers
  void ProcessResultMetadataOutputBuffers(
      uint32_t frame_number,
      ScopedCameraMetadata metadata,
      std::vector<cros::ScopedBufferHandle> buffers) override;

  // Validate and get one timestamp
  void ValidateAndGetTimestamp(int64_t* timestamp);

 private:
  // Store timestamps of shutter callback in the first-in-first-out order
  std::list<uint64_t> capture_timestamps_;

  // Store result metadata in the first-in-first-out order
  std::list<ScopedCameraMetadata> result_metadata_;
};

void Camera3ResultTimestampsTest::SetUp() {
  Camera3FrameFixture::SetUp();
  cam_device_.RegisterNotifyCallback(base::BindRepeating(
      &Camera3ResultTimestampsTest::Notify, base::Unretained(this)));
}

void Camera3ResultTimestampsTest::Notify(const camera3_notify_msg* msg) {
  EXPECT_EQ(CAMERA3_MSG_SHUTTER, msg->type)
      << "Shutter error = " << msg->message.error.error_code;

  if (msg->type == CAMERA3_MSG_SHUTTER) {
    capture_timestamps_.push_back(msg->message.shutter.timestamp);
  }
}

void Camera3ResultTimestampsTest::ProcessResultMetadataOutputBuffers(
    uint32_t frame_number,
    ScopedCameraMetadata metadata,
    std::vector<cros::ScopedBufferHandle> buffers) {
  result_metadata_.push_back(std::move(metadata));
}

void Camera3ResultTimestampsTest::ValidateAndGetTimestamp(int64_t* timestamp) {
  ASSERT_FALSE(capture_timestamps_.empty())
      << "Capture timestamp is unavailable";
  ASSERT_FALSE(result_metadata_.empty()) << "Result metadata is unavailable";
  camera_metadata_ro_entry_t entry;
  ASSERT_EQ(0, find_camera_metadata_ro_entry(result_metadata_.front().get(),
                                             ANDROID_SENSOR_TIMESTAMP, &entry))
      << "Metadata key ANDROID_SENSOR_TIMESTAMP not found";
  *timestamp = entry.data.i64[0];
  EXPECT_EQ(capture_timestamps_.front(), *timestamp)
      << "Shutter notification timestamp must be same as capture result"
         " timestamp";
  capture_timestamps_.pop_front();
  result_metadata_.pop_front();
}

TEST_P(Camera3ResultTimestampsTest, GetFrame) {
  // Reference:
  // camera2/cts/CaptureResultTest.java#testResultTimestamps
  cam_device_.AddOutputStream(default_format_, default_width_, default_height_,
                              CAMERA3_STREAM_ROTATION_0);
  ASSERT_EQ(0, cam_device_.ConfigureStreams(nullptr))
      << "Configuring stream fails";

  ASSERT_EQ(0,
            CreateCaptureRequestByTemplate(CAMERA3_TEMPLATE_PREVIEW, nullptr))
      << "Creating capture request fails";
  struct timespec timeout;
  GetTimeOfTimeout(kDefaultTimeoutMs, &timeout);
  ASSERT_EQ(0, cam_device_.WaitCaptureResult(timeout));
  int64_t timestamp1 = 0;
  ValidateAndGetTimestamp(&timestamp1);

  ASSERT_EQ(0,
            CreateCaptureRequestByTemplate(CAMERA3_TEMPLATE_PREVIEW, nullptr))
      << "Creating capture request fails";
  GetTimeOfTimeout(kDefaultTimeoutMs, &timeout);
  ASSERT_EQ(0, cam_device_.WaitCaptureResult(timeout));
  int64_t timestamp2 = 0;
  ValidateAndGetTimestamp(&timestamp2);

  ASSERT_LT(timestamp1, timestamp2) << "Timestamps must be increasing";
}

// Test parameters:
// - Camera ID
class Camera3InvalidBufferTest : public Camera3FrameFixture,
                                 public ::testing::WithParamInterface<int32_t> {
 public:
  Camera3InvalidBufferTest() : Camera3FrameFixture(GetParam()) {}

  void SetUp() override;

 protected:
  // Callback functions from HAL device
  virtual void ProcessCaptureResult(const camera3_capture_result* result);

  void RunInvalidBufferTest(buffer_handle_t* handle);

  // Callback functions from HAL device
  // Do nothing.
  virtual void Notify(const camera3_notify_msg* msg) {}

  sem_t capture_result_sem_;

 private:
  // Number of configured streams
  static const int32_t kNumberOfConfiguredStreams;
};

const int32_t Camera3InvalidBufferTest::kNumberOfConfiguredStreams = 1;

void Camera3InvalidBufferTest::SetUp() {
  Camera3FrameFixture::SetUp();
  cam_device_.RegisterProcessCaptureResultCallback(base::BindRepeating(
      &Camera3InvalidBufferTest::ProcessCaptureResult, base::Unretained(this)));
  cam_device_.RegisterNotifyCallback(base::BindRepeating(
      &Camera3InvalidBufferTest::Notify, base::Unretained(this)));
  sem_init(&capture_result_sem_, 0, 0);
}

void Camera3InvalidBufferTest::ProcessCaptureResult(
    const camera3_capture_result* result) {
  ASSERT_NE(nullptr, result) << "Capture result is null";
  for (uint32_t i = 0; i < result->num_output_buffers; i++) {
    EXPECT_EQ(CAMERA3_BUFFER_STATUS_ERROR, result->output_buffers[i].status)
        << "Capture result should return error on invalid buffer";
  }
  if (result->num_output_buffers > 0) {
    sem_post(&capture_result_sem_);
  }
}

void Camera3InvalidBufferTest::RunInvalidBufferTest(buffer_handle_t* handle) {
  cam_device_.AddOutputStream(default_format_, default_width_, default_height_,
                              CAMERA3_STREAM_ROTATION_0);
  std::vector<const camera3_stream_t*> streams;
  ASSERT_EQ(0, cam_device_.ConfigureStreams(&streams))
      << "Configuring stream fails";
  const camera_metadata_t* default_settings;
  default_settings =
      cam_device_.ConstructDefaultRequestSettings(CAMERA3_TEMPLATE_PREVIEW);
  ASSERT_NE(nullptr, default_settings) << "Camera default settings are NULL";
  camera3_stream_buffer_t stream_buffer = {
      .stream = const_cast<camera3_stream_t*>(streams.front()),
      .buffer = handle,
      .status = CAMERA3_BUFFER_STATUS_OK,
      .acquire_fence = -1,
      .release_fence = -1};
  std::vector<camera3_stream_buffer_t> stream_buffers(1, stream_buffer);
  camera3_capture_request_t capture_request = {
      .frame_number = UINT32_MAX,
      .settings = default_settings,
      .input_buffer = NULL,
      .num_output_buffers = static_cast<uint32_t>(stream_buffers.size()),
      .output_buffers = stream_buffers.data(),
      .num_physcam_settings = 0};
  int ret = cam_device_.ProcessCaptureRequest(&capture_request);
  if (ret == -EINVAL) {
    return;
  }
  ASSERT_EQ(0, ret);
  struct timespec timeout;
  GetTimeOfTimeout(kDefaultTimeoutMs, &timeout);
  ASSERT_EQ(0, sem_timedwait(&capture_result_sem_, &timeout));
}

TEST_P(Camera3InvalidBufferTest, NullBufferHandle) {
  buffer_handle_t handle = nullptr;
  RunInvalidBufferTest(&handle);
}

// Test parameters:
// - Camera ID, frame format, resolution width, resolution height
class Camera3FrameContentTest
    : public Camera3FrameFixture,
      public ::testing::WithParamInterface<
          std::tuple<int32_t, int32_t, int32_t, int32_t>> {
 public:
  const double kContentTestSsimThreshold = 0.75;

  Camera3FrameContentTest()
      : Camera3FrameFixture(std::get<0>(GetParam())),
        format_(std::get<1>(GetParam())),
        width_(std::get<2>(GetParam())),
        height_(std::get<3>(GetParam())) {}

  ~Camera3FrameContentTest() override {
    if (GetCrosCameraHal() != nullptr &&
        GetCrosCameraHal()->set_privacy_switch_state != nullptr) {
      GetCrosCameraHal()->set_privacy_switch_state(false);
    }
  }

 protected:
  void ProcessResultMetadataOutputBuffers(
      uint32_t frame_number,
      ScopedCameraMetadata metadata,
      std::vector<cros::ScopedBufferHandle> buffers) override;

  int32_t format_;

  int32_t width_;

  int32_t height_;

  cros::ScopedBufferHandle buffer_handle_;
};

void Camera3FrameContentTest::ProcessResultMetadataOutputBuffers(
    uint32_t frame_number,
    ScopedCameraMetadata metadata,
    std::vector<cros::ScopedBufferHandle> buffers) {
  ASSERT_EQ(nullptr, buffer_handle_);
  buffer_handle_ = std::move(buffers.front());
}

TEST_P(Camera3FrameContentTest, CorruptionDetection) {
  auto test_pattern_modes = GetAvailableColorBarsTestPatternModes();
  ASSERT_FALSE(test_pattern_modes.empty())
      << "Failed to get sensor available test pattern modes";

  cam_device_.AddOutputStream(format_, width_, height_,
                              CAMERA3_STREAM_ROTATION_0);
  ASSERT_EQ(0, cam_device_.ConfigureStreams(nullptr))
      << "Configuring stream fails";
  ScopedCameraMetadata metadata(clone_camera_metadata(
      cam_device_.ConstructDefaultRequestSettings(CAMERA3_TEMPLATE_PREVIEW)));
  UpdateMetadata(ANDROID_SENSOR_TEST_PATTERN_MODE, test_pattern_modes.data(), 1,
                 &metadata);
  ASSERT_EQ(0, CreateCaptureRequestByMetadata(metadata, nullptr))
      << "Creating capture request fails";

  struct timespec timeout;
  GetTimeOfTimeout(kDefaultTimeoutMs, &timeout);
  WaitShutterAndCaptureResult(timeout);
  ASSERT_NE(nullptr, buffer_handle_) << "Failed to get frame buffer";
  auto capture_image = ConvertToImage(std::move(buffer_handle_), width_,
                                      height_, ImageFormat::IMAGE_FORMAT_I420);
  ASSERT_NE(nullptr, capture_image);

  uint32_t sensor_pixel_array_width;
  uint32_t sensor_pixel_array_height;
  ASSERT_EQ(0, cam_device_.GetStaticInfo()->GetSensorPixelArraySize(
                   &sensor_pixel_array_width, &sensor_pixel_array_height));

  for (const auto& it : color_bars_test_patterns_) {
    auto pattern_image = GenerateColorBarsPattern(
        width_, height_, it, test_pattern_modes.front(),
        sensor_pixel_array_width, sensor_pixel_array_height);
    ASSERT_NE(nullptr, pattern_image);

    if (ComputeSsim(*capture_image, *pattern_image) >
        kContentTestSsimThreshold) {
      return;
    }
  }
  std::stringstream ss;
  ss << "/tmp/corruption_test_0x" << std::hex << format_ << "_" << std::dec
     << width_ << "x" << height_;
  capture_image->SaveToFile(ss.str());
  ADD_FAILURE() << "The frame content is corrupted";
}

TEST_P(Camera3FrameContentTest, DetectGreenLine) {
  auto test_pattern_modes = GetAvailableColorBarsTestPatternModes();
  ASSERT_FALSE(test_pattern_modes.empty())
      << "Failed to get sensor available test pattern modes";

  cam_device_.AddOutputStream(format_, width_, height_,
                              CAMERA3_STREAM_ROTATION_0);
  ASSERT_EQ(0, cam_device_.ConfigureStreams(nullptr))
      << "Configuring stream fails";
  ScopedCameraMetadata metadata(clone_camera_metadata(
      cam_device_.ConstructDefaultRequestSettings(CAMERA3_TEMPLATE_PREVIEW)));
  UpdateMetadata(ANDROID_SENSOR_TEST_PATTERN_MODE, test_pattern_modes.data(), 1,
                 &metadata);
  ASSERT_EQ(0, CreateCaptureRequestByMetadata(metadata, nullptr))
      << "Creating capture request fails";

  struct timespec timeout;
  GetTimeOfTimeout(kDefaultTimeoutMs, &timeout);
  WaitShutterAndCaptureResult(timeout);
  ASSERT_NE(nullptr, buffer_handle_) << "Failed to get frame buffer";
  auto i420_image = ConvertToImage(std::move(buffer_handle_), width_, height_,
                                   ImageFormat::IMAGE_FORMAT_I420);
  ASSERT_NE(nullptr, i420_image);
  ASSERT_EQ(3, i420_image->planes.size());

  auto IsBottomLineGreen = [](const ScopedImage& i420_image) {
    uint32_t plane_width = i420_image->width / 2;
    uint32_t plane_height = i420_image->height / 2;
    for (int plane = 1; plane < i420_image->planes.size(); plane++) {
      int offset = plane_width * (plane_height - 1);
      for (size_t w = 0; w < plane_width; w++) {
        if (i420_image->planes[plane].addr[offset + w] != 0) {
          return false;
        }
      }
    }
    return true;
  };
  EXPECT_FALSE(IsBottomLineGreen(i420_image))
      << "Green line at the bottom of captured frame";
  auto IsRightMostLineGreen = [](const ScopedImage& i420_image) {
    uint32_t plane_width = i420_image->width / 2;
    uint32_t plane_height = i420_image->height / 2;
    for (int plane = 1; plane < i420_image->planes.size(); plane++) {
      for (size_t h = 1; h <= plane_height; h++) {
        int offset = plane_width * h - 1;
        if (i420_image->planes[plane].addr[offset] != 0) {
          return false;
        }
      }
    }
    return true;
  };
  EXPECT_FALSE(IsRightMostLineGreen(i420_image))
      << "Green line at the rightmost of captured frame";
}

TEST_P(Camera3FrameContentTest, SWPrivacySwitch) {
  if (GetCrosCameraHal() == nullptr) {
    GTEST_SKIP() << "--camera_hal_path is not specified";
  }
  if (GetCrosCameraHal()->set_privacy_switch_state == nullptr) {
    GTEST_SKIP()
        << "cros_camera_hal::set_privacy_switch_state is not implemented";
  }

  GetCrosCameraHal()->set_privacy_switch_state(true);

  cam_device_.AddOutputStream(format_, width_, height_,
                              CAMERA3_STREAM_ROTATION_0);
  ASSERT_EQ(0, cam_device_.ConfigureStreams(nullptr))
      << "Configuring stream fails";
  ScopedCameraMetadata metadata(clone_camera_metadata(
      cam_device_.ConstructDefaultRequestSettings(CAMERA3_TEMPLATE_PREVIEW)));
  ASSERT_EQ(0, CreateCaptureRequestByMetadata(metadata, nullptr))
      << "Creating capture request fails";

  struct timespec timeout;
  GetTimeOfTimeout(kDefaultTimeoutMs, &timeout);
  WaitShutterAndCaptureResult(timeout);
  ASSERT_NE(nullptr, buffer_handle_) << "Failed to get frame buffer";
  auto i420_image = ConvertToImage(std::move(buffer_handle_), width_, height_,
                                   ImageFormat::IMAGE_FORMAT_I420);
  ASSERT_NE(nullptr, i420_image);
  ASSERT_EQ(3, i420_image->planes.size());

  auto IsBlack = [](const ScopedImage& i420_image) {
    // Allow some margin of error when checking Y values.
    uint8_t delta_y = 2;
    for (size_t h = 0; h < i420_image->height; ++h) {
      for (size_t w = 0; w < i420_image->width; ++w) {
        uint8_t y = i420_image->planes[0].addr[h * i420_image->width + w];
        if (!((0 <= y && y <= delta_y) ||
              (16 - delta_y <= y && y <= 16 + delta_y))) {
          LOGF(ERROR) << "Non black pixel detected: Y="
                      << static_cast<int32_t>(y);
          return false;
        }
      }
    }
    // Allow some margin of error when checking U/V values.
    uint8_t delta_uv = 16;
    for (size_t h = 0; h < i420_image->height / 2; ++h) {
      for (size_t w = 0; w < i420_image->width / 2; ++w) {
        uint8_t u = i420_image->planes[1].addr[h * i420_image->width / 2 + w];
        uint8_t v = i420_image->planes[2].addr[h * i420_image->width / 2 + w];
        if (!(128 - delta_uv <= u && u <= 128 + delta_uv &&
              128 - delta_uv <= v && v <= 128 + delta_uv)) {
          LOGF(ERROR) << "Non black pixel detected: U="
                      << static_cast<int32_t>(u)
                      << ", V=" << static_cast<int32_t>(v);
          return false;
        }
      }
    }
    return true;
  };
  EXPECT_TRUE(IsBlack(i420_image))
      << "Non black frame when the SW privacy switch is ON";
}

// Test parameters:
// - Camera ID, frame format, resolution width, resolution height
// - Rotation degrees
class Camera3PortraitRotationTest
    : public Camera3FrameFixture,
      public ::testing::WithParamInterface<
          std::tuple<std::tuple<int32_t, int32_t, int32_t, int32_t>,
                     int32_t,
                     bool>> {
 public:
  const double kPortraitTestSsimThreshold = 0.75;

  Camera3PortraitRotationTest()
      : Camera3FrameFixture(std::get<0>(std::get<0>(GetParam()))),
        format_(std::get<1>(std::get<0>(GetParam()))),
        width_(std::get<2>(std::get<0>(GetParam()))),
        height_(std::get<3>(std::get<0>(GetParam()))),
        rotation_degrees_(std::get<1>(GetParam())),
        use_rotate_and_crop_api_(std::get<2>(GetParam())),
        save_images_(base::CommandLine::ForCurrentProcess()->HasSwitch(
            "save_portrait_test_images")) {}

 protected:
  void ProcessResultMetadataOutputBuffers(
      uint32_t frame_number,
      ScopedCameraMetadata metadata,
      std::vector<cros::ScopedBufferHandle> buffers) override;

  // Rotate |in_buffer| 180 degrees to |out_buffer|.
  int Rotate180(const Image& in_buffer, Image* out_buffer);

  int32_t format_;

  int32_t width_;

  int32_t height_;

  int32_t rotation_degrees_;

  bool use_rotate_and_crop_api_;

  bool save_images_;

  cros::ScopedBufferHandle buffer_handle_;
};

void Camera3PortraitRotationTest::ProcessResultMetadataOutputBuffers(
    uint32_t frame_number,
    ScopedCameraMetadata metadata,
    std::vector<cros::ScopedBufferHandle> buffers) {
  ASSERT_EQ(nullptr, buffer_handle_);
  buffer_handle_ = std::move(buffers.front());
}

int Camera3PortraitRotationTest::Rotate180(const Image& in_buffer,
                                           Image* out_buffer) {
  if (in_buffer.format != ImageFormat::IMAGE_FORMAT_I420 ||
      out_buffer->format != ImageFormat::IMAGE_FORMAT_I420 ||
      in_buffer.width != out_buffer->width ||
      in_buffer.height != out_buffer->height) {
    return -EINVAL;
  }
  return libyuv::I420Rotate(
      in_buffer.planes[0].addr, in_buffer.planes[0].stride,
      in_buffer.planes[1].addr, in_buffer.planes[1].stride,
      in_buffer.planes[2].addr, in_buffer.planes[2].stride,
      out_buffer->planes[0].addr, out_buffer->planes[0].stride,
      out_buffer->planes[1].addr, out_buffer->planes[1].stride,
      out_buffer->planes[2].addr, out_buffer->planes[2].stride, in_buffer.width,
      in_buffer.height, libyuv::RotationMode::kRotate180);
}

TEST_P(Camera3PortraitRotationTest, GetFrame) {
  auto test_pattern_modes = GetAvailableColorBarsTestPatternModes();
  ASSERT_FALSE(test_pattern_modes.empty())
      << "Failed to get sensor available test pattern modes";

  uint8_t rotate_and_crop_mode = ANDROID_SCALER_ROTATE_AND_CROP_NONE;
  if (use_rotate_and_crop_api_) {
    switch (rotation_degrees_) {
      case 90:
        rotate_and_crop_mode = ANDROID_SCALER_ROTATE_AND_CROP_90;
        break;
      case 270:
        rotate_and_crop_mode = ANDROID_SCALER_ROTATE_AND_CROP_270;
        break;
      default:
        FAIL() << "Invalid rotation degree: " << rotation_degrees_;
    }
    auto modes = cam_device_.GetStaticInfo()->GetAvailableRotateAndCropModes();
    if (modes.size() <= 1) {
      EXPECT_EQ(modes.count(ANDROID_SCALER_ROTATE_AND_CROP_NONE), modes.size());
      GTEST_SKIP() << "ANDROID_SCALER_ROTATE_AND_CROP is not supported";
    }
    EXPECT_EQ(modes.count(ANDROID_SCALER_ROTATE_AND_CROP_NONE), 1);
    EXPECT_EQ(modes.count(ANDROID_SCALER_ROTATE_AND_CROP_AUTO), 1);
    // Android only requires 90 to be supported. We additionally check every
    // tested rotation degrees here.
    EXPECT_EQ(modes.count(rotate_and_crop_mode), 1);
  }

  if (cam_device_.GetStaticInfo()->IsFormatAvailable(format_)) {
    VLOGF(1) << "Device " << cam_id_;
    VLOGF(1) << "Format 0x" << std::hex << format_;
    VLOGF(1) << "Resolution " << width_ << "x" << height_;
    VLOGF(1) << "Rotation " << rotation_degrees_;
    VLOGF(1) << "Use ANDROID_SCALER_ROTATE_AND_CROP: "
             << use_rotate_and_crop_api_;

    cam_device_.AddOutputStream(format_, width_, height_,
                                CAMERA3_STREAM_ROTATION_0);
    ASSERT_EQ(0, cam_device_.ConfigureStreams(nullptr))
        << "Configuring stream fails";

    // Get original pattern
    ScopedCameraMetadata metadata(clone_camera_metadata(
        cam_device_.ConstructDefaultRequestSettings(CAMERA3_TEMPLATE_PREVIEW)));
    UpdateMetadata(ANDROID_SENSOR_TEST_PATTERN_MODE, test_pattern_modes.data(),
                   1, &metadata);
    ASSERT_EQ(0, CreateCaptureRequestByMetadata(metadata, nullptr))
        << "Creating capture request fails";

    struct timespec timeout;
    GetTimeOfTimeout(kDefaultTimeoutMs, &timeout);
    WaitShutterAndCaptureResult(timeout);
    ASSERT_NE(nullptr, buffer_handle_) << "Failed to get original frame buffer";
    auto orig_i420_image =
        ConvertToImage(std::move(buffer_handle_), width_, height_,
                       ImageFormat::IMAGE_FORMAT_I420);
    ASSERT_NE(nullptr, orig_i420_image);
    auto SaveImage = [this](const Image& image, const std::string suffix) {
      std::stringstream ss;
      ss << "/tmp/portrait_test_0x" << std::hex << format_ << "_" << std::dec
         << width_ << "x" << height_ << "_" << rotation_degrees_ << suffix;
      EXPECT_EQ(0, image.SaveToFile(ss.str()));
    };
    if (save_images_) {
      SaveImage(*orig_i420_image, "_orig");
    }

    // Re-configure streams with rotation
    camera3_stream_rotation_t crop_rotate_scale_degrees =
        CAMERA3_STREAM_ROTATION_0;
    if (!use_rotate_and_crop_api_) {
      switch (rotation_degrees_) {
        case 90:
          crop_rotate_scale_degrees = CAMERA3_STREAM_ROTATION_90;
          break;
        case 270:
          crop_rotate_scale_degrees = CAMERA3_STREAM_ROTATION_270;
          break;
        default:
          FAIL() << "Invalid rotation degree: " << rotation_degrees_;
      }
    }
    cam_device_.AddOutputStream(format_, width_, height_,
                                crop_rotate_scale_degrees);
    ASSERT_EQ(0, cam_device_.ConfigureStreams(nullptr))
        << "Configuring stream fails";

    if (use_rotate_and_crop_api_) {
      UpdateMetadata(ANDROID_SCALER_ROTATE_AND_CROP, &rotate_and_crop_mode, 1,
                     &metadata);
    }
    ASSERT_EQ(0, CreateCaptureRequestByMetadata(metadata, nullptr))
        << "Creating capture request fails";

    // Verify the original pattern is asymmetric
    ScopedImage orig_rotated_i420_image(
        new Image(width_, height_, ImageFormat::IMAGE_FORMAT_I420));
    ASSERT_EQ(0, Rotate180(*orig_i420_image, orig_rotated_i420_image.get()));
    ASSERT_LE(ComputeSsim(*orig_i420_image, *orig_rotated_i420_image),
              kPortraitTestSsimThreshold)
        << "Test pattern appears to be symmetric";

    // Generate software crop-rotate-scaled pattern
    ScopedImage sw_portrait_i420_image = CropRotateScale(
        std::move(orig_i420_image), rotation_degrees_, width_, height_);
    ASSERT_NE(nullptr, sw_portrait_i420_image);
    if (save_images_) {
      SaveImage(*sw_portrait_i420_image, "_swconv");
    }

    GetTimeOfTimeout(kDefaultTimeoutMs, &timeout);
    WaitShutterAndCaptureResult(timeout);
    ASSERT_NE(nullptr, buffer_handle_) << "Failed to get portrait frame buffer";
    auto portrait_i420_image =
        ConvertToImage(std::move(buffer_handle_), width_, height_,
                       ImageFormat::IMAGE_FORMAT_I420);
    ASSERT_NE(nullptr, portrait_i420_image);
    if (save_images_) {
      SaveImage(*portrait_i420_image, "_conv");
    }

    // Compare similarity of crop-rotate-scaled patterns
    ASSERT_GT(ComputeSsim(*sw_portrait_i420_image, *portrait_i420_image),
              kPortraitTestSsimThreshold)
        << "SSIM value is lower than threshold";
  }
}

// Test parameters:
// - Camera ID
class Camera3PortraitModeTest : public Camera3FrameFixture,
                                public ::testing::WithParamInterface<int32_t> {
 public:
  const uint32_t kPortraitModeTimeoutMs = 10000;

  Camera3PortraitModeTest() : Camera3FrameFixture(GetParam()) {}

 protected:
  void ProcessResultMetadataOutputBuffers(
      uint32_t frame_number,
      ScopedCameraMetadata metadata,
      std::vector<cros::ScopedBufferHandle> buffers) override;

  // Get portrait mode vendor tags; return false if the tag is not listed in
  // vendor tag manager.
  bool GetPortraitModeVendorTags(uint32_t* portrait_mode_vendor_tag,
                                 uint32_t* segmentation_result_vendor_tag);

  bool LoadTestImage();
  void TakePortraitModePictureTest(bool has_face);

  ScopedCameraMetadata result_metadata_;
  cros::ScopedBufferHandle yuv_buffer_handle_;
  cros::ScopedBufferHandle blob_buffer_handle_;
};

void Camera3PortraitModeTest::ProcessResultMetadataOutputBuffers(
    uint32_t frame_number,
    ScopedCameraMetadata metadata,
    std::vector<cros::ScopedBufferHandle> buffers) {
  result_metadata_ = std::move(metadata);
  for (auto& buffer : buffers) {
    auto* native_handle = camera_buffer_handle_t::FromBufferHandle(*buffer);
    if (native_handle->hal_pixel_format == HAL_PIXEL_FORMAT_BLOB) {
      blob_buffer_handle_ = std::move(buffer);
    } else {
      yuv_buffer_handle_ = std::move(buffer);
    }
  }
}

bool Camera3PortraitModeTest::GetPortraitModeVendorTags(
    uint32_t* portrait_mode_vendor_tag,
    uint32_t* segmentation_result_vendor_tag) {
  if (!cam_module_.GetVendorTagByName("com.google.effect.portraitMode",
                                      portrait_mode_vendor_tag) ||
      !cam_module_.GetVendorTagByName(
          "com.google.effect.portraitModeSegmentationResult",
          segmentation_result_vendor_tag)) {
    return false;
  }
  return true;
}

bool Camera3PortraitModeTest::LoadTestImage() {
  auto* gralloc = Camera3TestGralloc::GetInstance();
  uint32_t width = gralloc->GetWidth(*yuv_buffer_handle_);
  uint32_t height = gralloc->GetHeight(*yuv_buffer_handle_);
  base::CommandLine* cmd_line = base::CommandLine::ForCurrentProcess();
  base::FilePath portrait_mode_test_data_path =
      cmd_line->GetSwitchValuePath("portrait_mode_test_data");
  if (portrait_mode_test_data_path.empty()) {
    LOGF(ERROR) << "Failed to find test data. Did you specify "
                   "'--portrait_mode_test_data='?";
    return false;
  }
  int64_t file_size = 0;
  if (!base::GetFileSize(portrait_mode_test_data_path, &file_size) ||
      file_size <= 0) {
    LOGF(ERROR) << "Failed get file size";
    return false;
  }
  auto test_image = std::vector<char>(file_size);
  int test_image_size = base::ReadFile(portrait_mode_test_data_path,
                                       test_image.data(), file_size);
  if (test_image_size < file_size) {
    LOGF(ERROR) << "Failed to read test image "
                << portrait_mode_test_data_path.value();
    return false;
  }
  libyuv::MJpegDecoder decoder;
  if (!decoder.LoadFrame(reinterpret_cast<uint8_t*>(test_image.data()),
                         test_image_size)) {
    LOGF(ERROR) << "Failed to parse test image";
    return false;
  }
  ScopedImage i420_image(new Image(decoder.GetWidth(), decoder.GetHeight(),
                                   ImageFormat::IMAGE_FORMAT_I420));
  if (libyuv::MJPGToI420(
          reinterpret_cast<uint8_t*>(test_image.data()), test_image_size,
          i420_image->planes[0].addr, i420_image->planes[0].stride,
          i420_image->planes[1].addr, i420_image->planes[1].stride,
          i420_image->planes[2].addr, i420_image->planes[2].stride,
          decoder.GetWidth(), decoder.GetHeight(), decoder.GetWidth(),
          decoder.GetHeight()) != 0) {
    LOGF(ERROR) << "Failed to convert test image to I420";
    return false;
  }
  i420_image = CropRotateScale(std::move(i420_image), 0, width, height);
  if (!i420_image) {
    LOGF(ERROR) << "Failed to crop, rotate and scale test image";
    return false;
  }

  struct android_ycbcr ycbcr_info;
  if (gralloc->LockYCbCr(*yuv_buffer_handle_, 0, 0, 0, width, height,
                         &ycbcr_info) != 0) {
    LOGF(ERROR) << "Failed to lock YUV buffer";
    return false;
  }
  uint32_t v4l2_format =
      cros::CameraBufferManager::GetV4L2PixelFormat(*yuv_buffer_handle_);
  bool res = false;
  switch (v4l2_format) {
    case V4L2_PIX_FMT_NV12:
    case V4L2_PIX_FMT_NV12M:
      if (libyuv::I420ToNV12(
              i420_image->planes[0].addr, i420_image->planes[0].stride,
              i420_image->planes[1].addr, i420_image->planes[1].stride,
              i420_image->planes[2].addr, i420_image->planes[2].stride,
              static_cast<uint8_t*>(ycbcr_info.y), ycbcr_info.ystride,
              static_cast<uint8_t*>(ycbcr_info.cb), ycbcr_info.cstride, width,
              height) == 0) {
        res = true;
      } else {
        LOGF(ERROR) << "Failed to convert test image to NV12";
      }
      break;
    default:
      LOGF(ERROR) << "Unsupported format " << FormatToString(v4l2_format);
  }
  gralloc->Unlock(*yuv_buffer_handle_);
  return res;
}

static bool FillImageWithBlackColor(buffer_handle_t buffer) {
  auto* gralloc = Camera3TestGralloc::GetInstance();
  uint32_t width = gralloc->GetWidth(buffer);
  uint32_t height = gralloc->GetHeight(buffer);
  struct android_ycbcr ycbcr_info;
  if (gralloc->LockYCbCr(buffer, 0, 0, 0, width, height, &ycbcr_info) != 0) {
    LOGF(ERROR) << "Failed to lock YUV buffer";
    return false;
  }
  uint32_t v4l2_format = cros::CameraBufferManager::GetV4L2PixelFormat(buffer);
  bool res = false;
  switch (v4l2_format) {
    case V4L2_PIX_FMT_NV12:
    case V4L2_PIX_FMT_NV12M:
      std::fill(
          static_cast<uint8_t*>(ycbcr_info.y),
          static_cast<uint8_t*>(ycbcr_info.y) + ycbcr_info.ystride * height, 0);
      std::fill(static_cast<uint8_t*>(ycbcr_info.cb),
                static_cast<uint8_t*>(ycbcr_info.cb) +
                    ycbcr_info.cstride * height / 2,
                0x80U);
      res = true;
      break;
    default:
      LOGF(ERROR) << "Unsupported format " << FormatToString(v4l2_format);
  }
  gralloc->Unlock(buffer);
  return res;
}

void Camera3PortraitModeTest::TakePortraitModePictureTest(bool has_face) {
  uint32_t portrait_mode_vendor_tag;
  uint32_t segmentation_result_vendor_tag;
  ASSERT_TRUE(GetPortraitModeVendorTags(&portrait_mode_vendor_tag,
                                        &segmentation_result_vendor_tag));
  auto out_resolutions =
      cam_device_.GetStaticInfo()->GetSortedOutputResolutions(
          HAL_PIXEL_FORMAT_BLOB);
  ASSERT_FALSE(out_resolutions.empty())
      << "Failed to get JPEG format output resolutions";
  ResolutionInfo resolution = out_resolutions.back();
  auto in_resolutions = cam_device_.GetStaticInfo()->GetSortedOutputResolutions(
      HAL_PIXEL_FORMAT_YCbCr_420_888);
  ASSERT_TRUE(std::binary_search(in_resolutions.begin(), in_resolutions.end(),
                                 resolution))
      << "Failed to find " << resolution << " in input YUV resolutions";

  cam_device_.AddInputStream(HAL_PIXEL_FORMAT_YCbCr_420_888, resolution.Width(),
                             resolution.Height());
  cam_device_.AddOutputStream(HAL_PIXEL_FORMAT_YCbCr_420_888,
                              resolution.Width(), resolution.Height(),
                              CAMERA3_STREAM_ROTATION_0);
  cam_device_.AddOutputStream(HAL_PIXEL_FORMAT_BLOB, resolution.Width(),
                              resolution.Height(), CAMERA3_STREAM_ROTATION_0);
  std::vector<const camera3_stream_t*> streams;
  ASSERT_EQ(0, cam_device_.ConfigureStreams(&streams))
      << "Configuring stream fails";
  ASSERT_EQ(0, CreateCaptureRequestByTemplate(CAMERA3_TEMPLATE_STILL_CAPTURE,
                                              nullptr))
      << "Creating capture request fails";

  struct timespec timeout;
  GetTimeOfTimeout(kDefaultTimeoutMs, &timeout);
  WaitShutterAndCaptureResult(timeout);
  ASSERT_NE(nullptr, yuv_buffer_handle_) << "Failed to get YUV output buffer";
  ASSERT_NE(nullptr, blob_buffer_handle_) << "Failed to get BLOB output buffer";

  std::vector<uint8_t> enable_portrait_mode(1, 1);
  UpdateMetadata(portrait_mode_vendor_tag, enable_portrait_mode.data(), 1,
                 &result_metadata_);

  auto GetStream = [&streams](int32_t format, bool is_output) {
    auto dir = is_output ? CAMERA3_STREAM_OUTPUT : CAMERA3_STREAM_INPUT;
    auto it = std::find_if(
        streams.begin(), streams.end(), [&](const camera3_stream_t* stream) {
          return stream->format == format && stream->stream_type == dir;
        });
    return it == streams.end() ? nullptr : *it;
  };
  // prepare input_buffer
  if (has_face) {
    ASSERT_TRUE(LoadTestImage());
  } else {
    ASSERT_TRUE(FillImageWithBlackColor(*yuv_buffer_handle_));
  }
  auto in_buffer = std::move(yuv_buffer_handle_);
  auto in_stream = GetStream(HAL_PIXEL_FORMAT_YCbCr_420_888, false);
  ASSERT_NE(in_stream, nullptr);
  camera3_stream_buffer_t input_buffer = {
      .stream = const_cast<camera3_stream_t*>(in_stream),
      .buffer = in_buffer.get(),
      .status = CAMERA3_BUFFER_STATUS_OK,
      .acquire_fence = -1,
      .release_fence = -1};
  // prepare output_buffer
  std::vector<camera3_stream_buffer_t> output_buffers;
  auto out_stream = GetStream(HAL_PIXEL_FORMAT_BLOB, true);
  ASSERT_NE(out_stream, nullptr);
  ASSERT_EQ(0, cam_device_.AllocateOutputBuffersByStreams({out_stream},
                                                          &output_buffers))
      << "Failed to allocate buffers for capture request";
  camera3_capture_request_t capture_request = {
      .frame_number = UINT32_MAX,
      .settings = result_metadata_.get(),
      .input_buffer = &input_buffer,
      .num_output_buffers = static_cast<uint32_t>(output_buffers.size()),
      .output_buffers = output_buffers.data(),
      .num_physcam_settings = 0};

  // Process capture request
  ASSERT_EQ(0, cam_device_.ProcessCaptureRequest(&capture_request))
      << "Creating capture request fails";
  Camera3PerfLog::GetInstance()->UpdateFrameEvent(
      cam_id_, capture_request.frame_number, FrameEvent::PORTRAIT_MODE_STARTED,
      base::TimeTicks::Now());

  GetTimeOfTimeout(kPortraitModeTimeoutMs, &timeout);
  WaitShutterAndCaptureResult(timeout);
  ASSERT_NE(nullptr, blob_buffer_handle_) << "Failed to get BLOB output buffer";
  Camera3PerfLog::GetInstance()->UpdateFrameEvent(
      cam_id_, capture_request.frame_number, FrameEvent::PORTRAIT_MODE_ENDED,
      base::TimeTicks::Now());
  camera_metadata_ro_entry_t entry = {};
  ASSERT_EQ(
      0, find_camera_metadata_ro_entry(result_metadata_.get(),
                                       segmentation_result_vendor_tag, &entry))
      << "Fail to find "
      << get_camera_metadata_tag_name(segmentation_result_vendor_tag)
      << " in result metadata";
  ASSERT_EQ(1, entry.count);
  if (has_face) {
    ASSERT_EQ(0, entry.data.u8[0]) << "Portrait mode failed";
  } else {
    ASSERT_EQ(3, entry.data.u8[0])
        << "Portrait mode should have failed with no face in the picture";
  }
}

TEST_P(Camera3PortraitModeTest, BasicOperation) {
  TakePortraitModePictureTest(true);
}

TEST_P(Camera3PortraitModeTest, NoFace) {
  TakePortraitModePictureTest(false);
}

INSTANTIATE_TEST_SUITE_P(
    Camera3FrameTest,
    Camera3SingleFrameTest,
    ::testing::Combine(
        ::testing::ValuesIn(Camera3Module().GetTestCameraIds()),
        ::testing::Values(HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED,
                          HAL_PIXEL_FORMAT_YCbCr_420_888,
                          HAL_PIXEL_FORMAT_YCrCb_420_SP,
                          HAL_PIXEL_FORMAT_BLOB,
                          HAL_PIXEL_FORMAT_YV12,
                          HAL_PIXEL_FORMAT_Y8,
                          HAL_PIXEL_FORMAT_Y16,
                          HAL_PIXEL_FORMAT_RAW16),
        ::testing::Values(CAMERA3_TEMPLATE_PREVIEW,
                          CAMERA3_TEMPLATE_STILL_CAPTURE,
                          CAMERA3_TEMPLATE_VIDEO_RECORD,
                          CAMERA3_TEMPLATE_VIDEO_SNAPSHOT,
                          CAMERA3_TEMPLATE_ZERO_SHUTTER_LAG,
                          CAMERA3_TEMPLATE_MANUAL),
        ::testing::Bool()));

INSTANTIATE_TEST_SUITE_P(
    Camera3FrameTest,
    Camera3MultiFrameTest,
    ::testing::Combine(::testing::ValuesIn(Camera3Module().GetTestCameraIds()),
                       ::testing::Values(CAMERA3_TEMPLATE_PREVIEW,
                                         CAMERA3_TEMPLATE_STILL_CAPTURE,
                                         CAMERA3_TEMPLATE_VIDEO_RECORD,
                                         CAMERA3_TEMPLATE_VIDEO_SNAPSHOT,
                                         CAMERA3_TEMPLATE_ZERO_SHUTTER_LAG,
                                         CAMERA3_TEMPLATE_MANUAL),
                       ::testing::Range(1, 10)));

INSTANTIATE_TEST_SUITE_P(
    Camera3FrameTest,
    Camera3MixedTemplateMultiFrameTest,
    ::testing::ValuesIn(Camera3Module().GetTestCameraIds()));

INSTANTIATE_TEST_SUITE_P(
    Camera3FrameTest,
    Camera3FlushRequestsTest,
    ::testing::Combine(::testing::ValuesIn(Camera3Module().GetTestCameraIds()),
                       ::testing::Values(CAMERA3_TEMPLATE_PREVIEW,
                                         CAMERA3_TEMPLATE_STILL_CAPTURE,
                                         CAMERA3_TEMPLATE_VIDEO_RECORD,
                                         CAMERA3_TEMPLATE_VIDEO_SNAPSHOT,
                                         CAMERA3_TEMPLATE_ZERO_SHUTTER_LAG,
                                         CAMERA3_TEMPLATE_MANUAL),
                       ::testing::Values(10)));

INSTANTIATE_TEST_SUITE_P(
    Camera3FrameTest,
    Camera3MultiStreamFrameTest,
    ::testing::ValuesIn(Camera3Module().GetTestCameraIds()));

INSTANTIATE_TEST_SUITE_P(
    Camera3FrameTest,
    Camera3InvalidRequestTest,
    ::testing::ValuesIn(Camera3Module().GetTestCameraIds()));

INSTANTIATE_TEST_SUITE_P(
    Camera3FrameTest,
    Camera3SimpleCaptureFrames,
    ::testing::Combine(::testing::ValuesIn(Camera3Module().GetTestCameraIds()),
                       ::testing::Values(10)));

INSTANTIATE_TEST_SUITE_P(
    Camera3FrameTest,
    Camera3ResultTimestampsTest,
    ::testing::ValuesIn(Camera3Module().GetTestCameraIds()));

INSTANTIATE_TEST_SUITE_P(
    Camera3FrameTest,
    Camera3InvalidBufferTest,
    ::testing::ValuesIn(Camera3Module().GetTestCameraIds()));

static std::vector<std::tuple<int32_t, int32_t, int32_t, int32_t>>
IterateCameraIdFormatResolution() {
  std::vector<std::tuple<int32_t, int32_t, int32_t, int32_t>> result;
  auto cam_ids = Camera3Module().GetTestCameraIds();
  auto formats =
      std::vector<int>({HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED,
                        HAL_PIXEL_FORMAT_YCbCr_420_888, HAL_PIXEL_FORMAT_BLOB});
  for (const auto& cam_id : cam_ids) {
    for (const auto& format : formats) {
      auto resolutions =
          Camera3Module().GetSortedOutputResolutions(cam_id, format);
      for (const auto& resolution : resolutions) {
        result.emplace_back(cam_id, format, resolution.Width(),
                            resolution.Height());
      }
    }
  }
  return result;
}

INSTANTIATE_TEST_SUITE_P(
    Camera3FrameTest,
    Camera3FrameContentTest,
    ::testing::ValuesIn(IterateCameraIdFormatResolution()));

INSTANTIATE_TEST_SUITE_P(
    Camera3FrameTest,
    Camera3PortraitRotationTest,
    ::testing::Combine(::testing::ValuesIn(IterateCameraIdFormatResolution()),
                       ::testing::Values(90, 270),
                       ::testing::Values(false, true)));

INSTANTIATE_TEST_SUITE_P(
    Camera3PortraitModeTest,
    Camera3PortraitModeTest,
    ::testing::ValuesIn(Camera3Module().GetTestCameraIds()));

}  // namespace camera3_test
