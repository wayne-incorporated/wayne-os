/* Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hal/usb/stream_format.h"

#include <algorithm>
#include <cmath>
#include <tuple>

#include <linux/videodev2.h>
#include <system/graphics.h>

#include "cros-camera/common.h"
#include "hal/usb/quirks.h"

namespace cros {

namespace {

constexpr int kSupportedHalFormats[] = {
    HAL_PIXEL_FORMAT_BLOB, HAL_PIXEL_FORMAT_YCbCr_420_888,
    HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED};

std::vector<uint32_t> GetSupportedFourCCs(bool prefer_mjpeg) {
  // The preference of supported fourccs in the list is from high to low.
  std::vector<uint32_t> formats = {
      V4L2_PIX_FMT_YUYV, V4L2_PIX_FMT_MJPEG, V4L2_PIX_FMT_YUV420,
      V4L2_PIX_FMT_RGB24, V4L2_PIX_FMT_Y16, V4L2_PIX_FMT_Z16, V4L2_PIX_FMT_INVZ,
      // JPEG works as MJPEG on some gspca webcams from field reports, see
      // https://code.google.com/p/webrtc/issues/detail?id=529, put it as the
      // least preferred format.
      V4L2_PIX_FMT_JPEG};
  if (prefer_mjpeg) {
    auto it = std::find(formats.begin(), formats.end(), V4L2_PIX_FMT_MJPEG);
    formats.erase(it);
    formats.insert(formats.begin(), V4L2_PIX_FMT_MJPEG);
  }
  return formats;
}

}  // namespace

// Return corresponding format by matching resolution |width|x|height| in
// |formats|.
const SupportedFormat* FindFormatByResolution(const SupportedFormats& formats,
                                              uint32_t width,
                                              uint32_t height) {
  for (const auto& format : formats) {
    if (format.width == width && format.height == height) {
      return &format;
    }
  }
  return NULL;
}

SupportedFormat GetMaximumFormat(const SupportedFormats& supported_formats) {
  SupportedFormat max_format;
  memset(&max_format, 0, sizeof(max_format));
  for (const auto& supported_format : supported_formats) {
    if (supported_format.width >= max_format.width &&
        supported_format.height >= max_format.height) {
      max_format = supported_format;
    }
  }
  return max_format;
}

std::vector<int32_t> GetJpegAvailableThumbnailSizes(
    const SupportedFormats& supported_formats) {
  // This list will include at least one non-zero resolution, plus (0,0) for
  // indicating no thumbnail should be generated.
  std::vector<Size> sizes = {{0, 0}};

  // Each output JPEG size in android.scaler.availableStreamConfigurations will
  // have at least one corresponding size that has the same aspect ratio in
  // availableThumbnailSizes, and vice versa.
  for (auto& supported_format : supported_formats) {
    double aspect_ratio =
        static_cast<double>(supported_format.width) / supported_format.height;

    if (supported_format.width < 192) {
      // Use the same resolution as the thumbnail size.
      sizes.push_back({supported_format.width, supported_format.height});
      continue;
    }
    // Note that we only support to generate thumbnails with (width % 8 == 0)
    // and (height % 2 == 0) for now, so set width as multiple of 48 is good for
    // the common ratios 4:3, 16:9, and 3:2. When width is 192, the thumbnail
    // sizes would be 192x144, 192x108, and 192x128 respectively.
    uint32_t thumbnail_width = 192;
    uint32_t thumbnail_height = round(thumbnail_width / aspect_ratio);

    // It's still possible that some resolutions that make thumbnail_height odd,
    // such as 11:9 (352x288). Ensure it's even by masking out LSB.
    thumbnail_height &= ~1;

    sizes.push_back({thumbnail_width, thumbnail_height});
  }

  // The sizes will be sorted by increasing pixel area (width x height). If
  // several resolutions have the same area, they will be sorted by increasing
  // width.
  std::sort(sizes.begin(), sizes.end());
  sizes.erase(std::unique(sizes.begin(), sizes.end()), sizes.end());

  // The aspect ratio of the largest thumbnail size will be same as the aspect
  // ratio of largest JPEG output size in
  // android.scaler.availableStreamConfigurations. The largest size is defined
  // as the size that has the largest pixel area in a given size list.
  auto max_format = GetMaximumFormat(supported_formats);
  double aspect_ratio =
      static_cast<double>(max_format.width) / max_format.height;
  for (uint32_t thumbnail_width = 240; true; thumbnail_width += 48) {
    uint32_t thumbnail_height = round(thumbnail_width / aspect_ratio);
    thumbnail_height &= ~1;
    Size size(thumbnail_width, thumbnail_height);
    if (sizes.back() < size) {
      sizes.push_back(size);
      break;
    }
  }

  std::vector<int32_t> ret;
  for (auto& size : sizes) {
    ret.push_back(size.width);
    ret.push_back(size.height);
  }
  return ret;
}

SupportedFormats GetQualifiedFormats(const SupportedFormats& supported_formats,
                                     uint32_t quirks) {
  // The preference of supported fourccs in the list is from high to low.
  bool prefer_mjpeg = quirks & kQuirkPreferMjpeg;
  const std::vector<uint32_t> supported_fourccs =
      GetSupportedFourCCs(prefer_mjpeg);
  SupportedFormats qualified_formats;
  for (const auto& supported_fourcc : supported_fourccs) {
    for (const auto& supported_format : supported_formats) {
      if (supported_format.fourcc != supported_fourcc) {
        continue;
      }

      // For the same resolution, prefer the format which has larger frame rate.
      // For the same frame rate, choose preferred fourcc first.
      auto it = qualified_formats.cbegin();
      for (; it != qualified_formats.cend(); it++) {
        if (it->width == supported_format.width &&
            it->height == supported_format.height) {
          break;
        }
      }
      if (it != qualified_formats.cend()) {
        float max_fps_existed_format = GetMaximumFrameRate(*it);
        float max_fps_current_format = GetMaximumFrameRate(supported_format);
        if (max_fps_existed_format < max_fps_current_format) {
          qualified_formats.erase(it);
        } else {
          continue;
        }
      }
      qualified_formats.push_back(supported_format);
    }
  }

  // Sort the resolution from high to low for easier reading and consistent of
  // different camera modules.
  // CTS uses the first 2 resolutions to create streams. It also let CTS choose
  // high resolutions.
  std::sort(qualified_formats.begin(), qualified_formats.end());
  std::reverse(qualified_formats.begin(), qualified_formats.end());
  return qualified_formats;
}

bool IsFormatSupported(const SupportedFormats& supported_formats,
                       const camera3_stream_t& stream) {
  if (std::find(std::begin(kSupportedHalFormats),
                std::end(kSupportedHalFormats),
                stream.format) == std::end(kSupportedHalFormats)) {
    return false;
  }
  for (const auto& supported_format : supported_formats) {
    if (stream.width == supported_format.width &&
        stream.height == supported_format.height) {
      return true;
    }
  }
  return false;
}

float GetMaximumFrameRate(const SupportedFormat& format) {
  float max_fps = 0;
  for (const auto& frame_rate : format.frame_rates) {
    if (frame_rate > max_fps) {
      max_fps = frame_rate;
    }
  }

  return max_fps;
}

}  // namespace cros
