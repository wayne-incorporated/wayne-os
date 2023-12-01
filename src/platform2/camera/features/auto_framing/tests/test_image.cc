/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "features/auto_framing/tests/test_image.h"

#include <drm_fourcc.h>
#include <libyuv.h>

#include <string>

#include <base/bits.h>
#include <base/files/file_util.h>
#include <base/json/json_reader.h>
#include <base/strings/string_util.h>
#include <base/values.h>

#include "cros-camera/camera_buffer_manager.h"
#include "cros-camera/common.h"

namespace cros::tests {

namespace {

TestImage::PixelFormat StringToPixelFormat(const std::string& str) {
  const std::string str_upper = base::ToUpperASCII(str);
  if (str_upper == "NV12") {
    return TestImage::PixelFormat::kNV12;
  } else {
    return TestImage::PixelFormat::kUnknown;
  }
}

TestImage::Metadata ParseMetadata(const base::Value& value) {
  CHECK(value.is_dict());
  const base::Value::Dict& dict = value.GetDict();

  const std::optional<int> width = dict.FindInt("width");
  const std::optional<int> height = dict.FindInt("height");
  const std::string* pixel_format_str = dict.FindString("pixel_format");
  CHECK(width.has_value() && height.has_value() && pixel_format_str);

  const TestImage::PixelFormat pixel_format =
      StringToPixelFormat(*pixel_format_str);
  CHECK_NE(pixel_format, TestImage::PixelFormat::kUnknown);

  std::vector<Rect<uint32_t>> face_rectangles;
  const base::Value::List* face_rects_value = dict.FindList("face_rectangles");
  if (face_rects_value) {
    for (auto& face_rect_value : *face_rects_value) {
      CHECK(face_rect_value.is_list());
      const auto& list_view = face_rect_value.GetList();
      CHECK_EQ(list_view.size(), 4);
      face_rectangles.emplace_back(
          base::checked_cast<uint32_t>(list_view[0].GetInt()),
          base::checked_cast<uint32_t>(list_view[1].GetInt()),
          base::checked_cast<uint32_t>(list_view[2].GetInt()),
          base::checked_cast<uint32_t>(list_view[3].GetInt()));
    }
  }

  return TestImage::Metadata{
      .width = base::checked_cast<uint32_t>(*width),
      .height = base::checked_cast<uint32_t>(*height),
      .pixel_format = pixel_format,
      .face_rectangles = std::move(face_rectangles),
  };
}

uint32_t GetImageSize(uint32_t width,
                      uint32_t height,
                      TestImage::PixelFormat pixel_format) {
  switch (pixel_format) {
    case TestImage::PixelFormat::kNV12:
      return width * height + ((width + 1) / 2) * ((height + 1) / 2) * 2;
    default:
      NOTREACHED();
      return 0;
  }
}

bool ValidateMetadata(const TestImage::Metadata& metadata) {
  return metadata.width > 0 && metadata.height > 0 &&
         metadata.pixel_format != TestImage::PixelFormat::kUnknown &&
         std::all_of(
             metadata.face_rectangles.begin(), metadata.face_rectangles.end(),
             [&](const Rect<uint32_t>& rect) {
               return rect.is_valid() && rect.right() < metadata.width &&
                      rect.bottom() < metadata.height;
             });
}

}  // namespace

std::optional<TestImage> TestImage::Create(const base::FilePath& image_path) {
  base::FilePath metadata_path = image_path.AddExtension("json");
  std::string json_data;
  if (!base::ReadFileToString(metadata_path, &json_data)) {
    LOGF(ERROR) << "Failed to read image metadata from " << metadata_path;
    return std::nullopt;
  }
  const std::optional<base::Value> value = base::JSONReader::Read(json_data);
  if (!value) {
    LOGF(ERROR) << "Failed to read image metadata file as JSON";
    return std::nullopt;
  }
  Metadata metadata = ParseMetadata(*value);
  if (!ValidateMetadata(metadata)) {
    LOGF(ERROR) << "Invalid image metadata";
    return std::nullopt;
  }

  const uint32_t expected_size =
      GetImageSize(metadata.width, metadata.height, metadata.pixel_format);
  std::vector<uint8_t> image(expected_size);
  const int read_size = base::ReadFile(
      image_path, reinterpret_cast<char*>(image.data()), expected_size);
  if (read_size == -1) {
    LOGF(ERROR) << "Failed to read image from " << image_path;
    return std::nullopt;
  } else if (base::checked_cast<uint32_t>(read_size) != expected_size) {
    LOGF(ERROR) << "Unexpected image file size; expected " << expected_size
                << ", got " << read_size;
    return std::nullopt;
  }

  return TestImage(std::move(image), std::move(metadata));
}

uint32_t TestImage::width() const {
  return metadata_.width;
}
uint32_t TestImage::height() const {
  return metadata_.height;
}
Size TestImage::size() const {
  return Size(width(), height());
}
TestImage::PixelFormat TestImage::pixel_format() const {
  return metadata_.pixel_format;
}

uint32_t TestImage::hal_format() const {
  switch (pixel_format()) {
    case PixelFormat::kNV12:
      return HAL_PIXEL_FORMAT_YCBCR_420_888;
    default:
      NOTREACHED();
      return 0;
  }
}
uint32_t TestImage::drm_format() const {
  switch (pixel_format()) {
    case PixelFormat::kNV12:
      return DRM_FORMAT_NV12;
    default:
      NOTREACHED();
      return 0;
  }
}
const uint8_t* TestImage::data() const {
  return reinterpret_cast<const uint8_t*>(image_.data());
}
const std::vector<Rect<uint32_t>>& TestImage::face_rectangles() const {
  return metadata_.face_rectangles;
}

bool WriteTestImageToBuffer(const TestImage& image,
                            buffer_handle_t buffer,
                            std::optional<Rect<uint32_t>> crop) {
  if (!crop) {
    crop = Rect<uint32_t>(0, 0, image.width(), image.height());
  }
  if (!crop->is_valid() || crop->right() >= image.width() ||
      crop->bottom() >= image.height()) {
    LOGF(ERROR) << "Invalid crop window: " << crop->ToString();
    return false;
  }
  ScopedMapping mapping(buffer);
  switch (image.pixel_format()) {
    case TestImage::PixelFormat::kNV12: {
      switch (mapping.drm_format()) {
        case DRM_FORMAT_NV12: {
          const int ret = libyuv::NV12Scale(
              image.data() + crop->left + crop->top * image.width(),
              image.width(),
              image.data() + image.width() * image.height() +
                  base::bits::AlignDown(static_cast<int>(crop->left), 2) +
                  (crop->top / 2) *
                      base::bits::AlignUp(static_cast<int>(image.width()), 2),
              base::bits::AlignUp(static_cast<int>(image.width()), 2),
              crop->width, crop->height, mapping.plane(0).addr,
              mapping.plane(0).stride, mapping.plane(1).addr,
              mapping.plane(1).stride, mapping.width(), mapping.height(),
              libyuv::kFilterBilinear);
          if (ret != 0) {
            LOGF(ERROR) << "libyuv::NV12Scale failed: " << ret;
            return false;
          }
          return true;
        }
        default:
          LOGF(ERROR) << "Unsupported buffer format: "
                      << FormatToString(mapping.drm_format());
          return false;
      }
    }
    default:
      NOTREACHED();
      return false;
  }
}

}  // namespace cros::tests
