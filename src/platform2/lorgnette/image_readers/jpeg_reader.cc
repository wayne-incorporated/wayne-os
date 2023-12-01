// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "lorgnette/image_readers/jpeg_reader.h"

#include <optional>
#include <utility>
#include <vector>

#include <base/notreached.h>
#include <dbus/lorgnette/dbus-constants.h>

#include "lorgnette/constants.h"

namespace lorgnette {

// static
std::unique_ptr<ImageReader> JpegReader::Create(
    brillo::ErrorPtr* error,
    const ScanParameters& params,
    const std::optional<int>& resolution,
    base::ScopedFILE out_file) {
  std::unique_ptr<JpegReader> reader(
      new JpegReader(params, std::move(out_file)));

  if (!reader->ValidateParams(error) ||
      !reader->Initialize(error, resolution)) {
    return nullptr;  // brillo::Error::AddTo already called.
  }

  return reader;
}

JpegReader::~JpegReader() {
  if (initialized_) {
    jpeg_destroy_compress(&cinfo_);
  }
}

bool JpegReader::ReadRow(brillo::ErrorPtr* error, uint8_t* data) {
  DCHECK(valid_);

  JSAMPROW row_pointer[1];
  std::vector<uint8_t> expanded;
  switch (params_.depth) {
    case 1:
      // Expand each bit of `data` to a byte, which is what libjpeg expects.
      for (int i = 0; i < params_.pixels_per_line; i++) {
        expanded.push_back((data[i / 8] >> (7 - (i % 8))) & 0x01 ? 0x00 : 0xFF);
      }
      row_pointer[0] = expanded.data();
      break;
    case 8:
      row_pointer[0] = data;
      break;
    default:
      NOTREACHED();
  }

  jpeg_write_scanlines(&cinfo_, row_pointer, 1);

  return true;
}

bool JpegReader::Finalize(brillo::ErrorPtr* error) {
  DCHECK(valid_);

  // Reset |valid_| so that no new rows can be added to the image, and the image
  // cannot be finalized a second time.
  valid_ = false;

  jpeg_finish_compress(&cinfo_);

  return true;
}

JpegReader::JpegReader(const ScanParameters& params, base::ScopedFILE out_file)
    : ImageReader(params, std::move(out_file)) {}

bool JpegReader::ValidateParams(brillo::ErrorPtr* error) {
  if (!ImageReader::ValidateParams(error)) {
    return false;  // brillo::Error::AddTo already called.
  }

  if (params_.depth != 1 && params_.depth != 8) {
    brillo::Error::AddToPrintf(error, FROM_HERE, kDbusDomain,
                               kManagerServiceError,
                               "Invalid JPEG scan bit depth %d", params_.depth);
    return false;
  }

  return true;
}

bool JpegReader::Initialize(brillo::ErrorPtr* error,
                            const std::optional<int>& resolution) {
  cinfo_.err = jpeg_std_error(&jerr_);
  jpeg_create_compress(&cinfo_);
  jpeg_stdio_dest(&cinfo_, out_file_.get());

  switch (params_.format) {
    case kGrayscale:
      cinfo_.input_components = 1;
      cinfo_.in_color_space = JCS_GRAYSCALE;
      break;
    case kRGB:
      cinfo_.input_components = 3;
      cinfo_.in_color_space = JCS_RGB;
      break;
    default:
      brillo::Error::AddToPrintf(
          error, FROM_HERE, kDbusDomain, kManagerServiceError,
          "Unrecognized frame format %d", params_.format);
      jpeg_destroy_compress(&cinfo_);
      return false;
  }

  cinfo_.image_height = params_.lines;
  cinfo_.image_width = params_.pixels_per_line;

  jpeg_set_defaults(&cinfo_);

  if (resolution.has_value()) {
    cinfo_.density_unit = 1;  // dots/inch.
    cinfo_.X_density = resolution.value();
    cinfo_.Y_density = resolution.value();
  }

  cinfo_.optimize_coding = TRUE;

  jpeg_set_quality(&cinfo_, 95, TRUE);
  jpeg_start_compress(&cinfo_, TRUE);

  initialized_ = true;
  valid_ = true;
  return true;
}

}  // namespace lorgnette
