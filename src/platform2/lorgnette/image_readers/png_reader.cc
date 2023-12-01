// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "lorgnette/image_readers/png_reader.h"

#include <optional>
#include <utility>

#include <dbus/lorgnette/dbus-constants.h>

#include "lorgnette/constants.h"

namespace lorgnette {

namespace {

// Wrapper for libpng functions that handles converting the setjmp based
// exceptions into safe, usable error codes. It is used like so:
//   brillo::ErrorPtr* error = [...];
//   png_struct* png = [...];
//   png_info* info = [...];
//   int result = LibpngErrorWrap(error, png_write_info, png, info);
template <typename Fn, typename... Args>
int LibpngErrorWrap(brillo::ErrorPtr* error,
                    const Fn& libpng_function,
                    png_struct* png,
                    Args... args) {
  jmp_buf* buf = png_set_longjmp_fn(png, longjmp, sizeof(jmp_buf));
  if (!buf) {
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "Failed to initialize jmp_buf");
    return -1;
  }
  int result = setjmp(*buf);
  if (result != 0) {
    // |libpng_function| failed and longjmp'ed here.
    // Note that error is not set here. It needs to be set by the caller.
    return result;
  }
  libpng_function(png, args...);
  // Disable longjmp so that we don't inadvertently longjmp here from another
  // libpng function.
  png_set_longjmp_fn(png, nullptr, sizeof(jmp_buf));
  return 0;
}

}  // namespace

// static
std::unique_ptr<ImageReader> PngReader::Create(
    brillo::ErrorPtr* error,
    const ScanParameters& params,
    const std::optional<int>& resolution,
    base::ScopedFILE out_file) {
  std::unique_ptr<PngReader> reader(new PngReader(params, std::move(out_file)));

  if (!reader->ValidateParams(error) ||
      !reader->Initialize(error, resolution)) {
    return nullptr;  // brillo::Error::AddTo already called.
  }

  return reader;
}

PngReader::~PngReader() {
  if (png_) {
    // |png_| and |info_| should always have been created together.
    DCHECK(info_);

    png_destroy_write_struct(&png_, &info_);
  }
}

bool PngReader::ReadRow(brillo::ErrorPtr* error, uint8_t* data) {
  DCHECK(valid_);

  int ret = LibpngErrorWrap(error, png_write_row, png_, data);
  if (ret != 0) {
    brillo::Error::AddToPrintf(error, FROM_HERE, kDbusDomain,
                               kManagerServiceError,
                               "Writing PNG row failed with result %d", ret);
    return false;
  }

  return true;
}

bool PngReader::Finalize(brillo::ErrorPtr* error) {
  DCHECK(valid_);

  // Reset |valid_| so that no new rows can be added to the image, and the image
  // cannot be finalized a second time.
  valid_ = false;

  int ret = LibpngErrorWrap(error, png_write_end, png_, info_);
  if (ret != 0) {
    brillo::Error::AddToPrintf(
        error, FROM_HERE, kDbusDomain, kManagerServiceError,
        "Finalizing PNG write failed with result %d", ret);
    return false;
  }

  return true;
}

PngReader::PngReader(const ScanParameters& params, base::ScopedFILE out_file)
    : ImageReader(params, std::move(out_file)) {}

bool PngReader::ValidateParams(brillo::ErrorPtr* error) {
  if (!ImageReader::ValidateParams(error)) {
    return false;  // brillo::Error::AddTo already called.
  }

  if (params_.depth != 1 && params_.depth != 8 && params_.depth != 16) {
    brillo::Error::AddToPrintf(error, FROM_HERE, kDbusDomain,
                               kManagerServiceError,
                               "Invalid PNG scan bit depth %d", params_.depth);
    return false;
  }

  return true;
}

bool PngReader::Initialize(brillo::ErrorPtr* error,
                           const std::optional<int>& resolution) {
  png_ =
      png_create_write_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  if (!png_) {
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "Could not initialize PNG write struct");
    return false;
  }

  info_ = png_create_info_struct(png_);
  if (!info_) {
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "Could not initialize PNG info struct");
    png_destroy_write_struct(&png_, nullptr);
    return false;
  }

  int width = params_.pixels_per_line;
  int height = params_.lines;
  int color_type =
      params_.format == kGrayscale ? PNG_COLOR_TYPE_GRAY : PNG_COLOR_TYPE_RGB;
  png_set_IHDR(png_, info_, width, height, params_.depth, color_type,
               PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_BASE,
               PNG_FILTER_TYPE_BASE);

  if (resolution.has_value()) {
    constexpr double inches_per_meter = 39.3701;
    uint32_t png_resolution = resolution.value() * inches_per_meter;
    png_set_pHYs(png_, info_, png_resolution, png_resolution,
                 PNG_RESOLUTION_METER);
  }

  png_init_io(png_, out_file_.get());
  int ret = LibpngErrorWrap(error, png_write_info, png_, info_);
  if (ret != 0) {
    brillo::Error::AddToPrintf(error, FROM_HERE, kDbusDomain,
                               kManagerServiceError,
                               "Writing PNG info failed with result %d", ret);
    png_destroy_write_struct(&png_, &info_);
    return false;
  }

  // Sanity check to make sure that we're not consuming more data in
  // png_write_row than we have available.
  if (png_get_rowbytes(png_, info_) > params_.bytes_per_line) {
    brillo::Error::AddToPrintf(
        error, FROM_HERE, kDbusDomain, kManagerServiceError,
        "PNG image row requires %zu bytes, but SANE is only providing %d "
        "bytes",
        png_get_rowbytes(png_, info_), params_.bytes_per_line);
    png_destroy_write_struct(&png_, &info_);
    return false;
  }

  // Setup output transformations within libpng so that image data from SANE
  // can be converted to the correct endianness or values for PNG data.
  switch (params_.depth) {
    case 1:
      // Inverts black and white pixels, since monocolor data from SANE has an
      // inverted representation when compared to PNG.
      png_set_invert_mono(png_);
      break;
    case 16:
      // Transpose byte order, since PNG is big-endian and SANE is endian-native
      // i.e. little-endian.
      png_set_swap(png_);
      break;
  }

  valid_ = true;
  return true;
}

}  // namespace lorgnette
