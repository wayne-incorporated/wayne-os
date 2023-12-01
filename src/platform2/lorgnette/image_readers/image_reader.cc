// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "lorgnette/image_readers/image_reader.h"

#include <inttypes.h>

#include <utility>

#include <dbus/lorgnette/dbus-constants.h>

#include "lorgnette/constants.h"

namespace lorgnette {

namespace {

// The maximum memory size allowed to be allocated for an image.  At the current
// maximum resolution and color depth that the frontend will request, this gives
// 407 sq in, which is more than enough for an 11x17 ledger page or an 8.5x47
// ADF scan.  This also gives just enough for a 1200-dpi 24-bit scan of a
// typical letter/A4-sized platen.  This limit will need to be reconsidered if
// we want to enable full 1200 dpi scanning.
constexpr size_t kMaximumImageSize = 420 * 1024 * 1024;

// Maximum supported height and width for scanned images. Although PNG can
// support larger images, JPEG cannot.
constexpr size_t kMaximiumImageWidth = 65535;
constexpr size_t kMaximiumImageHeight = 65535;

}  // namespace

ImageReader::ImageReader(const ScanParameters& params,
                         base::ScopedFILE out_file)
    : params_(params), out_file_(std::move(out_file)) {}

bool ImageReader::ValidateParams(brillo::ErrorPtr* error) {
  if (params_.depth == 1 && params_.format != kGrayscale) {
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "Cannot have bit depth of 1 with non-grayscale scan");
    return false;
  }

  if (params_.lines < 0) {
    brillo::Error::AddTo(
        error, FROM_HERE, kDbusDomain, kManagerServiceError,
        "Cannot handle scanning of files with unknown lengths");
    return false;
  }

  if (params_.lines == 0) {
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "Cannot scan an image with 0 lines");
    return false;
  }

  if (params_.lines > kMaximiumImageHeight) {
    brillo::Error::AddToPrintf(
        error, FROM_HERE, kDbusDomain, kManagerServiceError,
        "Cannot scan an image with invalid height (%d)", params_.lines);
    return false;
  }

  if (params_.pixels_per_line <= 0 ||
      params_.pixels_per_line > kMaximiumImageWidth) {
    brillo::Error::AddToPrintf(error, FROM_HERE, kDbusDomain,
                               kManagerServiceError,
                               "Cannot scan an image with invalid width (%d)",
                               params_.pixels_per_line);
    return false;
  }

  // Make sure bytes_per_line is large enough to be plausible for
  // pixels_per_line.  It is allowed to be bigger in case the device pads up to
  // a multiple of some internal size.
  size_t colors_per_pixel = params_.format == kRGB ? 3 : 1;
  uint64_t min_bytes_per_line =
      (params_.pixels_per_line * params_.depth * colors_per_pixel + 7) / 8;
  if (params_.bytes_per_line < min_bytes_per_line) {
    brillo::Error::AddToPrintf(
        error, FROM_HERE, kDbusDomain, kManagerServiceError,
        "bytes_per_line (%d) is too small to hold %d pixels with depth %d",
        params_.bytes_per_line, params_.pixels_per_line, params_.depth);
    return false;
  }

  uint64_t needed = static_cast<uint64_t>(params_.lines) *
                    static_cast<uint64_t>(params_.bytes_per_line);
  if (needed > kMaximumImageSize) {
    brillo::Error::AddToPrintf(
        error, FROM_HERE, kDbusDomain, kManagerServiceError,
        "Needed scan buffer size of %" PRIu64 " is too large", needed);
    return false;
  }

  return true;
}

}  // namespace lorgnette
