// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LORGNETTE_IMAGE_READERS_IMAGE_READER_H_
#define LORGNETTE_IMAGE_READERS_IMAGE_READER_H_

#include <cstdint>
#include <optional>

#include <base/files/file.h>
#include <brillo/errors/error.h>

#include "lorgnette/sane_client.h"

namespace lorgnette {

// This class is responsible for reading data from a bitmap and producing an
// image.
class ImageReader {
 public:
  ImageReader(const ImageReader&) = delete;
  ImageReader& operator=(const ImageReader&) = delete;
  virtual ~ImageReader() = default;

  // Reads one row of data and appends it to the image in progress.
  virtual bool ReadRow(brillo::ErrorPtr* error, uint8_t* data) = 0;

  // Finalizes the image. Should only be called when all image data has been
  // read by ReadData().
  virtual bool Finalize(brillo::ErrorPtr* error) = 0;

 protected:
  // Concrete ImageReaders' Create() methods should be used instead.
  ImageReader(const ScanParameters& params, base::ScopedFILE out_file);

  // Performs some sanity checks on |params|. Additional format-specific
  // validation should be performed by each concrete image reader. If this
  // function returns false, no other methods should be called on the
  // image reader.
  virtual bool ValidateParams(brillo::ErrorPtr* error);

  // Sets up objects needed by the image reader. Must be called before
  // ReadData().
  virtual bool Initialize(brillo::ErrorPtr* error,
                          const std::optional<int>& resolution) = 0;

  const ScanParameters params_;
  base::ScopedFILE out_file_;
};

}  // namespace lorgnette

#endif  // LORGNETTE_IMAGE_READERS_IMAGE_READER_H_
