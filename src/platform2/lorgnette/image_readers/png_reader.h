// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LORGNETTE_IMAGE_READERS_PNG_READER_H_
#define LORGNETTE_IMAGE_READERS_PNG_READER_H_

#include <memory>
#include <optional>

#include <png.h>

#include "lorgnette/image_readers/image_reader.h"

namespace lorgnette {

// This class is responsible for reading data from a bitmap and producing a PNG
// image.
class PngReader final : public ImageReader {
 public:
  static std::unique_ptr<ImageReader> Create(
      brillo::ErrorPtr* error,
      const ScanParameters& params,
      const std::optional<int>& resolution,
      base::ScopedFILE out_file);
  ~PngReader();

  bool ReadRow(brillo::ErrorPtr* error, uint8_t* data) override;
  bool Finalize(brillo::ErrorPtr* error) override;

 private:
  PngReader(const ScanParameters& params, base::ScopedFILE out_file);
  bool ValidateParams(brillo::ErrorPtr* error) override;
  bool Initialize(brillo::ErrorPtr* error,
                  const std::optional<int>& resolution) override;

  // Whether or not the PngReader is in a valid state.
  bool valid_ = false;

  png_struct* png_ = nullptr;
  png_info* info_ = nullptr;
};

}  // namespace lorgnette

#endif  // LORGNETTE_IMAGE_READERS_PNG_READER_H_
