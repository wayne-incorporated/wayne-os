// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml_core/tests/png_io.h"

#include <base/logging.h>

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <utility>

bool PngInfo::CompareRowData(const png_bytep* left,
                             const png_bytep* right,
                             uint32_t height,
                             uint64_t num_row_bytes) const {
  for (uint32_t i = 0; i < height; ++i) {
    for (uint64_t j = 0; j < num_row_bytes; ++j) {
      if (left[i][j] != right[i][j])
        return false;
    }
  }
  return true;
}

bool PngInfo::operator==(const PngInfo& rhs) const {
  return width == rhs.width && height == rhs.height &&
         bit_depth == rhs.bit_depth && num_row_bytes == rhs.num_row_bytes &&
         CompareRowData(row_pointers.get(), rhs.row_pointers.get(), height,
                        num_row_bytes);
}

bool PngInfo::operator!=(const PngInfo& rhs) const {
  return !(*this == rhs);
}

bool PngInfo::GetRawData(uint8_t* buf, uint64_t buf_len) {
  if (buf_len != num_row_bytes * height) {
    return false;
  }
  for (int i = 0; i < height; ++i) {
    for (int j = 0; j < num_row_bytes; ++j) {
      buf[i * num_row_bytes + j] = row_pointers.get()[i][j];
    }
  }
  return true;
}

std::optional<PngInfo> PngImageIO::ReadPngFile(const base::FilePath filename) {
  FILE* fp = fopen(filename.value().c_str(), "rb");
  if (!fp) {
    LOG(ERROR) << "Could not find file: " << filename;
    return std::nullopt;
  }

  // creating some required pngio structures
  png_structp png_ptr =
      png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
  if (!png_ptr) {
    fclose(fp);
    return std::nullopt;
  }
  png_infop info_ptr = png_create_info_struct(png_ptr);
  if (!info_ptr) {
    fclose(fp);
    return std::nullopt;
  }

  if (setjmp(png_jmpbuf(png_ptr))) {
    fclose(fp);
    return std::nullopt;
  }
  png_init_io(png_ptr, fp);

  png_read_info(png_ptr, info_ptr);

  // strip 16 bit channels to 8 bits if needed
  if (png_get_bit_depth(png_ptr, info_ptr) == 16)
    png_set_strip_16(png_ptr);

  // ensure color type is rgb
  if (png_get_color_type(png_ptr, info_ptr) == PNG_COLOR_TYPE_PALETTE)
    png_set_palette_to_rgb(png_ptr);

  // Add alpha channel to make it RGBA
  if (png_get_color_type(png_ptr, info_ptr) == PNG_COLOR_TYPE_RGB ||
      png_get_color_type(png_ptr, info_ptr) == PNG_COLOR_TYPE_GRAY ||
      png_get_color_type(png_ptr, info_ptr) == PNG_COLOR_TYPE_PALETTE) {
    png_set_filler(png_ptr, 0xFF, PNG_FILLER_AFTER);
  }

  // Expand bit depth to 8 bits per channel
  if (png_get_bit_depth(png_ptr, info_ptr) < 8)
    png_set_packing(png_ptr);

  // update info struct
  png_read_update_info(png_ptr, info_ptr);

  // create buffer in which to store pixel data
  uint32_t height = png_get_image_height(png_ptr, info_ptr);

  std::unique_ptr<png_bytep> row_pointers(
      new png_bytep[sizeof(png_bytep) * height]);
  for (int y = 0; y < height; ++y) {
    row_pointers.get()[y] = new png_byte[png_get_rowbytes(png_ptr, info_ptr)];
  }

  // read in image
  png_read_image(png_ptr, row_pointers.get());

  PngInfo png_info{
      .width = png_get_image_width(png_ptr, info_ptr),
      .height = png_get_image_height(png_ptr, info_ptr),
      .bit_depth = png_get_bit_depth(png_ptr, info_ptr),
      .num_row_bytes = png_get_rowbytes(png_ptr, info_ptr),
      .row_pointers = std::move(row_pointers),
  };

  fclose(fp);

  // cleaning up pngio structures
  png_destroy_read_struct(&png_ptr, &info_ptr, NULL);

  return png_info;
}

bool PngImageIO::WritePngFile(const base::FilePath filename,
                              const PngInfo& png_info) {
  FILE* fp = fopen(filename.value().c_str(), "wb");
  if (!fp) {
    LOG(ERROR) << "Could not find file: " << filename;
    return false;
  }

  // creating some necessary pngio structs
  png_structp png_ptr =
      png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
  if (!png_ptr) {
    fclose(fp);
    return false;
  }
  png_infop info_ptr = png_create_info_struct(png_ptr);
  if (!info_ptr) {
    fclose(fp);
    return false;
  }

  if (setjmp(png_jmpbuf(png_ptr))) {
    fclose(fp);
    return false;
  }
  png_init_io(png_ptr, fp);

  // configure the output image format
  png_set_IHDR(png_ptr, info_ptr, png_info.width, png_info.height,
               png_info.bit_depth, PNG_COLOR_TYPE_RGBA, PNG_INTERLACE_NONE,
               PNG_COMPRESSION_TYPE_BASE, PNG_FILTER_TYPE_BASE);
  png_write_info(png_ptr, info_ptr);
  png_write_image(png_ptr, png_info.row_pointers.get());

  png_write_end(png_ptr, NULL);
  png_destroy_write_struct(&png_ptr, &info_ptr);

  fclose(fp);
  return true;
}
