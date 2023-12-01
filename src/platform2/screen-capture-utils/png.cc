// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "screen-capture-utils/png.h"

#include <setjmp.h>

#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <base/files/scoped_file.h>
#include <png.h>

namespace screenshot {

void SaveAsPng(const char* path,
               void* data,
               uint32_t width,
               uint32_t height,
               uint32_t stride) {
  png_struct* png =
      png_create_write_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  CHECK(png) << "png_create_write_struct failed";

  png_info* info = png_create_info_struct(png);
  CHECK(info) << "png_create_info_struct failed";

  CHECK_EQ(setjmp(png_jmpbuf(png)), 0) << "PNG encode failed";

  base::ScopedFILE fp(fopen(path, "we"));
  PCHECK(fp) << "Failed to open " << path << " for writing";
  png_init_io(png, fp.get());

  png_set_IHDR(png, info, width, height, 8, PNG_COLOR_TYPE_RGB,
               PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_DEFAULT,
               PNG_FILTER_TYPE_DEFAULT);
  png_write_info(png, info);

  png_set_bgr(png);
  png_set_filler(png, 0, PNG_FILLER_AFTER);

  std::vector<png_byte*> rows(height);
  for (uint32_t i = 0; i < height; ++i)
    rows[i] = static_cast<png_byte*>(data) + stride * i;

  png_write_image(png, rows.data());
  png_write_end(png, nullptr);

  png_destroy_write_struct(&png, &info);
}

}  // namespace screenshot
