// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstddef>
#include <cstdint>

#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "screen-capture-utils/png.h"

class PngFuzzerTest {
 public:
  static void Run(const uint8_t* data, size_t size) {
    // We need 8 bytes for width/height and at least 4 bytes for the image
    // data.
    if (size < 12) {
      return;
    }
    FuzzedDataProvider data_provider(data, size);
    // width and height consume 8 bytes;
    size = size - 8;
    // width and height are not uniformly random but this is a simple
    // approximation.
    uint32_t width =
        data_provider.ConsumeIntegralInRange<uint32_t>(1, size / 4);
    // stride = width * bytes_per_pixel.
    uint32_t stride = width * 4;
    uint32_t height =
        data_provider.ConsumeIntegralInRange<uint32_t>(1, size / stride);
    CHECK_LE(stride * height, size);
    // Don't limit input raw data.
    std::vector<uint8_t> image_data =
        data_provider.ConsumeRemainingBytes<uint8_t>();
    base::ScopedTempDir temp_dir;
    CHECK(temp_dir.CreateUniqueTempDir());
    base::FilePath file_path = temp_dir.GetPath().Append("image.png");
    screenshot::SaveAsPng(file_path.value().c_str(), image_data.data(), width,
                          height, stride);
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  PngFuzzerTest::Run(data, size);
  return 0;
}
