// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_CORE_TESTS_PNG_IO_H_
#define ML_CORE_TESTS_PNG_IO_H_

#include <cstdint>
#include <memory>
#include <png.h>
#include <stdlib.h>

#include <base/files/file_util.h>

class PngInfo {
 public:
  bool GetRawData(uint8_t* buf, uint64_t buf_len);

  uint32_t width;
  uint32_t height;
  int bit_depth;
  uint64_t num_row_bytes;
  std::unique_ptr<png_bytep> row_pointers;

  bool operator==(const PngInfo& rhs) const;

  bool operator!=(const PngInfo& rhs) const;

 private:
  bool CompareRowData(const png_bytep* left,
                      const png_bytep* right,
                      uint32_t height,
                      uint64_t num_row_bytes) const;
};

class PngImageIO {
 public:
  std::optional<PngInfo> ReadPngFile(const base::FilePath filename);
  bool WritePngFile(const base::FilePath filename, const PngInfo& png_info);
};

#endif  // ML_CORE_TESTS_PNG_IO_H_
