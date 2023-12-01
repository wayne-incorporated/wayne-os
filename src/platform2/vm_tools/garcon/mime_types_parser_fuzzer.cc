// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <vector>

#include <stddef.h>
#include <stdint.h>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>

#include "vm_tools/garcon/mime_types_parser.h"

class Environment {
 public:
  Environment() {
    // Disable logging.
    logging::SetMinLogLevel(logging::LOGGING_FATAL);
    // Setup temp dir for writing out the mime types file to parse.
    CHECK(temp_dir_.CreateUniqueTempDir());
  }

  base::ScopedTempDir temp_dir_;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;

  // 100KB max input size. The parser isn't designed for high efficiency and
  // it can end up timing out on larger input sizes that have lots of
  // whitespace.
  constexpr int kMaxInputSize = 102400;
  if (size > kMaxInputSize)
    return 0;

  // The filename has no impact on this function's execution.
  base::FilePath file_path(env.temp_dir_.GetPath().Append("mime_types"));
  base::WriteFile(file_path, reinterpret_cast<const char*>(data), size);

  vm_tools::garcon::MimeTypeMap map;
  vm_tools::garcon::ParseMimeTypes(file_path.value(), &map);

  return 0;
}
