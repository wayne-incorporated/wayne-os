// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "vm_tools/garcon/icon_index_file.h"

class Environment {
 public:
  Environment() {
    // Disable logging.
    logging::SetMinLogLevel(logging::LOGGING_FATAL);
    // Setup temp dir for writing out the desktop file to parse.
    CHECK(temp_dir_.CreateUniqueTempDir());
  }

  base::ScopedTempDir temp_dir_;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  FuzzedDataProvider data_provider(data, size);
  // The filename has no impact on this function's execution.
  base::FilePath index_file_path(env.temp_dir_.GetPath().Append("index.theme"));
  // We handle up to 10MB files in the code, but 16KB should be plenty for fuzz
  // testing.
  std::string file_contents = data_provider.ConsumeRandomLengthString(16384);
  base::WriteFile(index_file_path, file_contents.c_str(), file_contents.size());

  // This takes a dir name and then parses index.theme inside that dir.
  std::unique_ptr<vm_tools::garcon::IconIndexFile> index_file =
      vm_tools::garcon::IconIndexFile::ParseIconIndexFile(
          env.temp_dir_.GetPath());

  // If it was valid, test it a little further. We will only be passing known
  // values into this, but the structure could become broken from fuzzing so
  // this is worth doing.
  if (index_file) {
    index_file->GetPathsForSizeAndScale(32, 1);
    index_file->GetPathsForSizeAndScale(128, 2);
  }
  return 0;
}
