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

#include "vm_tools/garcon/desktop_file.h"

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
  // Don't fuzz the filename for the desktop file, FilePath will DCHECK on
  // non-absolute file paths and we also don't want to do recursion and mess up
  // other parts of the filesystem either by writing to random paths.
  base::FilePath desktop_file_path(
      env.temp_dir_.GetPath().Append("fuzz.desktop"));
  // We handle up to 10MB files in the code, but 16KB should be plenty for fuzz
  // testing.
  std::string file_contents = data_provider.ConsumeRandomLengthString(16384);
  base::WriteFile(desktop_file_path, file_contents.c_str(),
                  file_contents.size());

  std::unique_ptr<vm_tools::garcon::DesktopFile> desktop_file =
      vm_tools::garcon::DesktopFile::ParseDesktopFile(desktop_file_path);

  // If it was valid, fuzz it further.
  if (desktop_file) {
    desktop_file->GenerateExecutableFileName();
    std::vector<std::string> exec_args;
    size_t random_arg_count = data_provider.ConsumeIntegralInRange(1, 16);
    for (int i = 0; i < random_arg_count; ++i) {
      exec_args.push_back(data_provider.ConsumeRandomLengthString(128));
    }
    desktop_file->GenerateArgvWithFiles(exec_args);
  }
  return 0;
}
