// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include <string>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>

#include "base/logging.h"
#include "metrics/metrics_library.h"

const char kTestConsentIdFile[] = "test-consent-id";

class Environment {
 public:
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // Disable logging.
    CHECK(temp_dir_.CreateUniqueTempDir());
    temp_file_ = temp_dir_.GetPath().Append(kTestConsentIdFile);
  }
  Environment(const Environment&) = delete;
  Environment& operator=(const Environment&) = delete;

  const base::FilePath& temp_file() { return temp_file_; }

 private:
  base::ScopedTempDir temp_dir_;
  base::FilePath temp_file_;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  static MetricsLibrary lib;

  lib.SetConsentFileForTest(env.temp_file());

  base::WriteFile(env.temp_file(), reinterpret_cast<const char*>(data), size);

  std::string id;
  lib.ConsentId(&id);
  base::DeleteFile(env.temp_file());

  return 0;
}
