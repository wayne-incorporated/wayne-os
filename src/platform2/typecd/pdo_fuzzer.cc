// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "typecd/pdo.h"

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>

#include "fuzzer/FuzzedDataProvider.h"

namespace {
constexpr int kPdoDirNameMaxLength = 256;
}  // namespace

namespace typecd {

class PdoFuzzer {
 public:
  PdoFuzzer() {
    // Set up the temporary directory where we create the partner sysfs
    // directory.
    CHECK(scoped_temp_dir_.CreateUniqueTempDir());
    temp_dir_ = scoped_temp_dir_.GetPath();
  }

  base::FilePath temp_dir_;
  base::ScopedTempDir scoped_temp_dir_;
};

}  // namespace typecd

class Environment {
 public:
  Environment() { logging::SetMinLogLevel(logging::LOGGING_ERROR); }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  typecd::PdoFuzzer fuzzer;
  FuzzedDataProvider data_provider(data, size);

  // Set up fake sysfs path.
  auto pdo_dirname =
      data_provider.ConsumeRandomLengthString(kPdoDirNameMaxLength);
  auto pdo_path = fuzzer.temp_dir_.Append(pdo_dirname);

  // CreateDirectory() failures shouldn't be flagged as PdoFuzzer errors.
  if (!base::CreateDirectory(pdo_path))
    return 0;

  auto pdo = typecd::Pdo::MakePdo(pdo_path);
  return 0;
}
