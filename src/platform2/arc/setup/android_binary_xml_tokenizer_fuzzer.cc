// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/setup/xml/android_binary_xml_tokenizer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include <base/check.h>
#include <base/logging.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>

class Environment {
 public:
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // Disable logging.
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;

  base::ScopedTempDir temp_dir;
  CHECK(temp_dir.CreateUniqueTempDir());
  base::FilePath test_file_path = temp_dir.GetPath().AppendASCII("test.xml");

  CHECK(base::WriteFile(test_file_path, base::span<const uint8_t>(data, size)));

  arc::AndroidBinaryXmlTokenizer tokenizer;
  if (tokenizer.Init(test_file_path)) {
    while (tokenizer.Next()) {
    }
  }
  return 0;
}
