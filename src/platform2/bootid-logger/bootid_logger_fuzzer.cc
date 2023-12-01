// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/check.h>
#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <base/time/time.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <stddef.h>
#include <stdint.h>

#include "bootid-logger/bootid_logger.h"
#include "bootid-logger/constants.h"

namespace {

class Environment {
 public:
  Environment() { logging::SetMinLogLevel(logging::LOGGING_FATAL); }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;

  FuzzedDataProvider data_provider(data, size);

  ExtractBootId(data_provider.ConsumeBytesAsString(kBootIdLength));
  ExtractBootId(data_provider.ConsumeBytesAsString(kBootEntryLocalTimeLength));
  ExtractBootId(
      data_provider.ConsumeRandomLengthString(kBootEntryLocalTimeLength));

  base::ScopedTempDir tmp_dir;
  CHECK(tmp_dir.CreateUniqueTempDir());
  base::FilePath file_path = tmp_dir.GetPath().Append("tmpFile");

  const std::string& cur_boot_id =
      data_provider.ConsumeBytesAsString(kBootIdLength);
  // Boot id must be 32 hexadecimal digits.
  if (cur_boot_id.length() != kBootIdLength)
    return 0;

  base::Time now =
      base::Time::FromTimeT(data_provider.ConsumeIntegral<time_t>());
  base::Time keep =
      base::Time::FromTimeT(data_provider.ConsumeIntegral<time_t>());
  size_t max_entries = data_provider.ConsumeIntegral<size_t>();

  // Put all remaining bytes in the file.
  auto path = base::FilePath(file_path);
  base::File file(path,
                  base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);
  if (!file.created()) {
    LOG(ERROR) << "Failed to create " << file_path.value();
    return 0;
  }

  const std::string& file_contents =
      data_provider.ConsumeRemainingBytesAsString();
  file.Write(0, file_contents.c_str(), file_contents.length());

  WriteBootEntry(path, cur_boot_id, now, keep, max_entries);

  return 0;
}
}  // namespace
