// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/container/obb-mounter/mount_obb_fuse_main.h"

#include <cstddef>
#include <cstdint>
#include <fuse/fuse.h>
#include <string>

#include <base/check.h>
#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "arc/container/obb-mounter/volume.h"

namespace {

constexpr int kRandomIDMaxLength = 32;
constexpr int kRandomFilePathMaxLength = 128;

bool IgnoreLogging(int, const char*, int, size_t, const std::string&) {
  return true;
}

}  // namespace

class Environment {
 public:
  Environment() {
    // Need to disable logging
    logging::SetLogMessageHandler(&IgnoreLogging);
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  FuzzedDataProvider data_provider(data, size);
  // Create string arguments first
  const std::string& mount_path =
      data_provider.ConsumeRandomLengthString(kRandomFilePathMaxLength);
  const std::string& owner_uid =
      data_provider.ConsumeRandomLengthString(kRandomIDMaxLength);
  const std::string& owner_gid =
      data_provider.ConsumeRandomLengthString(kRandomIDMaxLength);

  // Create a temporary directory to hold the created file
  base::ScopedTempDir temp_dir;
  CHECK(temp_dir.CreateUniqueTempDir());
  base::FilePath file_path = temp_dir.GetPath().Append("tmpFile");

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

  mount_obb_fuse_main(path.value(), file_path.value(), mount_path, owner_uid,
                      owner_gid);

  return 0;
}
