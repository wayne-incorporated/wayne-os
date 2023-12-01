// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstddef>
#include <cstdint>

#include "crash-reporter/bluetooth_devcd_parser_util.h"

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>

#include "crash-reporter/udev_bluetooth_util.h"

class Environment {
 public:
  Environment() {
    // Set-up code.
    CHECK(tmp_dir_.CreateUniqueTempDir());
    output_dir_ = tmp_dir_.GetPath();
    dump_path_ = output_dir_.Append("bt_firmware.devcd");
    target_path_ = output_dir_.Append("bt_firmware.txt");

    // Disable logging per instructions.
    logging::SetMinLogLevel(logging::LOG_FATAL);
  }

  bool CreateDumpFile(const void* data, size_t size) {
    // Clear previous test files, if any.
    if (!base::DeleteFile(dump_path_) || !base::DeleteFile(target_path_)) {
      return false;
    }

    // Create input coredump file.
    base::File file(dump_path_,
                    base::File::FLAG_CREATE | base::File::FLAG_WRITE);

    if (file.IsValid()) {
      file.WriteAtCurrentPos(static_cast<const char*>(data), size);
    }

    return true;
  }

  base::FilePath output_dir_;
  base::FilePath dump_path_;
  base::FilePath target_path_;

 private:
  base::ScopedTempDir tmp_dir_;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  std::string sig;

  // Fuzzing code.
  if (env.CreateDumpFile(data, size)) {
    bluetooth_util::IsBluetoothCoredump(env.dump_path_);
    bluetooth_util::ParseBluetoothCoredump(env.dump_path_, env.output_dir_,
                                           false, &sig);
  }

  return 0;
}
