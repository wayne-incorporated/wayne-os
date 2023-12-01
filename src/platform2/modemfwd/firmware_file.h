// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MODEMFWD_FIRMWARE_FILE_H_
#define MODEMFWD_FIRMWARE_FILE_H_

#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>

#include "modemfwd/firmware_file_info.h"

namespace modemfwd {

// A class that prepares the firmware file for flashing by encapsulating the
// decompression step if the firmware file is compressed.
class FirmwareFile {
 public:
  FirmwareFile();
  FirmwareFile(const FirmwareFile&) = delete;
  FirmwareFile& operator=(const FirmwareFile&) = delete;

  ~FirmwareFile();

  // Prepares the firmware file based on the given firmware file information.
  // If the firmware file is compressed, it decompresses the firmware file into
  // a temporary directory, which will be cleaned up upon destruction of this
  // object.
  bool PrepareFrom(const base::FilePath& firmware_dir,
                   const FirmwareFileInfo& file_info);

  // Returns the firmware file path to be referenced in the log and journal
  // file.
  const base::FilePath& path_for_logging() const { return path_for_logging_; }

  // Returns the actual firmware file path on the filesystem.
  const base::FilePath& path_on_filesystem() const {
    return path_on_filesystem_;
  }

 private:
  base::ScopedTempDir temp_dir_;
  base::FilePath path_for_logging_;
  base::FilePath path_on_filesystem_;
};

}  // namespace modemfwd

#endif  // MODEMFWD_FIRMWARE_FILE_H_
