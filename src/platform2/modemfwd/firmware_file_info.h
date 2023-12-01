// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MODEMFWD_FIRMWARE_FILE_INFO_H_
#define MODEMFWD_FIRMWARE_FILE_INFO_H_

#include <string>

#include <base/files/file_path.h>

namespace modemfwd {

struct FirmwareFileInfo {
  enum class Compression {
    NONE,
    XZ,
  };

  FirmwareFileInfo() : compression(Compression::NONE) {}

  FirmwareFileInfo(const std::string& firmware_path, const std::string& version)
      : FirmwareFileInfo(firmware_path, version, Compression::NONE) {}

  FirmwareFileInfo(const std::string& firmware_path,
                   const std::string& version,
                   Compression compression)
      : firmware_path(firmware_path),
        version(version),
        compression(compression) {}

  // relative path to the firmware file.
  std::string firmware_path;
  std::string version;
  Compression compression;
};

}  // namespace modemfwd

#endif  // MODEMFWD_FIRMWARE_FILE_INFO_H_
