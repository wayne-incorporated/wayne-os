// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "minios/disk_util.h"

#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

#include "minios/process_manager.h"

namespace minios {

namespace {
constexpr char kDevicePath[] = "/dev";
constexpr char kStoragePath[] = "/sys/class/block";
}  // namespace

DiskUtil::DiskUtil() : device_path_(kDevicePath), storage_path_(kStoragePath) {}

base::FilePath DiskUtil::GetFixedDrive() {
  base::FileEnumerator e(base::FilePath(storage_path_), false,
                         base::FileEnumerator::DIRECTORIES);
  for (base::FilePath path = e.Next(); !path.empty(); path = e.Next()) {
    // Skip over loopback and dm-verity devices.
    if (base::StartsWith(path.BaseName().value(), "loop",
                         base::CompareCase::SENSITIVE) ||
        base::StartsWith(path.BaseName().value(), "dm-",
                         base::CompareCase::SENSITIVE)) {
      continue;
    }

    auto removable_file_path = path.Append("removable");
    if (!base::PathExists(removable_file_path)) {
      LOG(INFO) << "Skipping storage path " << path.value()
                << " as the removable file is missing.";
      continue;
    }
    std::string is_removable;
    if (!base::ReadFileToString(removable_file_path, &is_removable)) {
      PLOG(WARNING) << "Failed to read " << removable_file_path.value();
      continue;
    }
    if (base::TrimWhitespaceASCII(is_removable,
                                  base::TrimPositions::TRIM_ALL) != "0") {
      LOG(INFO) << "Skipping storage path " << path.value()
                << " as it's removable.";
      continue;
    }

    auto fixed_drive = device_path_.Append(path.BaseName());
    if (!base::PathExists(fixed_drive)) {
      LOG(INFO) << "Skipping storage path " << path.value()
                << " as missing path " << fixed_drive.value();
      continue;
    }

    // This returns the first fixed drive found.
    LOG(INFO) << "Found fixed drive " << fixed_drive.value();
    return fixed_drive;
  }

  // Empty `base::FilePath` is no fixed drives are found.
  return {};
}

base::FilePath DiskUtil::GetStatefulPartition(const base::FilePath& drive) {
  for (const auto& path : {base::FilePath(drive.value() + "p1"),
                           base::FilePath(drive.value() + "1")}) {
    if (base::PathExists(path))
      return path;
  }
  return {};
}

void DiskUtil::SetDevicePathForTest(const base::FilePath& device_path) {
  device_path_ = device_path;
}

void DiskUtil::SetStoragePathForTest(const base::FilePath& storage_path) {
  storage_path_ = storage_path;
}

}  // namespace minios
