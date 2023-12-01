// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/fetchers/storage/device_lister.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/logging.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>

#include "diagnostics/base/file_utils.h"
#include "diagnostics/cros_healthd/fetchers/storage/platform.h"

namespace diagnostics {

namespace {

constexpr char kSysBlockPath[] = "sys/block/";
constexpr char kRemovableFile[] = "removable";
constexpr char kLoopPrefix[] = "loop";
constexpr char kDevMapperPrefix[] = "dm-";
constexpr char kZramPrefix[] = "zram";
constexpr char kEmmcPrefix[] = "mmcblk";

}  // namespace

StorageDeviceLister::StorageDeviceLister(std::unique_ptr<Platform> platform)
    : platform_(std::move(platform)) {
  DCHECK(platform_);
}

std::vector<std::string> StorageDeviceLister::ListDevices(
    const base::FilePath& rootfs) const {
  std::vector<std::string> result;
  const std::vector<std::string> kIgnoredPrefixes = {
      kLoopPrefix, kDevMapperPrefix, kZramPrefix};

  base::FilePath path = rootfs.Append(kSysBlockPath);
  base::FileEnumerator lister(path, false /* non-recursive */,
                              base::FileEnumerator::DIRECTORIES);

  for (base::FilePath device_path = lister.Next(); !device_path.empty();
       device_path = lister.Next()) {
    auto dev_name = device_path.BaseName().value();
    bool ignored = false;

    // Filter 'virtual' devices.
    for (auto p : kIgnoredPrefixes) {
      if (base::StartsWith(dev_name, p, base::CompareCase::SENSITIVE)) {
        ignored = true;
        break;
      }
    }
    if (ignored)
      continue;

    // Filter explicitly removable, or devices where removability could not be
    // detected.
    int64_t removable = 0;
    if (!ReadInteger(device_path, kRemovableFile, &base::StringToInt64,
                     &removable) ||
        removable) {
      VLOG(1) << "Storage device " << device_path.value()
              << " does not specify the removable property or is removable.";
      continue;
    }

    // eMMC devices inserted into card readers are treated as unremovable, so
    // filter all eMMC devices unless they're the |root_device|.
    auto root_device = platform_->GetRootDeviceName();
    if (base::StartsWith(dev_name, kEmmcPrefix, base::CompareCase::SENSITIVE)) {
      if (root_device != dev_name)
        continue;
    }

    result.push_back(device_path.BaseName().value());
  }

  return result;
}

}  // namespace diagnostics
