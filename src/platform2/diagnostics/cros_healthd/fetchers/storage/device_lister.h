// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_FETCHERS_STORAGE_DEVICE_LISTER_H_
#define DIAGNOSTICS_CROS_HEALTHD_FETCHERS_STORAGE_DEVICE_LISTER_H_

#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>

#include "diagnostics/cros_healthd/fetchers/storage/platform.h"

namespace diagnostics {

// StorageDeviceLister lists node names of non-removable physical storage
// devices present in the system.
class StorageDeviceLister {
 public:
  explicit StorageDeviceLister(
      std::unique_ptr<Platform> platform = std::make_unique<Platform>());
  StorageDeviceLister(const StorageDeviceLister&) = delete;
  StorageDeviceLister(StorageDeviceLister&&) = delete;
  StorageDeviceLister& operator=(const StorageDeviceLister&) = delete;
  StorageDeviceLister& operator=(StorageDeviceLister&&) = delete;
  virtual ~StorageDeviceLister() = default;

  // Lists internal storage devices nodes names.
  virtual std::vector<std::string> ListDevices(
      const base::FilePath& rootfs) const;

 private:
  const std::unique_ptr<const Platform> platform_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_FETCHERS_STORAGE_DEVICE_LISTER_H_
