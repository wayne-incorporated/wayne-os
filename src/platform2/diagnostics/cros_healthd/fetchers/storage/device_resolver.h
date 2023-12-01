// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_FETCHERS_STORAGE_DEVICE_RESOLVER_H_
#define DIAGNOSTICS_CROS_HEALTHD_FETCHERS_STORAGE_DEVICE_RESOLVER_H_

#include <list>
#include <memory>
#include <set>
#include <string>

#include <base/files/file_path.h>

#include "diagnostics/cros_healthd/fetchers/storage/platform.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {

// Resolves the purpose of the device.
class StorageDeviceResolver {
 public:
  static base::expected<std::unique_ptr<StorageDeviceResolver>,
                        ash::cros_healthd::mojom::ProbeErrorPtr>
  Create(const base::FilePath& rootfs, const std::string& root_device);

  virtual ~StorageDeviceResolver() = default;

  virtual ash::cros_healthd::mojom::StorageDevicePurpose GetDevicePurpose(
      const std::string& dev_name) const;

 protected:
  StorageDeviceResolver() = default;

 private:
  static base::expected<std::set<std::string>,
                        ash::cros_healthd::mojom::ProbeErrorPtr>
  GetSwapDevices(const base::FilePath& rootfs);
  static base::expected<std::set<std::string>,
                        ash::cros_healthd::mojom::ProbeErrorPtr>
  ResolveDevices(const base::FilePath& rootfs,
                 const std::list<std::string>& swap_devs);

  explicit StorageDeviceResolver(
      const std::set<std::string>& swap_backing_devices,
      const std::string& root_device_);

  const std::set<std::string> swap_backing_devices_;
  const std::string root_device_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_FETCHERS_STORAGE_DEVICE_RESOLVER_H_
