// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/fetchers/storage/device_manager.h"

#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <base/synchronization/lock.h>
#include <brillo/udev/udev.h>
#include <brillo/udev/udev_device.h>

#include "diagnostics/cros_healthd/fetchers/storage/device_info.h"
#include "diagnostics/cros_healthd/utils/error_utils.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

constexpr char kSysBlockPath[] = "sys/block/";

}  // namespace

StorageDeviceManager::StorageDeviceManager(
    std::unique_ptr<StorageDeviceLister> device_lister,
    std::unique_ptr<StorageDeviceResolver> device_resolver,
    std::unique_ptr<brillo::Udev> udev,
    std::unique_ptr<Platform> platform)
    : device_lister_(std::move(device_lister)),
      device_resolver_(std::move(device_resolver)),
      udev_(std::move(udev)),
      platform_(std::move(platform)) {
  DCHECK(device_lister_);
  DCHECK(device_resolver_);
  DCHECK(udev_);
  DCHECK(platform_);
}

std::vector<base::FilePath> StorageDeviceManager::ListDevicesPaths(
    const base::FilePath& root) const {
  std::vector<base::FilePath> res;
  std::vector<std::string> device_names = device_lister_->ListDevices(root);

  for (auto d : device_names)
    res.push_back(root.Append(kSysBlockPath).Append(d));

  return res;
}

mojom::ProbeErrorPtr StorageDeviceManager::RefreshDevices(
    const base::FilePath& root) {
  std::vector<base::FilePath> new_devices_vector = ListDevicesPaths(root);
  std::set<base::FilePath> new_devices(new_devices_vector.begin(),
                                       new_devices_vector.end());

  // Cleanup devices that disappeared between probes. This shall never happen,
  // but we handle it here just in case.
  auto it = devices_.begin();
  while (it != devices_.end()) {
    const auto& devpath = it->first;
    const auto& detected = new_devices.find(devpath);
    if (detected == new_devices.end()) {
      LOG(WARNING) << "Device disapeared: " << devpath.value();
      it = devices_.erase(it);
      continue;
    } else {
      new_devices.erase(detected);
      ++it;
    }
  }

  // Add new devices. We expect it to happen only once for each device.
  for (const auto& sys_path : new_devices) {
    VLOG(1) << "Preparing the node " << sys_path.value();

    std::unique_ptr<brillo::UdevDevice> dev =
        udev_->CreateDeviceFromSysPath(sys_path.value().c_str());
    if (!dev) {
      return CreateAndLogProbeError(
          mojom::ErrorType::kSystemUtilityError,
          "Unable to retrieve udev for " + sys_path.value());
    }

    // Fill the output with a colon-separated list of subsystems. For example,
    // "block:mmc:mmc_host:pci". Similar output is returned by `lsblk -o
    // SUBSYSTEMS`.
    std::string subsystem = dev->GetSubsystem();
    for (auto it = dev->GetParent(); it; it = it->GetParent()) {
      auto s = it->GetSubsystem();
      if (s != nullptr)
        subsystem += std::string(":") + s;
    }

    auto dev_info = StorageDeviceInfo::Create(
        sys_path, base::FilePath(dev->GetDeviceNode()), subsystem,
        device_resolver_->GetDevicePurpose(sys_path.BaseName().value()),
        platform_.get());

    if (!dev_info) {
      return CreateAndLogProbeError(
          mojom::ErrorType::kSystemUtilityError,
          base::StringPrintf("Unable to create dev info object for %s : '%s'",
                             sys_path.value().c_str(), subsystem.c_str()));
    }

    devices_[sys_path] = std::move(dev_info);
  }
  return nullptr;
}

base::expected<std::vector<mojom::NonRemovableBlockDeviceInfoPtr>,
               mojom::ProbeErrorPtr>
StorageDeviceManager::FetchDevicesInfo(const base::FilePath& root) {
  std::vector<mojom::NonRemovableBlockDeviceInfoPtr> devices{};

  base::AutoLock lock(fetch_lock_);
  if (auto error = RefreshDevices(root); !error.is_null()) {
    return base::unexpected(std::move(error));
  }

  for (auto& dev_info_pair : devices_) {
    auto& dev_info = dev_info_pair.second;
    if (auto info_result = dev_info->FetchDeviceInfo();
        info_result.has_value()) {
      devices.push_back(info_result.value().Clone());
    } else {
      return base::unexpected(info_result.error()->Clone());
    }
  }

  return devices;
}

}  // namespace diagnostics
