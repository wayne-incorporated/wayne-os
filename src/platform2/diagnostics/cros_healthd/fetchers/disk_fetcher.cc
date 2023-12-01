// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/fetchers/disk_fetcher.h"

#include <utility>
#include <vector>

#include <base/notreached.h>
#include <base/types/expected.h>
#include <brillo/udev/udev.h>

#include "diagnostics/cros_healthd/fetchers/storage/device_lister.h"
#include "diagnostics/cros_healthd/fetchers/storage/device_manager.h"
#include "diagnostics/cros_healthd/fetchers/storage/device_resolver.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

}  // namespace

mojom::ProbeErrorPtr DiskFetcher::InitManager() {
  auto udev = brillo::Udev::Create();
  if (!udev)
    return mojom::ProbeError::New(mojom::ErrorType::kSystemUtilityError,
                                  "Unable to create udev interface");

  auto platform = std::make_unique<Platform>();
  if (auto resolver_result = StorageDeviceResolver::Create(
          context_->root_dir(), platform->GetRootDeviceName());
      resolver_result.has_value()) {
    manager_.reset(
        new StorageDeviceManager(std::make_unique<StorageDeviceLister>(),
                                 std::move(resolver_result.value()),
                                 std::move(udev), std::move(platform)));
    return nullptr;
  } else {
    return std::move(resolver_result.error());
  }
}

mojom::NonRemovableBlockDeviceResultPtr
DiskFetcher::FetchNonRemovableBlockDevicesInfo() {
  if (!manager_) {
    if (auto error = InitManager(); !error.is_null()) {
      return mojom::NonRemovableBlockDeviceResult::NewError(std::move(error));
    }
  }

  if (auto devices_result = manager_->FetchDevicesInfo(context_->root_dir());
      devices_result.has_value()) {
    return mojom::NonRemovableBlockDeviceResult::NewBlockDeviceInfo(
        std::move(devices_result.value()));
  } else {
    return mojom::NonRemovableBlockDeviceResult::NewError(
        std::move(devices_result.error()));
  }
}

}  // namespace diagnostics
