// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "lorgnette/sane_client.h"

#include <chromeos/dbus/service_constants.h>

#include <optional>

#include "lorgnette/dbus_adaptors/org.chromium.lorgnette.Manager.h"
#include "lorgnette/ippusb_device.h"

namespace lorgnette {

namespace {

constexpr char kIppUsbSocketDir[] = "/run/ippusb";

}  // namespace

std::unique_ptr<SaneDevice> SaneClient::ConnectToDevice(
    brillo::ErrorPtr* error,
    SANE_Status* sane_status,
    const std::string& device_name) {
  std::string real_device = device_name;
  if (device_name.substr(0, 7) == "ippusb:") {
    LOG(INFO) << "Finding real backend for device: " << device_name;
    std::optional<std::string> backend =
        BackendForDevice(device_name, IppUsbSocketDir());
    if (!backend.has_value()) {
      brillo::Error::AddToPrintf(
          error, FROM_HERE, brillo::errors::dbus::kDomain, kManagerServiceError,
          "Didn't get a corrected backend string for ippusb device %s.  Cannot "
          "contact scanner.",
          device_name.c_str());
      return nullptr;
    }

    real_device = backend.value();
    LOG(INFO) << "Updated backend for device: " << real_device;
  }

  return ConnectToDeviceInternal(error, sane_status, real_device);
}

base::FilePath SaneClient::IppUsbSocketDir() const {
  return base::FilePath(kIppUsbSocketDir);
}

}  // namespace lorgnette
