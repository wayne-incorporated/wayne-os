// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "modemfwd/metrics.h"
#include "modemfwd/notification_manager.h"

#include <string>

#include <base/logging.h>

namespace modemfwd {

NotificationManager::NotificationManager(
    org::chromium::ModemfwdAdaptor* dbus_adaptor, Metrics* metrics)
    : dbus_adaptor_(dbus_adaptor), metrics_(metrics) {}

void NotificationManager::NotifyUpdateFirmwareCompletedSuccess(
    bool fw_installed, uint32_t firmware_types) {
  dbus_adaptor_->SendUpdateFirmwareCompletedSignal(true, "");
  if (fw_installed) {
    metrics_->SendFwInstallResultSuccess();
    metrics_->SendDetailedFwInstallSuccessResult(firmware_types);
  }
}

void NotificationManager::NotifyUpdateFirmwareCompletedFailure(
    const brillo::Error* error) {
  NotifyUpdateFirmwareCompletedFlashFailure(
      error, static_cast<int>(
                 metrics::ModemFirmwareType::kModemFirmwareTypeNotAvailable));
}

void NotificationManager::NotifyUpdateFirmwareCompletedFlashFailure(
    const brillo::Error* error, uint32_t firmware_types) {
  DCHECK(error);
  dbus_adaptor_->SendUpdateFirmwareCompletedSignal(false, error->GetCode());
  metrics_->SendFwInstallResultFailure(error);
  metrics_->SendDetailedFwInstallFailureResult(firmware_types, error);
}

}  // namespace modemfwd
