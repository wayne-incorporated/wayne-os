// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MODEMFWD_NOTIFICATION_MANAGER_H_
#define MODEMFWD_NOTIFICATION_MANAGER_H_

#include <string>

#include <brillo/daemons/dbus_daemon.h>

#include "modemfwd/dbus_adaptors/org.chromium.Modemfwd.h"
#include "modemfwd/metrics.h"

namespace modemfwd {

class NotificationManager {
 public:
  explicit NotificationManager(org::chromium::ModemfwdAdaptor* dbus_adaptor,
                               Metrics* metrics);
  virtual ~NotificationManager() = default;

  virtual void NotifyUpdateFirmwareCompletedSuccess(bool fw_installed,
                                                    uint32_t firmware_types);
  virtual void NotifyUpdateFirmwareCompletedFailure(const brillo::Error*);
  virtual void NotifyUpdateFirmwareCompletedFlashFailure(
      const brillo::Error* error, uint32_t firmware_types);

 protected:
  NotificationManager() = default;

 private:
  // Owned by Daemon
  org::chromium::ModemfwdAdaptor* dbus_adaptor_;
  Metrics* metrics_;
};

}  // namespace modemfwd

#endif  // MODEMFWD_NOTIFICATION_MANAGER_H_
