// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PCIGUARD_DAEMON_H_
#define PCIGUARD_DAEMON_H_

#include "pciguard/session_monitor.h"
#include "pciguard/udev_monitor.h"

#include <brillo/daemons/dbus_daemon.h>
#include <memory>
#include <string>

namespace pciguard {

using brillo::dbus_utils::DBusSignal;

class Daemon : public brillo::DBusServiceDaemon {
 public:
  Daemon();
  Daemon(const Daemon&) = delete;
  Daemon& operator=(const Daemon&) = delete;
  ~Daemon() = default;

 protected:
  int OnInit() override;
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override;
  void HandleUserPermissionChanged(bool ext_pci_allowed);

 private:
  std::unique_ptr<SysfsUtils> utils_;
  std::unique_ptr<EventHandler> event_handler_;
  std::unique_ptr<SessionMonitor> session_monitor_;
  std::unique_ptr<UdevMonitor> udev_monitor_;
  std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object_;
  std::weak_ptr<DBusSignal<std::string>> dev_blocked_signal_;
  void HandlePCIDeviceBlocked(const std::string& drvr);
};

}  // namespace pciguard

#endif  // PCIGUARD_DAEMON_H__
