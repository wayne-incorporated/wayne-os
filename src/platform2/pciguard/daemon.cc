// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "pciguard/daemon.h"
#include "pciguard/sysfs_utils.h"

#include <base/check.h>
#include <base/logging.h>
#include <dbus/pciguard/dbus-constants.h>
#include <sysexits.h>

namespace pciguard {

Daemon::Daemon() : DBusServiceDaemon(kPciguardServiceName) {}

int Daemon::OnInit() {
  LOG(INFO) << "pciguard daemon starting...";

  utils_ = std::make_unique<SysfsUtils>();
  int exit_code = utils_->OnInit();
  if (exit_code != EX_OK)
    return exit_code;

  event_handler_ = std::make_unique<EventHandler>(utils_.get());

  exit_code = DBusServiceDaemon::OnInit();
  if (exit_code != EX_OK)
    return exit_code;

  // Begin monitoring the session events
  session_monitor_ =
      std::make_unique<SessionMonitor>(bus_, event_handler_.get());
  // Begin monitoring the thunderbolt udev events
  UdevMonitor::PcidevBlockedFn cb = [this](const std::string& drvr) {
    HandlePCIDeviceBlocked(drvr);
  };
  udev_monitor_ = std::make_unique<UdevMonitor>(event_handler_.get(), cb);

  LOG(INFO) << "pciguard daemon started";

  return EX_OK;
}

void Daemon::RegisterDBusObjectsAsync(
    brillo::dbus_utils::AsyncEventSequencer* sequencer) {
  DCHECK(!dbus_object_);
  dbus_object_ = std::make_unique<brillo::dbus_utils::DBusObject>(
      nullptr, bus_, dbus::ObjectPath(kPciguardServicePath));

  brillo::dbus_utils::DBusInterface* dbus_interface =
      dbus_object_->AddOrGetInterface(kPciguardServiceInterface);
  CHECK(dbus_interface) << "Couldn't get dbus_interface";

  dbus_interface->AddSimpleMethodHandler(kSetExternalPciDevicesPermissionMethod,
                                         base::Unretained(this),
                                         &Daemon::HandleUserPermissionChanged);
  dev_blocked_signal_ =
      dbus_interface->RegisterSignal<std::string>(kPCIDeviceBlockedSignal);
  dbus_object_->RegisterAsync(sequencer->GetHandler(
      "Failed to register D-Bus object", true /* failure_is_fatal */));
}

void Daemon::HandleUserPermissionChanged(bool ext_pci_allowed) {
  DCHECK(event_handler_);
  event_handler_->OnUserPermissionChanged(ext_pci_allowed);
}

void Daemon::HandlePCIDeviceBlocked(const std::string& drvr) {
  auto signal = dev_blocked_signal_.lock();
  if (signal)
    signal->Send(drvr);
}

}  // namespace pciguard
