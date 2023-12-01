/* Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hardware_verifier/daemon.h"

#include <memory>

#include <dbus/hardware_verifier/dbus-constants.h>

namespace hardware_verifier {

using brillo::dbus_utils::AsyncEventSequencer;
using brillo::dbus_utils::DBusObject;

Daemon::Daemon() : brillo::DBusServiceDaemon(kHardwareVerifierServiceName) {}

int Daemon::OnInit() {
  VLOG(1) << "Starting D-Bus service";
  const auto exit_code = brillo::DBusServiceDaemon::OnInit();
  return exit_code;
}

void Daemon::RegisterDBusObjectsAsync(AsyncEventSequencer* sequencer) {
  DCHECK(!dbus_object_);
  dbus_object_ = std::make_unique<brillo::dbus_utils::DBusObject>(
      nullptr, bus_, dbus::ObjectPath(kHardwareVerifierServicePath));
  adaptor_.reset(new DBusAdaptor(bus_, dbus_object_.get()));
  adaptor_->RegisterAsync(
      sequencer->GetHandler("RegisterAsync() failed", true));
}

}  // namespace hardware_verifier
