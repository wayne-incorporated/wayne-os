/* Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef HARDWARE_VERIFIER_DAEMON_H_
#define HARDWARE_VERIFIER_DAEMON_H_

#include <memory>

#include <brillo/daemons/dbus_daemon.h>
#include <brillo/dbus/async_event_sequencer.h>
#include <brillo/dbus/dbus_object.h>

#include "hardware_verifier/dbus_adaptor.h"

namespace hardware_verifier {

// Daemon class for the hardware_verifier D-Bus service daemon.
class Daemon : public brillo::DBusServiceDaemon {
 public:
  Daemon();
  Daemon(const Daemon&) = delete;
  Daemon& operator=(const Daemon&) = delete;

  ~Daemon() override = default;

 protected:
  // brillo::DBusServiceDaemon overrides.
  int OnInit() override;
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override;

 private:
  std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object_;
  std::unique_ptr<DBusAdaptor> adaptor_;
};

}  // namespace hardware_verifier

#endif  // HARDWARE_VERIFIER_DAEMON_H_
