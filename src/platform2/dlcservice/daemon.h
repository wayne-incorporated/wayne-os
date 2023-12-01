// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DLCSERVICE_DAEMON_H_
#define DLCSERVICE_DAEMON_H_

#include <memory>
#include <string>

#include <base/cancelable_callback.h>
#include <brillo/daemons/dbus_daemon.h>
#include <brillo/dbus/dbus_connection.h>

#include "dlcservice/dbus_adaptors/dbus_adaptor.h"

namespace dlcservice {

// |Daemon| is a D-Bus service daemon.
class Daemon : public brillo::DBusServiceDaemon {
 public:
  Daemon();
  ~Daemon() override = default;

 private:
  // |brillo::Daemon| overrides:
  int OnInit() override;
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override;

  std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object_;
  std::unique_ptr<DlcService> dlc_service_;
  std::unique_ptr<DBusAdaptor> dbus_adaptor_;
  // TODO(crbug/965232): Use a separate bus (D-Bus connection) for proxies to
  // avoid missing signal messages.
  scoped_refptr<dbus::Bus> bus_for_proxies_;
  brillo::DBusConnection dbus_connection_for_proxies_;

  Daemon(const Daemon&) = delete;
  Daemon& operator=(const Daemon&) = delete;
};

}  // namespace dlcservice

#endif  // DLCSERVICE_DAEMON_H_
