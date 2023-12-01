// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_DAEMON_H_
#define MINIOS_DAEMON_H_

#include <memory>

#include <brillo/daemons/dbus_daemon.h>

#include "minios/dbus_adaptors/dbus_adaptor.h"
#include "minios/minios.h"

namespace minios {

// |Daemon| is a D-Bus service daemon.
class Daemon : public brillo::DBusServiceDaemon {
 public:
  Daemon();
  ~Daemon() override = default;

  void Start();

  Daemon(const Daemon&) = delete;
  Daemon& operator=(const Daemon&) = delete;

 private:
  // |brillo::Daemon| overrides:
  int OnEventLoopStarted() override;
  // |brillo::DBusServiceDaemon| overrides:
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override;

  brillo::DBusConnection dbus_connection_for_proxies_;
  scoped_refptr<dbus::Bus> bus_for_proxies_;

  std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object_;
  std::unique_ptr<DBusAdaptor> dbus_adaptor_;
  std::shared_ptr<MiniOs> mini_os_;
};

}  // namespace minios

#endif  // MINIOS_DAEMON_H__
