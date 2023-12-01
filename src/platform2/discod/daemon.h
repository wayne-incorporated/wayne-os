// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DISCOD_DAEMON_H_
#define DISCOD_DAEMON_H_

#include <memory>

#include <brillo/daemons/dbus_daemon.h>

#include "discod/control_loop.h"
#include "discod/server.h"

namespace discod {

class Daemon : public brillo::DBusServiceDaemon {
 public:
  explicit Daemon(std::unique_ptr<ControlLoop> control_loop);
  Daemon(const Daemon&) = delete;
  Daemon& operator=(const Daemon&) = delete;
  ~Daemon() override = default;

 private:
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override;

  std::unique_ptr<Server> server_;
  std::unique_ptr<ControlLoop> control_loop_;
};

}  //  namespace discod

#endif  // DISCOD_DAEMON_H_
