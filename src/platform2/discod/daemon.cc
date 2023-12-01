// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "discod/daemon.h"

#include <memory>
#include <utility>

#include <base/files/file_path.h>
#include <brillo/daemons/dbus_daemon.h>
#include <chromeos/dbus/service_constants.h>

#include "discod/control_loop.h"
#include "discod/controls/file_based_binary_control.h"
#include "discod/server.h"

namespace discod {

Daemon::Daemon(std::unique_ptr<ControlLoop> control_loop)
    : brillo::DBusServiceDaemon(kDiscodServiceName),
      control_loop_(std::move(control_loop)) {}

void Daemon::RegisterDBusObjectsAsync(
    brillo::dbus_utils::AsyncEventSequencer* sequencer) {
  server_ = std::make_unique<Server>(bus_, std::move(control_loop_));
  server_->RegisterAsync(
      sequencer->GetHandler("Failed to export discod service.", false));
}

}  // namespace discod
