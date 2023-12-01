// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "discod/server.h"

#include <memory>
#include <utility>

#include <base/logging.h>
#include <base/memory/ref_counted.h>
#include <brillo/dbus/dbus_object.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>

#include "discod/control_loop.h"
#include "discod/dbus_adaptors/org.chromium.Discod.h"

namespace discod {

Server::Server(scoped_refptr<dbus::Bus> bus,
               std::unique_ptr<ControlLoop> control_loop)
    : org::chromium::DiscodAdaptor(this),
      dbus_object_(nullptr, bus, dbus::ObjectPath(kDiscodServicePath)),
      control_loop_(std::move(control_loop)) {}

Server::~Server() {
  if (control_loop_) {
    VLOG(1) << "Stopping the control loop...";
    control_loop_->Stop();
  }
}

void Server::RegisterAsync(
    brillo::dbus_utils::AsyncEventSequencer::CompletionAction cb) {
  if (control_loop_) {
    VLOG(1) << "Starting the control loop...";
    control_loop_->Start();
    control_loop_->StartControlLogic();
  }
  RegisterWithDBusObject(&dbus_object_);
  dbus_object_.RegisterAsync(std::move(cb));
}

void Server::EnableWriteBoost() {
  VLOG(1) << "Received EnableWriteBoost call";
  if (control_loop_) {
    control_loop_->EnableWriteBoost();
  }
}

}  // namespace discod
