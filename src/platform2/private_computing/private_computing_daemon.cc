// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "private_computing/private_computing_daemon.h"

#include <utility>

#include <base/check.h>
#include <brillo/dbus/async_event_sequencer.h>
#include <brillo/dbus/dbus_object.h>
#include <dbus/private_computing/dbus-constants.h>

#include "private_computing/private_computing_adaptor.h"

namespace private_computing {

namespace {
const char kObjectServicePath[] =
    "/org/chromium/PrivateComputing/ObjectManager";
}  // namespace

PrivateComputingDaemon::PrivateComputingDaemon()
    : DBusServiceDaemon(kPrivateComputingServiceName, kObjectServicePath) {}

void PrivateComputingDaemon::RegisterDBusObjectsAsync(
    brillo::dbus_utils::AsyncEventSequencer* sequencer) {
  auto dbus_object = std::make_unique<brillo::dbus_utils::DBusObject>(
      object_manager_.get(), object_manager_->GetBus(),
      org::chromium::PrivateComputingAdaptor::GetObjectPath());
  DCHECK(!adaptor_);
  adaptor_ = std::make_unique<PrivateComputingAdaptor>(std::move(dbus_object));
  adaptor_->RegisterAsync(
      sequencer->GetHandler("RegisterAsync() failed", true));
}

}  // namespace private_computing
