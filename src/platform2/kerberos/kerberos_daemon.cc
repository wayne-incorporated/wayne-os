// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "kerberos/kerberos_daemon.h"

#include <utility>

#include <base/check.h>
#include <base/logging.h>
#include <brillo/dbus/dbus_object.h>
#include <dbus/kerberos/dbus-constants.h>

#include "kerberos/kerberos_adaptor.h"

namespace kerberos {

namespace {
const char kObjectServicePath[] = "/org/chromium/Kerberos/ObjectManager";
}  // namespace

KerberosDaemon::KerberosDaemon()
    : DBusServiceDaemon(kKerberosServiceName, kObjectServicePath) {}

KerberosDaemon::~KerberosDaemon() = default;

void KerberosDaemon::RegisterDBusObjectsAsync(
    brillo::dbus_utils::AsyncEventSequencer* sequencer) {
  auto dbus_object = std::make_unique<brillo::dbus_utils::DBusObject>(
      object_manager_.get(), object_manager_->GetBus(),
      org::chromium::KerberosAdaptor::GetObjectPath());
  DCHECK(!adaptor_);
  adaptor_ = std::make_unique<KerberosAdaptor>(std::move(dbus_object));
  adaptor_->RegisterAsync(
      sequencer->GetHandler("RegisterAsync() failed", true));
}

}  // namespace kerberos
