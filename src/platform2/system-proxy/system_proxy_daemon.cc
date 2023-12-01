// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "system-proxy/system_proxy_daemon.h"

#include <utility>

#include <base/check.h>
#include <brillo/dbus/dbus_object.h>
#include <dbus/system_proxy/dbus-constants.h>

#include "system-proxy/system_proxy_adaptor.h"

namespace system_proxy {

namespace {
const char kObjectServicePath[] = "/org/chromium/SystemProxy/ObjectManager";
}  // namespace

SystemProxyDaemon::SystemProxyDaemon()
    : DBusServiceDaemon(kSystemProxyServiceName, kObjectServicePath) {}
SystemProxyDaemon::~SystemProxyDaemon() = default;

void SystemProxyDaemon::RegisterDBusObjectsAsync(
    brillo::dbus_utils::AsyncEventSequencer* sequencer) {
  auto dbus_object = std::make_unique<brillo::dbus_utils::DBusObject>(
      object_manager_.get(), object_manager_->GetBus(),
      org::chromium::SystemProxyAdaptor::GetObjectPath());
  DCHECK(!adaptor_);
  adaptor_ = std::make_unique<SystemProxyAdaptor>(std::move(dbus_object));
  adaptor_->RegisterAsync(
      sequencer->GetHandler("RegisterAsync() failed", true));
}
}  // namespace system_proxy
