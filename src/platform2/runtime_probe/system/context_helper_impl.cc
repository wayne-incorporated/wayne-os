// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include <memory>

#include <base/logging.h>
#include <brillo/dbus/dbus_connection.h>
#include <shill/dbus-proxies.h>

#include "runtime_probe/system/context_helper_impl.h"

namespace runtime_probe {

bool ContextHelperImpl::SetupDBusConnection() {
  dbus_bus_ = connection_.Connect();
  if (!dbus_bus_) {
    LOG(ERROR) << "Cannot connect to dbus.";
    return false;
  }
  return true;
}

void ContextHelperImpl::SetupShillManagerProxy() {
  // We can't establish D-Bus connection in some of the helpers, so it is not
  // established until we want to use it.
  if (!dbus_bus_) {
    CHECK(SetupDBusConnection()) << "Cannot setup dbus service";
  }
  shill_manager_proxy_ =
      std::make_unique<org::chromium::flimflam::ManagerProxy>(dbus_bus_);
}

std::unique_ptr<org::chromium::flimflam::DeviceProxyInterface>
ContextHelperImpl::CreateShillDeviceProxy(const dbus::ObjectPath& path) {
  // We can't establish D-Bus connection in some of the helpers, so it is not
  // established until we want to use it.
  if (!dbus_bus_) {
    CHECK(SetupDBusConnection()) << "Cannot setup dbus service";
  }
  return std::make_unique<org::chromium::flimflam::DeviceProxy>(dbus_bus_,
                                                                path);
}

}  // namespace runtime_probe
