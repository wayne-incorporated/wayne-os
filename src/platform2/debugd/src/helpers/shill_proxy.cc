// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/helpers/shill_proxy.h"

#include <chromeos/dbus/service_constants.h>

#include <optional>
#include <utility>

namespace debugd {

std::unique_ptr<ShillProxy> ShillProxy::Create() {
  scoped_refptr<dbus::Bus> bus = ConnectToSystemBus();
  if (!bus)
    return nullptr;

  return std::unique_ptr<ShillProxy>(new ShillProxy(bus));
}

ShillProxy::ShillProxy(scoped_refptr<dbus::Bus> bus)
    : SystemServiceProxy(bus, shill::kFlimflamServiceName) {}

std::optional<base::Value::Dict> ShillProxy::GetProperties(
    const std::string& interface_name, const dbus::ObjectPath& object_path) {
  dbus::MethodCall method_call(interface_name, shill::kGetPropertiesFunction);
  auto response = CallMethodAndGetResponse(object_path, &method_call);
  if (!response || !response->is_dict())
    return std::nullopt;
  return std::move(response->GetDict());
}

}  // namespace debugd
