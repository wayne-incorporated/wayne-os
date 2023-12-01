// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>

#include <base/strings/stringprintf.h>

#include "minios/shill_proxy.h"

namespace minios {

ShillProxy::ShillProxy(scoped_refptr<dbus::Bus> bus_for_proxies)
    : bus_for_proxies_(bus_for_proxies), weak_ptr_factory_(this) {}

void ShillProxy::ManagerRequestScan(
    const std::string& technology,
    OnManagerRequestScanSuccess success_callback,
    OnManagerRequestScanError error_callback) {
  std::make_unique<ManagerProxyType>(bus_for_proxies_)
      ->RequestScanAsync(technology, std::move(success_callback),
                         std::move(error_callback));
}

void ShillProxy::ManagerGetProperties(
    OnManagerGetPropertiesSuccess success_callback,
    OnManagerGetPropertiesError error_callback) {
  std::make_unique<ManagerProxyType>(bus_for_proxies_)
      ->GetPropertiesAsync(std::move(success_callback),
                           std::move(error_callback));
}

void ShillProxy::ManagerFindMatchingService(
    const brillo::VariantDictionary& dict,
    OnManagerFindMatchingServiceSuccess success_callback,
    OnManagerFindMatchingServiceError error_callback) {
  std::make_unique<ManagerProxyType>(bus_for_proxies_)
      ->FindMatchingServiceAsync(dict, std::move(success_callback),
                                 std::move(error_callback));
}

void ShillProxy::ServiceGetProperties(
    const dbus::ObjectPath& service_path,
    OnServiceGetPropertiesSuccess success_callback,
    OnServiceGetPropertiesError error_callback) {
  std::make_unique<ServiceProxyType>(bus_for_proxies_, service_path)
      ->GetPropertiesAsync(std::move(success_callback),
                           std::move(error_callback));
}

void ShillProxy::ServiceSetProperties(
    const dbus::ObjectPath& service_path,
    const brillo::VariantDictionary& dict,
    OnServiceSetPropertiesSuccess success_callback,
    OnServiceSetPropertiesError error_callback) {
  std::make_unique<ServiceProxyType>(bus_for_proxies_, service_path)
      ->SetPropertiesAsync(dict, std::move(success_callback),
                           std::move(error_callback));
}

void ShillProxy::ServiceConnect(const dbus::ObjectPath& service_path,
                                OnServiceConnectSuccess success_callback,
                                OnServiceConnectError error_callback) {
  std::make_unique<ServiceProxyType>(bus_for_proxies_, service_path)
      ->ConnectAsync(std::move(success_callback), std::move(error_callback));
}

}  // namespace minios
