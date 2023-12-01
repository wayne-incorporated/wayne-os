// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/dbus_objectmanager_wrapper.h"

#include <memory>
#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <google/protobuf/message_lite.h>

namespace power_manager::system {
namespace {

// Handles the result of an attempt to connect to a D-Bus signal, logging an
// error on failure.
void HandleSignalConnected(const std::string& interface,
                           const std::string& signal,
                           bool success) {
  if (!success)
    LOG(ERROR) << "Failed to connect to signal " << interface << "." << signal;
}

}  // namespace

DBusObjectManagerWrapper::DBusObjectManagerWrapper(
    const scoped_refptr<dbus::Bus>& bus,
    const std::string& service,
    const std::string& path,
    dbus::ObjectProxy::WaitForServiceToBeAvailableCallback
        service_available_callback,
    dbus::ObjectProxy::NameOwnerChangedCallback service_owner_changed_callback)
    : proxy_(new org::freedesktop::DBus::ObjectManagerProxy(
          bus, service, dbus::ObjectPath(path))) {
  // Monitor service owner changes. This callback lives for the lifetime of
  // the ObjectProxy.
  proxy_->GetObjectProxy()->SetNameOwnerChangedCallback(
      service_owner_changed_callback);

  // One time callback when service becomes available.
  proxy_->GetObjectProxy()->WaitForServiceToBeAvailable(
      std::move(service_available_callback));
}

DBusObjectManagerWrapper::~DBusObjectManagerWrapper() = default;

void DBusObjectManagerWrapper::GetManagedObjects(
    ManagedObjectsCallback callback) {
  proxy_->GetManagedObjectsAsync(std::move(callback), base::DoNothing());
}

void DBusObjectManagerWrapper::set_interfaces_added_callback(
    const InterfacesAddedCallback& callback) {
  proxy_->RegisterInterfacesAddedSignalHandler(
      callback, base::BindOnce(&HandleSignalConnected));
}

void DBusObjectManagerWrapper::set_interfaces_removed_callback(
    const InterfacesRemovedCallback& callback) {
  proxy_->RegisterInterfacesRemovedSignalHandler(
      callback, base::BindOnce(&HandleSignalConnected));
}

}  // namespace power_manager::system
