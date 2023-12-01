// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/bluetooth_bluez_proxy.h"

#include <memory>
#include <string>

#include <base/time/time.h>
#include <chromeos/dbus/bluetooth/dbus-constants.h>
#include <dbus/object_path.h>

#include "shill/event_dispatcher.h"
#include "shill/logging.h"
#include "shill/scope_logger.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kBluetooth;
}  // namespace Logging

namespace {
constexpr char kBlueZObjectPath[] = "/org/bluez/hci0";

constexpr base::TimeDelta kDBusInitializationDelay = base::Seconds(1);
}  // namespace

BluetoothBlueZProxy::BluetoothBlueZProxy(const scoped_refptr<dbus::Bus>& bus,
                                         EventDispatcher* dispatcher)
    : init_complete_(false),
      dispatcher_(dispatcher),
      bluez_proxy_(new org::bluez::Adapter1Proxy(
          bus,
          bluetooth_adapter::kBluetoothAdapterServiceName,
          dbus::ObjectPath(kBlueZObjectPath))) {
  // One time callback when service becomes available.
  bluez_proxy_->GetObjectProxy()->WaitForServiceToBeAvailable(base::BindOnce(
      &BluetoothBlueZProxy::OnServiceAvailable, weak_factory_.GetWeakPtr()));
}

bool BluetoothBlueZProxy::GetAdapterPowered(bool* powered) const {
  if (!init_complete_) {
    LOG(ERROR) << __func__ << ": BT BlueZ adapter is not ready";
    return false;
  }
  if (!bluez_proxy_->GetProperties()->GetAndBlock(
          &bluez_proxy_->GetProperties()->powered)) {
    LOG(ERROR) << "Failed to query BT 'Powered' property";
    return false;
  }
  if (!bluez_proxy_->is_powered_valid()) {
    LOG(ERROR) << "Invalid BT 'Powered' property";
    return false;
  }
  *powered = bluez_proxy_->powered();
  SLOG(3) << __func__ << ": " << bluez_proxy_->GetObjectPath().value()
          << ": BlueZ BT adapter is "
          << (bluez_proxy_->powered() ? "enabled" : "disabled");
  return true;
}

void BluetoothBlueZProxy::CompleteInitialization() {
  bluez_proxy_->InitializeProperties(base::BindRepeating(
      &BluetoothBlueZProxy::OnPropertyChanged, weak_factory_.GetWeakPtr()));
  init_complete_ = true;
  LOG(INFO) << "Completed initialization of BT BlueZ proxy";
}

void BluetoothBlueZProxy::OnServiceAvailable(bool /* available */) {
  LOG(INFO) << __func__ << ": BT BlueZ service is available";
  // D-Bus race condition: the service reports that it's available before all
  // the methods have been registered. Wait a little bit before querying.
  // TODO(b/263432564): remove the delay once the race condition has been fixed.
  dispatcher_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&BluetoothBlueZProxy::CompleteInitialization,
                     weak_factory_.GetWeakPtr()),
      kDBusInitializationDelay);
}

void BluetoothBlueZProxy::OnPropertyChanged(
    org::bluez::Adapter1ProxyInterface* /* proxy_interface */,
    const std::string& property_name) {
  SLOG(3) << __func__ << ": " << bluez_proxy_->GetObjectPath().value()
          << ": Property '" << property_name << "' changed";
}

}  // namespace shill
