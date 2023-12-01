// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/bluetooth_manager_proxy.h"

#include <cstdint>
#include <vector>

#include <brillo/variant_dictionary.h>

#include "bluetooth/dbus-proxies.h"
#include "shill/bluetooth/bluetooth_manager_interface.h"
#include "shill/error.h"
#include "shill/logging.h"
#include "shill/scope_logger.h"

namespace shill {

namespace {
// TOOD(b/262931830): Use constants defined in system_api once they've been
// added.
constexpr char kBTManagerServiceName[] = "org.chromium.bluetooth.Manager";

constexpr base::TimeDelta kDBusInitializationDelay = base::Seconds(1);
}

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kBluetooth;
}  // namespace Logging

BluetoothManagerProxy::BluetoothManagerProxy(
    const scoped_refptr<dbus::Bus>& bus,
    EventDispatcher* dispatcher,
    const base::RepeatingClosure& service_appeared_callback)
    : manager_proxy_(new org::chromium::bluetooth::ManagerProxy(
          bus, kBTManagerServiceName)),
      dispatcher_(dispatcher),
      service_appeared_callback_(service_appeared_callback) {
  // One time callback when service becomes available.
  manager_proxy_->GetObjectProxy()->WaitForServiceToBeAvailable(base::BindOnce(
      &BluetoothManagerProxy::OnServiceAvailable, weak_factory_.GetWeakPtr()));
}

bool BluetoothManagerProxy::GetFlossEnabled(bool* enabled) const {
  brillo::ErrorPtr error;
  if (!manager_proxy_->GetFlossEnabled(enabled, &error)) {
    LOG(ERROR) << "Failed to query Floss status: " << error->GetCode() << " "
               << error->GetMessage();
    return false;
  }
  SLOG(3) << __func__ << ": " << manager_proxy_->GetObjectPath().value()
          << ": BT uses " << (*enabled ? "Floss" : "BlueZ");
  return true;
}

void BluetoothManagerProxy::OnServiceAvailable(bool /* available */) const {
  SLOG(2) << __func__ << ": " << manager_proxy_->GetObjectPath().value()
          << ": BT manager service is available";
  // |service_appeared_callback_| might invoke calls to the ObjectProxy, so
  // defer the callback to the event loop.
  // Note:
  // Race condition in btmanagerd/D-Bus: btmanagerd's D-Bus interface reports
  // that it's available before all the methods have been registered. Wait a
  // little bit before querying.
  // TODO(b/263432564): remove the delay once the race condition has been fixed,
  // but keep deferring the callback to the event loop.
  dispatcher_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&BluetoothManagerProxy::OnServiceReady,
                     weak_factory_.GetWeakPtr()),
      kDBusInitializationDelay);
}

void BluetoothManagerProxy::OnServiceReady() const {
  SLOG(2) << __func__ << ": " << manager_proxy_->GetObjectPath().value()
          << ": BT manager service ready";
  if (!service_appeared_callback_.is_null()) {
    service_appeared_callback_.Run();
  }
}

bool BluetoothManagerProxy::GetAvailableAdapters(
    bool force_query,
    bool* is_floss,
    std::vector<BluetoothManagerInterface::BTAdapterWithEnabled>* adapters)
    const {
  if (!GetFlossEnabled(is_floss)) {
    return false;
  }
  if (!*is_floss && !force_query) {
    // The device is not using Floss at the moment. Return immediately since
    // Floss won't know if the BT adapters are enabled or not in that case.
    // Callers may choose to fallback to BlueZ.
    return true;
  }
  std::vector<brillo::VariantDictionary> bt_adapters;
  brillo::ErrorPtr error;
  if (!manager_proxy_->GetAvailableAdapters(&bt_adapters, &error)) {
    LOG(ERROR) << "Failed to query available BT adapters: " << error->GetCode()
               << " " << error->GetMessage();
    return false;
  }
  for (auto bt_adapter : bt_adapters) {
    BluetoothManagerInterface::BTAdapterWithEnabled adapter{
        .hci_interface = brillo::GetVariantValueOrDefault<int32_t>(
            bt_adapter, "hci_interface"),
        .enabled =
            brillo::GetVariantValueOrDefault<bool>(bt_adapter, "enabled")};
    adapters->push_back(adapter);
    SLOG(3) << __func__ << ": " << manager_proxy_->GetObjectPath().value()
            << ": Found BT adapter HCI " << adapter.hci_interface;
    if (*is_floss) {
      // The "enabled" bit is not valid if the device is using BlueZ.
      SLOG(3) << __func__ << ": " << manager_proxy_->GetObjectPath().value()
              << ": BT adapter " << (adapter.enabled ? "enabled" : "disabled");
    }
  }
  return true;
}

bool BluetoothManagerProxy::GetDefaultAdapter(int32_t* hci) const {
  brillo::ErrorPtr error;
  if (!manager_proxy_->GetDefaultAdapter(hci, &error)) {
    LOG(ERROR) << "Failed to get default adapter:" << error->GetCode() << " "
               << error->GetMessage();
    return false;
  }
  SLOG(3) << __func__ << ": " << manager_proxy_->GetObjectPath().value()
          << ": Found default BT adapter, HCI " << *hci;
  return true;
}

}  // namespace shill
