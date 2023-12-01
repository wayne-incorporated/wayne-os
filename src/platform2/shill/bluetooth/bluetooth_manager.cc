// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/bluetooth/bluetooth_manager.h"

#include <cstdint>
#include <utility>
#include <vector>

#include <base/functional/bind.h>

#include "shill/control_interface.h"
#include "shill/logging.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kBluetooth;
}  // namespace Logging

BluetoothManager::BluetoothManager(ControlInterface* control_interface)
    : init_complete_(false), control_interface_(control_interface) {}

bool BluetoothManager::Start() {
  bluetooth_manager_proxy_ =
      control_interface_->CreateBluetoothManagerProxy(base::BindRepeating(
          &BluetoothManager::OnBTManagerAvailable, weak_factory_.GetWeakPtr()));
  if (!bluetooth_manager_proxy_) {
    LOG(ERROR) << "Failed to initialize BT manager proxy";
    TearDown();
    return false;
  }
  bluez_proxy_ = control_interface_->CreateBluetoothBlueZProxy();
  if (!bluez_proxy_) {
    LOG(ERROR) << "Failed to initialize BlueZ proxy";
    TearDown();
    return false;
  }
  return true;
}

void BluetoothManager::Stop() {
  TearDown();
}

void BluetoothManager::TearDown() {
  init_complete_ = false;
  bluez_proxy_.reset();
  adapter_proxies_.clear();
  bluetooth_manager_proxy_.reset();
}

void BluetoothManager::CompleteInitialization() {
  LOG(INFO) << "Completing initialization of BT manager";

  // On startup we want to know the list of adapters that are present on the
  // device even if we can't get all the information we would like (are they
  // actually enabled?) at the time so we force the discovery even if the device
  // is currently using BlueZ.
  bool floss;
  std::vector<BluetoothManagerInterface::BTAdapterWithEnabled> adapters;
  if (!bluetooth_manager_proxy_->GetAvailableAdapters(/*force_query=*/true,
                                                      &floss, &adapters)) {
    LOG(ERROR) << __func__ << ": Failed to query available BT adapters";
    TearDown();
    return;
  }
  LOG(INFO) << "BT manager found " << adapters.size() << " adapters";
  for (auto adapter : adapters) {
    auto proxy =
        control_interface_->CreateBluetoothAdapterProxy(adapter.hci_interface);
    if (!proxy) {
      LOG(ERROR) << "Failed to initialize BT adapter proxy "
                 << adapter.hci_interface;
      TearDown();
      return;
    }
    SLOG(3) << __func__ << ": adding BT adapter " << adapter.hci_interface;
    adapter_proxies_.emplace(adapter.hci_interface, std::move(proxy));
  }
  init_complete_ = true;
  LOG(INFO) << "Completed initialization of BT manager";
}

void BluetoothManager::OnBTManagerAvailable() {
  LOG(INFO) << __func__ << ": BT manager is available";
  CompleteInitialization();
}

bool BluetoothManager::GetAvailableAdapters(
    bool* is_floss,
    std::vector<BluetoothManagerInterface::BTAdapterWithEnabled>* adapters)
    const {
  if (!init_complete_) {
    LOG(ERROR) << __func__ << "BT manager is not ready";
    return false;
  }
  if (!bluetooth_manager_proxy_->GetAvailableAdapters(/*force_query=*/false,
                                                      is_floss, adapters)) {
    LOG(ERROR) << __func__ << ": Failed to query available BT adapters";
    return false;
  }
  if (*is_floss) {
    // The device is using Floss so in that case BluetoothManagerProxy was able
    // to report the state of the BT adapters. Nothing left to do, return
    // success.
    return true;
  }
  SLOG(3) << __func__ << "Floss disabled, fallback to BlueZ";
  bool powered;
  if (!bluez_proxy_->GetAdapterPowered(&powered)) {
    LOG(ERROR) << __func__ << ": Failed to query BT powered state from BlueZ";
    return false;
  }
  // For BlueZ we only support 1 adapter, interface 0.
  adapters->push_back({.hci_interface = 0, .enabled = powered});
  return true;
}

bool BluetoothManager::GetDefaultAdapter(int32_t* hci) const {
  if (!init_complete_) {
    LOG(ERROR) << __func__ << "BT manager is not ready";
    return false;
  }
  if (!bluetooth_manager_proxy_->GetDefaultAdapter(hci)) {
    LOG(ERROR) << __func__ << "Failed to query the default BT adapter";
    return false;
  }
  return true;
}

bool BluetoothManager::GetProfileConnectionState(
    int32_t hci, BTProfile profile, BTProfileConnectionState* state) const {
  if (!init_complete_) {
    LOG(ERROR) << __func__ << "BT manager is not ready";
    return false;
  }
  auto it = adapter_proxies_.find(hci);
  if (it == adapter_proxies_.end()) {
    LOG(ERROR) << "Adapter " << hci << " not found";
    return false;
  }
  if (!it->second->GetProfileConnectionState(profile, state)) {
    LOG(ERROR) << "Failed to query profile connection state";
    return false;
  }
  return true;
}

bool BluetoothManager::IsDiscovering(int32_t hci, bool* discovering) const {
  if (!init_complete_) {
    LOG(ERROR) << __func__ << "BT manager is not ready";
    return false;
  }
  auto it = adapter_proxies_.find(hci);
  if (it == adapter_proxies_.end()) {
    LOG(ERROR) << "Adapter " << hci << " not found";
    return false;
  }
  if (!it->second->IsDiscovering(discovering)) {
    LOG(ERROR) << "Failed to query discovering state";
    return false;
  }
  return true;
}

}  // namespace shill
