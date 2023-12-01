// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <base/check.h>
#include <base/containers/contains.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/message.h>

#include "power_manager/powerd/system/bluez_battery_provider.h"

namespace power_manager::system {

namespace {

constexpr char kBluetoothDefaultAdapter[] = "/org/bluez/hci0";
constexpr char kBluetoothBatteryProviderPath[] =
    "/org/chromium/PowerManager/battery_provider";

// from "aa:BB:cc:11:22:33" to "AA_BB_CC_11_22_33"
std::string AddressToPath(const std::string& address) {
  std::string replaced = address;
  replace(replaced.begin(), replaced.end(), ':', '_');
  return base::ToUpperASCII(replaced);
}

// from "aa:BB:cc:11:22:33" to
// "/org/chromium/PowerManager/battery_provider/AA_BB_CC_11_22_33"
std::string AddressToBatteryObjectPath(const std::string& address) {
  return kBluetoothBatteryProviderPath + std::string("/") +
         AddressToPath(address);
}

void NoopCompletionAction(bool succeeded) {}

void OnPropertyChanged(const std::string& name) {}

}  // namespace

BluezBattery::BluezBattery(
    brillo::dbus_utils::ExportedObjectManager* object_manager,
    const scoped_refptr<dbus::Bus>& bus,
    const std::string& address,
    int level,
    const dbus::ObjectPath& object_path,
    const dbus::ObjectPath& device_path)
    : dbus_object_(object_manager, bus, object_path), address_(address) {
  device_.SetValue(device_path);
  SetLevel(level);
}

void BluezBattery::Export(
    brillo::dbus_utils::AsyncEventSequencer::CompletionAction callback) {
  brillo::dbus_utils::DBusInterface* iface = dbus_object_.AddOrGetInterface(
      bluetooth_battery::kBluetoothBatteryProviderInterface);
  iface->AddProperty(bluetooth_battery::kDeviceProperty, &device_);
  iface->AddProperty(bluetooth_battery::kPercentageProperty, &percentage_);
  dbus_object_.RegisterAsync(std::move(callback));
}

void BluezBattery::Unexport() {
  // TODO(b/278483576): Replace it by UnregisterAsync.
  dbus_object_.UnregisterAndBlock();
}

void BluezBattery::SetLevel(int level) {
  if (level < 0 || level > 100) {
    LOG(WARNING) << "Ignoring invalid battery level " << level;
    return;
  }

  percentage_.SetValue(level);
}

BluezBatteryProvider::BluezBatteryProvider() : weak_ptr_factory_(this) {}

void BluezBatteryProvider::Init(scoped_refptr<dbus::Bus> bus) {
  bus_ = bus;

  if (!bus_)
    return;

  battery_exported_object_manager_ =
      std::make_unique<brillo::dbus_utils::ExportedObjectManager>(
          bus_, dbus::ObjectPath(kBluetoothBatteryProviderPath));

  battery_exported_object_manager_->RegisterAsync(
      base::BindRepeating(&NoopCompletionAction));

  object_manager_ = bus_->GetObjectManager(
      bluetooth_battery::kBluetoothBatteryProviderManagerServiceName,
      dbus::ObjectPath("/"));
  object_manager_->RegisterInterface(
      bluetooth_battery::kBluetoothBatteryProviderManagerInterface, this);
}

void BluezBatteryProvider::Reset() {
  for (const auto& kv : batteries_) {
    kv.second->Unexport();
  }

  batteries_.clear();

  is_registered_ = false;
}

void BluezBatteryProvider::UpdateDeviceBattery(const std::string& address,
                                               int level) {
  BluezBattery* battery = GetBattery(address);

  if (battery) {
    battery->SetLevel(level);
    return;
  }

  CreateBattery(address, level);
}

void BluezBatteryProvider::ObjectAdded(const dbus::ObjectPath& object_path,
                                       const std::string& interface_name) {
  LOG(INFO) << "Bluetooth Battery Provider Manager appears";
  RegisterAsBatteryProvider(object_manager_->GetObjectProxy(object_path));
}

void BluezBatteryProvider::ObjectRemoved(const dbus::ObjectPath& object_path,
                                         const std::string& interface_name) {
  LOG(INFO) << "Bluetooth Battery Provider Manager disappears";
  Reset();
}

dbus::PropertySet* BluezBatteryProvider::CreateProperties(
    dbus::ObjectProxy* object_proxy,
    const dbus::ObjectPath& object_path,
    const std::string& interface_name) {
  return new dbus::PropertySet(object_proxy, interface_name,
                               base::BindRepeating(&OnPropertyChanged));
}

void BluezBatteryProvider::RegisterAsBatteryProvider(
    dbus::ObjectProxy* manager_proxy) {
  if (is_registered_) {
    LOG(WARNING)
        << "Battery Provider already registered, not registering again";
    return;
  }

  dbus::MethodCall method_call(
      bluetooth_battery::kBluetoothBatteryProviderManagerInterface,
      bluetooth_battery::kRegisterBatteryProvider);
  dbus::MessageWriter writer(&method_call);
  writer.AppendObjectPath(dbus::ObjectPath(kBluetoothBatteryProviderPath));

  manager_proxy->CallMethod(
      &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT,
      base::BindOnce(
          &BluezBatteryProvider::HandleRegisterBatteryProviderResponse,
          weak_ptr_factory_.GetWeakPtr()));
}

void BluezBatteryProvider::HandleRegisterBatteryProviderResponse(
    dbus::Response* response) {
  if (!response)
    return;

  if (!response->GetErrorName().empty()) {
    LOG(ERROR) << "Error registering as battery provider: "
               << response->GetErrorName();
    return;
  }

  is_registered_ = true;
}

BluezBattery* BluezBatteryProvider::CreateBattery(const std::string& address,
                                                  int level) {
  CHECK(!base::Contains(batteries_, address));

  if (!battery_exported_object_manager_)
    return nullptr;

  std::string device_path = std::string(kBluetoothDefaultAdapter) +
                            std::string("/dev_") + AddressToPath(address);
  std::string object_path = AddressToBatteryObjectPath(address);
  batteries_[address] = std::make_unique<BluezBattery>(
      battery_exported_object_manager_.get(), bus_, address, level,
      dbus::ObjectPath(object_path), dbus::ObjectPath(device_path));

  batteries_[address]->Export(base::BindRepeating(&NoopCompletionAction));

  return batteries_[address].get();
}

BluezBattery* BluezBatteryProvider::GetBattery(const std::string& address) {
  if (base::Contains(batteries_, address))
    return batteries_[address].get();

  return nullptr;
}

}  // namespace power_manager::system
