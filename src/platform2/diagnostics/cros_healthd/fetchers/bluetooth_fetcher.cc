// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/fetchers/bluetooth_fetcher.h"

#include <map>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <dbus/object_path.h>

#include "diagnostics/cros_healthd/system/bluetooth_info_manager.h"
#include "diagnostics/cros_healthd/utils/error_utils.h"
#include "diagnostics/dbus_bindings/bluetooth/dbus-proxies.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

constexpr char kBluetoothTypeBrEdrName[] = "BR/EDR";
constexpr char kBluetoothTypeLeName[] = "LE";
constexpr char kBluetoothTypeDualName[] = "DUAL";

constexpr char kSupportedCapabilitiesMaxAdvLenKey[] = "MaxAdvLen";
constexpr char kSupportedCapabilitiesMaxScnRspLenKey[] = "MaxScnRspLen";
constexpr char kSupportedCapabilitiesMinTxPowerKey[] = "MinTxPower";
constexpr char kSupportedCapabilitiesMaxTxPowerKey[] = "MaxTxPower";

// Convert std::string to |BluetoothDeviceType| enum.
mojom::BluetoothDeviceType GetDeviceType(const std::string& type) {
  if (type == kBluetoothTypeBrEdrName)
    return mojom::BluetoothDeviceType::kBrEdr;
  else if (type == kBluetoothTypeLeName)
    return mojom::BluetoothDeviceType::kLe;
  else if (type == kBluetoothTypeDualName)
    return mojom::BluetoothDeviceType::kDual;
  return mojom::BluetoothDeviceType::kUnfound;
}

// Parse Bluetooth info from AdminPolicyStatus1 interface and store in the map.
void ParseServiceAllowList(
    std::vector<org::bluez::AdminPolicyStatus1ProxyInterface*> admin_policies,
    std::map<dbus::ObjectPath, std::vector<std::string>>&
        out_service_allow_list) {
  for (const auto& policy : admin_policies) {
    out_service_allow_list[policy->GetObjectPath()] =
        policy->service_allow_list();
  }
}

// Parse Bluetooth info from LEAdvertisingManager1 interface and store in the
// map.
void ParseSupportedCapabilities(
    std::vector<org::bluez::LEAdvertisingManager1ProxyInterface*> advertisings,
    std::map<dbus::ObjectPath, mojom::SupportedCapabilitiesPtr>&
        out_supported_capabilities) {
  for (const auto& advertising : advertisings) {
    auto data = advertising->supported_capabilities();
    // Drop data if missing any element.
    if (data.find(kSupportedCapabilitiesMaxAdvLenKey) == data.end() ||
        data.find(kSupportedCapabilitiesMaxScnRspLenKey) == data.end() ||
        data.find(kSupportedCapabilitiesMinTxPowerKey) == data.end() ||
        data.find(kSupportedCapabilitiesMaxTxPowerKey) == data.end()) {
      continue;
    }
    mojom::SupportedCapabilities info;
    info.max_adv_len = brillo::GetVariantValueOrDefault<uint8_t>(
        data, kSupportedCapabilitiesMaxAdvLenKey);
    info.max_scn_rsp_len = brillo::GetVariantValueOrDefault<uint8_t>(
        data, kSupportedCapabilitiesMaxScnRspLenKey);
    info.min_tx_power = brillo::GetVariantValueOrDefault<int16_t>(
        data, kSupportedCapabilitiesMinTxPowerKey);
    info.max_tx_power = brillo::GetVariantValueOrDefault<int16_t>(
        data, kSupportedCapabilitiesMaxTxPowerKey);
    out_supported_capabilities[advertising->GetObjectPath()] = info.Clone();
  }
}

// Parse Bluetooth info from Battery1 interface and store in the map.
void ParseBatteryPercentage(
    std::vector<org::bluez::Battery1ProxyInterface*> batteries,
    std::map<dbus::ObjectPath, uint8_t>& out_battery_percentage) {
  for (const auto& battery : batteries) {
    out_battery_percentage[battery->GetObjectPath()] = battery->percentage();
  }
}

// Parse Bluetooth info from Device1 interface and store in the map.
void ParseDevicesInfo(
    std::vector<org::bluez::Device1ProxyInterface*> devices,
    std::vector<org::bluez::Battery1ProxyInterface*> batteries,
    std::map<dbus::ObjectPath, std::vector<mojom::BluetoothDeviceInfoPtr>>&
        out_connected_devices) {
  // Map from the device's ObjectPath to the battery percentage.
  std::map<dbus::ObjectPath, uint8_t> battery_percentage;
  ParseBatteryPercentage(batteries, battery_percentage);

  for (const auto& device : devices) {
    if (!device || !device->connected())
      continue;

    mojom::BluetoothDeviceInfo info;
    info.address = device->address();

    // The following are optional device properties.
    if (device->is_name_valid())
      info.name = device->name();
    if (device->is_type_valid())
      info.type = GetDeviceType(device->type());
    else
      info.type = mojom::BluetoothDeviceType::kUnfound;
    if (device->is_appearance_valid())
      info.appearance = mojom::NullableUint16::New(device->appearance());
    if (device->is_modalias_valid())
      info.modalias = device->modalias();
    if (device->is_rssi_valid())
      info.rssi = mojom::NullableInt16::New(device->rssi());
    if (device->is_mtu_valid())
      info.mtu = mojom::NullableUint16::New(device->mtu());
    if (device->is_uuids_valid())
      info.uuids = device->uuids();
    if (device->is_bluetooth_class_valid())
      info.bluetooth_class =
          mojom::NullableUint32::New(device->bluetooth_class());

    const auto it = battery_percentage.find(device->GetObjectPath());
    if (it != battery_percentage.end()) {
      info.battery_percentage = mojom::NullableUint8::New(it->second);
    }

    out_connected_devices[device->adapter()].push_back(info.Clone());
  }
}

}  // namespace

mojom::BluetoothResultPtr FetchBluetoothInfo(Context* context) {
  const auto bluetooth_info_manager = context->bluetooth_info_manager();
  if (!bluetooth_info_manager) {
    return mojom::BluetoothResult::NewError(CreateAndLogProbeError(
        mojom::ErrorType::kServiceUnavailable, "Bluez proxy is not ready"));
  }
  std::vector<mojom::BluetoothAdapterInfoPtr> adapter_infos;

  // Map from the adapter's ObjectPath to the service allow list.
  std::map<dbus::ObjectPath, std::vector<std::string>> service_allow_list;
  ParseServiceAllowList(bluetooth_info_manager->GetAdminPolicies(),
                        service_allow_list);

  // Map from the adapter's ObjectPath to the supported capabilities.
  std::map<dbus::ObjectPath, mojom::SupportedCapabilitiesPtr>
      supported_capabilities;
  ParseSupportedCapabilities(bluetooth_info_manager->GetAdvertisings(),
                             supported_capabilities);

  // Map from the adapter's ObjectPath to the connected devices.
  std::map<dbus::ObjectPath, std::vector<mojom::BluetoothDeviceInfoPtr>>
      connected_devices;
  ParseDevicesInfo(bluetooth_info_manager->GetDevices(),
                   bluetooth_info_manager->GetBatteries(), connected_devices);

  // Fetch adapters' info.
  for (const auto& adapter : bluetooth_info_manager->GetAdapters()) {
    if (!adapter)
      continue;
    mojom::BluetoothAdapterInfo info;

    info.name = adapter->name();
    info.address = adapter->address();
    info.powered = adapter->powered();
    info.discoverable = adapter->discoverable();
    info.discovering = adapter->discovering();
    info.uuids = adapter->uuids();
    info.modalias = adapter->modalias();

    const auto adapter_path = adapter->GetObjectPath();
    const auto it_connected_device = connected_devices.find(adapter_path);
    if (it_connected_device != connected_devices.end()) {
      info.num_connected_devices = it_connected_device->second.size();
      info.connected_devices = std::move(it_connected_device->second);
    }

    const auto it_service_allow_list = service_allow_list.find(adapter_path);
    if (it_service_allow_list != service_allow_list.end()) {
      info.service_allow_list = it_service_allow_list->second;
    }

    const auto it_capabilities = supported_capabilities.find(adapter_path);
    if (it_capabilities != supported_capabilities.end()) {
      info.supported_capabilities = std::move(it_capabilities->second);
    }
    adapter_infos.push_back(info.Clone());
  }

  return mojom::BluetoothResult::NewBluetoothAdapterInfo(
      std::move(adapter_infos));
}

}  // namespace diagnostics
