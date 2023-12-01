// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_WILCO_DTC_SUPPORTD_TELEMETRY_BLUETOOTH_EVENT_SERVICE_IMPL_H_
#define DIAGNOSTICS_WILCO_DTC_SUPPORTD_TELEMETRY_BLUETOOTH_EVENT_SERVICE_IMPL_H_

#include <map>
#include <set>
#include <string>
#include <vector>

#include <dbus/object_path.h>

#include "diagnostics/wilco_dtc_supportd/telemetry/bluetooth_event_service.h"
#include "diagnostics/wilco_dtc_supportd/utils/system/bluetooth_client.h"

namespace diagnostics {
namespace wilco {

// Adapter for communication with bluetooth daemon.
class BluetoothEventServiceImpl final : public BluetoothEventService,
                                        public BluetoothClient::Observer {
 public:
  explicit BluetoothEventServiceImpl(BluetoothClient* bluetooth_client);
  ~BluetoothEventServiceImpl() override;

  const std::vector<BluetoothEventService::AdapterData>& GetLatestEvent()
      override;

  // BluetoothClient::Observer overrides:
  void AdapterAdded(
      const dbus::ObjectPath& adapter_path,
      const BluetoothClient::AdapterProperties& properties) override;
  void AdapterRemoved(const dbus::ObjectPath& adapter_path) override;
  void AdapterPropertyChanged(
      const dbus::ObjectPath& adapter_path,
      const BluetoothClient::AdapterProperties& properties) override;
  void DeviceAdded(
      const dbus::ObjectPath& device_path,
      const BluetoothClient::DeviceProperties& properties) override;
  void DeviceRemoved(const dbus::ObjectPath& device_path) override;
  void DevicePropertyChanged(
      const dbus::ObjectPath& device_path,
      const BluetoothClient::DeviceProperties& properties) override;

 private:
  void AdapterChanged(const dbus::ObjectPath& adapter_path,
                      const BluetoothClient::AdapterProperties& properties);
  void DeviceChanged(const dbus::ObjectPath& device_path,
                     const BluetoothClient::DeviceProperties& properties);
  void RemoveConnectedDevice(const dbus::ObjectPath& device_path);

  void UpdateAdapterConnectedDevicesCount(const dbus::ObjectPath& adapter_path);

  void UpdateAdaptersData();

  std::map<dbus::ObjectPath, AdapterData> adapters_;

  // AdapterPath to connected DevicePaths mapping.
  std::map<dbus::ObjectPath, std::set<dbus::ObjectPath>> connected_devices_;

  // DevicePath to AdapterPath mapping.
  std::map<dbus::ObjectPath, dbus::ObjectPath> device_to_adapter_;

  // Last adapters data that was sent to observers.
  std::vector<AdapterData> last_adapters_data_;

  // Not owned.
  BluetoothClient* bluetooth_client_;
};

}  // namespace wilco
}  // namespace diagnostics

#endif  // DIAGNOSTICS_WILCO_DTC_SUPPORTD_TELEMETRY_BLUETOOTH_EVENT_SERVICE_IMPL_H_
