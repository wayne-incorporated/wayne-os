// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_WILCO_DTC_SUPPORTD_UTILS_SYSTEM_FAKE_BLUETOOTH_CLIENT_H_
#define DIAGNOSTICS_WILCO_DTC_SUPPORTD_UTILS_SYSTEM_FAKE_BLUETOOTH_CLIENT_H_

#include <vector>

#include <dbus/object_path.h>
#include <gmock/gmock.h>

#include "diagnostics/wilco_dtc_supportd/utils/system/bluetooth_client.h"

namespace diagnostics {
namespace wilco {

class FakeBluetoothClient : public BluetoothClient {
 public:
  FakeBluetoothClient();
  FakeBluetoothClient(const FakeBluetoothClient&) = delete;
  FakeBluetoothClient& operator=(const FakeBluetoothClient&) = delete;
  ~FakeBluetoothClient() override;

  // BluetoothClient overrides:
  MOCK_METHOD(std::vector<dbus::ObjectPath>, GetAdapters, (), (override));
  MOCK_METHOD(std::vector<dbus::ObjectPath>, GetDevices, (), (override));
  MOCK_METHOD(const BluetoothClient::AdapterProperties*,
              GetAdapterProperties,
              (const dbus::ObjectPath&),
              (override));
  MOCK_METHOD(const BluetoothClient::DeviceProperties*,
              GetDeviceProperties,
              (const dbus::ObjectPath&),
              (override));

  bool HasObserver(Observer* observer) const;

  void EmitAdapterAdded(const dbus::ObjectPath& object_path,
                        const AdapterProperties& properties) const;
  void EmitAdapterRemoved(const dbus::ObjectPath& object_path) const;
  void EmitAdapterPropertyChanged(const dbus::ObjectPath& object_path,
                                  const AdapterProperties& properties) const;
  void EmitDeviceAdded(const dbus::ObjectPath& object_path,
                       const DeviceProperties& properties) const;
  void EmitDeviceRemoved(const dbus::ObjectPath& object_path) const;
  void EmitDevicePropertyChanged(const dbus::ObjectPath& object_path,
                                 const DeviceProperties& properties) const;
};

}  // namespace wilco
}  // namespace diagnostics

#endif  // DIAGNOSTICS_WILCO_DTC_SUPPORTD_UTILS_SYSTEM_FAKE_BLUETOOTH_CLIENT_H_
