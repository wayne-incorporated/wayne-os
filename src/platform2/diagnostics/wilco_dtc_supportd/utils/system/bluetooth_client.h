// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_WILCO_DTC_SUPPORTD_UTILS_SYSTEM_BLUETOOTH_CLIENT_H_
#define DIAGNOSTICS_WILCO_DTC_SUPPORTD_UTILS_SYSTEM_BLUETOOTH_CLIENT_H_

#include <string>
#include <vector>

#include <base/observer_list.h>
#include <base/observer_list_types.h>
#include <dbus/object_path.h>
#include <dbus/object_proxy.h>
#include <dbus/property.h>

namespace diagnostics {
namespace wilco {

// BluetoothClient is used for monitoring objects representing Bluetooth
// Adapters and Devices.
class BluetoothClient {
 public:
  // Structure of properties associated with bluetooth adapters.
  struct AdapterProperties : public dbus::PropertySet {
    // The Bluetooth device address of the adapter.
    dbus::Property<std::string> address;

    // The Bluetooth system name, e.g. hci0.
    dbus::Property<std::string> name;

    // Whether the adapter radio is powered.
    dbus::Property<bool> powered;

    AdapterProperties(
        dbus::ObjectProxy* object_proxy,
        const dbus::PropertySet::PropertyChangedCallback& callback);
    ~AdapterProperties() override;
  };

  // Structure of properties associated with bluetooth devices.
  struct DeviceProperties : public dbus::PropertySet {
    // The Bluetooth device address of the device.
    dbus::Property<std::string> address;

    // The Bluetooth friendly name of the device.
    dbus::Property<std::string> name;

    // Indicates that the device is currently connected.
    dbus::Property<bool> connected;

    // Object path of the adapter the device belongs to.
    dbus::Property<dbus::ObjectPath> adapter;

    DeviceProperties(
        dbus::ObjectProxy* object_proxy,
        const dbus::PropertySet::PropertyChangedCallback& callback);
    ~DeviceProperties() override;
  };

  // Interface for observing bluetooth adapters and devices changes.
  class Observer : public base::CheckedObserver {
   public:
    virtual ~Observer() = default;

    // Called when the adapter with object path |adapter_path| is added to the
    // system.
    virtual void AdapterAdded(const dbus::ObjectPath& adapter_path,
                              const AdapterProperties& properties) = 0;

    // Called when the adapter with object path |adapter_path| is removed from
    // the system.
    virtual void AdapterRemoved(const dbus::ObjectPath& adapter_path) = 0;

    // Called when the adapter with object path |adapter_path| has a change in
    // value of the property.
    virtual void AdapterPropertyChanged(
        const dbus::ObjectPath& adapter_path,
        const AdapterProperties& properties) = 0;

    // Called when the device with object path |device_path| is added to the
    // system.
    virtual void DeviceAdded(const dbus::ObjectPath& device_path,
                             const DeviceProperties& properties) = 0;

    // Called when the device with object path |device_path| is removed from
    // the system.
    virtual void DeviceRemoved(const dbus::ObjectPath& device_path) = 0;

    // Called when the device with object path |device_path| has a
    // change in value of the property.
    virtual void DevicePropertyChanged(const dbus::ObjectPath& device_path,
                                       const DeviceProperties& properties) = 0;
  };

  BluetoothClient();
  BluetoothClient(const BluetoothClient&) = delete;
  BluetoothClient& operator=(const BluetoothClient&) = delete;
  virtual ~BluetoothClient();

  // Returns the list of object paths, in an undefined order, of objects
  // implementing the bluetooth_adapter::kBluetoothAdapterInterface interface.
  virtual std::vector<dbus::ObjectPath> GetAdapters() = 0;

  // Returns the list of object paths, in an undefined order, of objects
  // implementing the bluetooth_device::kBluetoothDeviceInterface interface.
  virtual std::vector<dbus::ObjectPath> GetDevices() = 0;

  // Returns an AdapterProperties pointer for the given |adapter_path| or NULL
  // if the object manager has not been informed of that object's existence or
  // the interface's properties.
  virtual const AdapterProperties* GetAdapterProperties(
      const dbus::ObjectPath& adapter_path) = 0;

  // Returns a DeviceProperties pointer for the given |device_path| or NULL if
  // the object manager has not been informed of that object's existence or
  // the interface's properties.
  virtual const DeviceProperties* GetDeviceProperties(
      const dbus::ObjectPath& device_path) = 0;

  void AddObserver(Observer* observer);
  void RemoveObserver(Observer* observer);

 protected:
  base::ObserverList<Observer> observers_;
};

}  // namespace wilco
}  // namespace diagnostics

#endif  // DIAGNOSTICS_WILCO_DTC_SUPPORTD_UTILS_SYSTEM_BLUETOOTH_CLIENT_H_
