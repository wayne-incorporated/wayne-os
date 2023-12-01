// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_DEVICE_DBUS_ADAPTOR_H_
#define SHILL_DBUS_DEVICE_DBUS_ADAPTOR_H_

#include <string>
#include <vector>

#include "dbus_bindings/org.chromium.flimflam.Device.h"
#include "shill/adaptor_interfaces.h"
#include "shill/dbus/dbus_adaptor.h"

namespace shill {

class Device;

// There is a 1:1 mapping between Device and DeviceDBusAdaptor instances.
// Furthermore, the Device owns the DeviceDBusAdaptor and manages its lifetime,
// so we're OK with DeviceDBusAdaptor having a bare pointer to its owner device.
class DeviceDBusAdaptor : public org::chromium::flimflam::DeviceAdaptor,
                          public org::chromium::flimflam::DeviceInterface,
                          public DBusAdaptor,
                          public DeviceAdaptorInterface {
 public:
  static const char kPath[];

  DeviceDBusAdaptor(const scoped_refptr<dbus::Bus>& bus, Device* device);
  DeviceDBusAdaptor(const DeviceDBusAdaptor&) = delete;
  DeviceDBusAdaptor& operator=(const DeviceDBusAdaptor&) = delete;

  ~DeviceDBusAdaptor() override;

  // Implementation of DeviceAdaptorInterface.
  const RpcIdentifier& GetRpcIdentifier() const override;
  void EmitBoolChanged(const std::string& name, bool value) override;
  void EmitUintChanged(const std::string& name, uint32_t value) override;
  void EmitUint16Changed(const std::string& name, uint16_t value) override;
  void EmitIntChanged(const std::string& name, int value) override;
  void EmitStringChanged(const std::string& name,
                         const std::string& value) override;
  void EmitStringmapChanged(const std::string& name,
                            const Stringmap& value) override;
  void EmitStringmapsChanged(const std::string& name,
                             const Stringmaps& value) override;
  void EmitStringsChanged(const std::string& name,
                          const Strings& value) override;
  void EmitKeyValueStoreChanged(const std::string& name,
                                const KeyValueStore& value) override;
  void EmitKeyValueStoresChanged(const std::string& name,
                                 const KeyValueStores& value) override;
  void EmitRpcIdentifierChanged(const std::string& name,
                                const RpcIdentifier& value) override;
  void EmitRpcIdentifierArrayChanged(const std::string& name,
                                     const RpcIdentifiers& value) override;

  // Implementation of DeviceAdaptor.
  bool GetProperties(brillo::ErrorPtr* error,
                     brillo::VariantDictionary* out_properties) override;
  bool SetProperty(brillo::ErrorPtr* error,
                   const std::string& name,
                   const brillo::Any& value) override;
  bool ClearProperty(brillo::ErrorPtr* error, const std::string& name) override;
  void Enable(DBusMethodResponsePtr<> response) override;
  void Disable(DBusMethodResponsePtr<> response) override;
  void Register(DBusMethodResponsePtr<> response,
                const std::string& network_id) override;
  void RequirePin(DBusMethodResponsePtr<> response,
                  const std::string& pin,
                  bool require) override;
  void EnterPin(DBusMethodResponsePtr<> response,
                const std::string& pin) override;
  void UnblockPin(DBusMethodResponsePtr<> response,
                  const std::string& unblock_code,
                  const std::string& pin) override;
  void ChangePin(DBusMethodResponsePtr<> response,
                 const std::string& old_pin,
                 const std::string& new_pin) override;
  void Reset(DBusMethodResponsePtr<> response) override;
  bool RequestRoam(brillo::ErrorPtr* error, const std::string& addr) override;

  void SetUsbEthernetMacAddressSource(DBusMethodResponsePtr<> response,
                                      const std::string& source) override;

  Device* device() const { return device_; }

 private:
  Device* device_;
};

}  // namespace shill

#endif  // SHILL_DBUS_DEVICE_DBUS_ADAPTOR_H_
