// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_SERVICE_DBUS_ADAPTOR_H_
#define SHILL_DBUS_SERVICE_DBUS_ADAPTOR_H_

#include <map>
#include <string>
#include <vector>

#include "dbus_bindings/org.chromium.flimflam.Service.h"
#include "shill/adaptor_interfaces.h"
#include "shill/data_types.h"
#include "shill/dbus/dbus_adaptor.h"

namespace shill {

class Service;

// Subclass of DBusAdaptor for Service objects
// There is a 1:1 mapping between Service and ServiceDBusAdaptor
// instances.  Furthermore, the Service owns the ServiceDBusAdaptor
// and manages its lifetime, so we're OK with ServiceDBusAdaptor
// having a bare pointer to its owner service.
class ServiceDBusAdaptor : public org::chromium::flimflam::ServiceAdaptor,
                           public org::chromium::flimflam::ServiceInterface,
                           public DBusAdaptor,
                           public ServiceAdaptorInterface {
 public:
  static const char kPath[];

  ServiceDBusAdaptor(const scoped_refptr<dbus::Bus>& bus, Service* service);
  ServiceDBusAdaptor(const ServiceDBusAdaptor&) = delete;
  ServiceDBusAdaptor& operator=(const ServiceDBusAdaptor&) = delete;

  ~ServiceDBusAdaptor() override;

  // Implementation of ServiceAdaptorInterface.
  const RpcIdentifier& GetRpcIdentifier() const override { return dbus_path(); }
  void EmitBoolChanged(const std::string& name, bool value) override;
  void EmitUint8Changed(const std::string& name, uint8_t value) override;
  void EmitUint16Changed(const std::string& name, uint16_t value) override;
  void EmitUint16sChanged(const std::string& name,
                          const Uint16s& value) override;
  void EmitUintChanged(const std::string& name, uint32_t value) override;
  void EmitUint64Changed(const std::string& name, uint64_t value) override;
  void EmitIntChanged(const std::string& name, int value) override;
  void EmitRpcIdentifierChanged(const std::string& name,
                                const RpcIdentifier& value) override;
  void EmitStringChanged(const std::string& name,
                         const std::string& value) override;
  void EmitStringmapChanged(const std::string& name,
                            const Stringmap& value) override;
  void EmitStringmapsChanged(const std::string& name,
                             const Stringmaps& value) override;

  // Implementation of ServiceAdaptor
  bool GetProperties(brillo::ErrorPtr* error,
                     brillo::VariantDictionary* properties) override;
  bool SetProperty(brillo::ErrorPtr* error,
                   const std::string& name,
                   const brillo::Any& value) override;
  bool SetProperties(brillo::ErrorPtr* error,
                     const brillo::VariantDictionary& properties) override;
  bool ClearProperty(brillo::ErrorPtr* error, const std::string& name) override;
  bool ClearProperties(brillo::ErrorPtr* error,
                       const std::vector<std::string>& names,
                       std::vector<bool>* results) override;
  bool Connect(brillo::ErrorPtr* error) override;
  bool Disconnect(brillo::ErrorPtr* error) override;
  bool Remove(brillo::ErrorPtr* error) override;
  bool CompleteCellularActivation(brillo::ErrorPtr* error) override;
  bool GetLoadableProfileEntries(
      brillo::ErrorPtr* error,
      std::map<dbus::ObjectPath, std::string>* entries) override;
  bool GetWiFiPassphrase(brillo::ErrorPtr* error,
                         std::string* out_passphrase) override;
  bool GetEapPassphrase(brillo::ErrorPtr* error,
                        std::string* out_passphrase) override;
  bool RequestPortalDetection(brillo::ErrorPtr* error) override;
  void RequestTrafficCounters(
      DBusMethodResponsePtr<VariantDictionaries> response) override;
  bool ResetTrafficCounters(brillo::ErrorPtr* error) override;

  Service* service() const { return service_; }

 private:
  void VariantDictionariesMethodReplyCallback(
      DBusMethodResponsePtr<VariantDictionaries> response,
      const Error& error,
      const VariantDictionaries& returned);

  Service* service_;
  base::WeakPtrFactory<ServiceDBusAdaptor> weak_factory_{this};
};

}  // namespace shill

#endif  // SHILL_DBUS_SERVICE_DBUS_ADAPTOR_H_
