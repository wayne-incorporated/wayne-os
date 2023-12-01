// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_IPCONFIG_DBUS_ADAPTOR_H_
#define SHILL_DBUS_IPCONFIG_DBUS_ADAPTOR_H_

#include <string>
#include <vector>

#include "dbus_bindings/org.chromium.flimflam.IPConfig.h"
#include "shill/adaptor_interfaces.h"
#include "shill/dbus/dbus_adaptor.h"

namespace shill {

class IPConfig;

// Subclass of DBusAdaptor for IPConfig objects
// There is a 1:1 mapping between IPConfig and IPConfigDBusAdaptor
// instances.  Furthermore, the IPConfig owns the IPConfigDBusAdaptor
// and manages its lifetime, so we're OK with IPConfigDBusAdaptor
// having a bare pointer to its owner ipconfig.
class IPConfigDBusAdaptor : public org::chromium::flimflam::IPConfigAdaptor,
                            public org::chromium::flimflam::IPConfigInterface,
                            public DBusAdaptor,
                            public IPConfigAdaptorInterface {
 public:
  static const char kInterfaceName[];
  static const char kPath[];

  IPConfigDBusAdaptor(const scoped_refptr<dbus::Bus>& bus, IPConfig* ipconfig);
  IPConfigDBusAdaptor(const IPConfigDBusAdaptor&) = delete;
  IPConfigDBusAdaptor& operator=(const IPConfigDBusAdaptor&) = delete;

  ~IPConfigDBusAdaptor() override;

  // Implementation of IPConfigAdaptorInterface.
  const RpcIdentifier& GetRpcIdentifier() const override { return dbus_path(); }
  void EmitBoolChanged(const std::string& name, bool value) override;
  void EmitUintChanged(const std::string& name, uint32_t value) override;
  void EmitIntChanged(const std::string& name, int value) override;
  void EmitStringChanged(const std::string& name,
                         const std::string& value) override;
  void EmitStringsChanged(const std::string& name,
                          const std::vector<std::string>& value) override;

  // Implementation of IPConfigAdaptor
  bool GetProperties(brillo::ErrorPtr* error,
                     brillo::VariantDictionary* properties) override;
  bool SetProperty(brillo::ErrorPtr* error,
                   const std::string& name,
                   const brillo::Any& value) override;
  bool ClearProperty(brillo::ErrorPtr* error, const std::string& name) override;
  bool Remove(brillo::ErrorPtr* error) override;

 private:
  IPConfig* ipconfig_;
};

}  // namespace shill

#endif  // SHILL_DBUS_IPCONFIG_DBUS_ADAPTOR_H_
