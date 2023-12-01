// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_SUPPLICANT_NETWORK_PROXY_H_
#define SHILL_DBUS_SUPPLICANT_NETWORK_PROXY_H_

#include <memory>
#include <string>

#include "shill/data_types.h"
#include "shill/refptr_types.h"
#include "shill/supplicant/supplicant_network_proxy_interface.h"
#include "supplicant/dbus-proxies.h"

namespace shill {

// SupplicantNetworkProxy. provides access to wpa_supplicant's
// network-interface APIs via D-Bus.
class SupplicantNetworkProxy : public SupplicantNetworkProxyInterface {
 public:
  SupplicantNetworkProxy(const scoped_refptr<dbus::Bus>& bus,
                         const RpcIdentifier& object_path);
  SupplicantNetworkProxy(const SupplicantNetworkProxy&) = delete;
  SupplicantNetworkProxy& operator=(const SupplicantNetworkProxy&) = delete;

  ~SupplicantNetworkProxy() override;

  // Implementation of SupplicantNetworkProxyInterface.
  // This function will always return true, since PropertySet::Set is an
  // async method. Failures will be logged in the callback.
  bool SetEnabled(bool enabled) override;

  bool SetProperties(const KeyValueStore& props) override;

 private:
  class PropertySet : public dbus::PropertySet {
   public:
    PropertySet(dbus::ObjectProxy* object_proxy,
                const std::string& interface_name,
                const PropertyChangedCallback& callback);
    PropertySet(const PropertySet&) = delete;
    PropertySet& operator=(const PropertySet&) = delete;

    brillo::dbus_utils::Property<bool> enabled;
    brillo::dbus_utils::Property<brillo::VariantDictionary> properties;

   private:
  };

  static const char kInterfaceName[];
  static const char kPropertyEnabled[];
  static const char kPropertyProperties[];

  // Signal handlers.
  void PropertiesChanged(const brillo::VariantDictionary& properties);

  // Callback invoked when the value of property |property_name| is changed.
  void OnPropertyChanged(const std::string& property_name);

  // Called when signal is connected to the ObjectProxy.
  void OnSignalConnected(const std::string& interface_name,
                         const std::string& signal_name,
                         bool success);

  std::unique_ptr<fi::w1::wpa_supplicant1::NetworkProxy> network_proxy_;
  std::unique_ptr<PropertySet> properties_;

  base::WeakPtrFactory<SupplicantNetworkProxy> weak_factory_{this};
};

}  // namespace shill

#endif  // SHILL_DBUS_SUPPLICANT_NETWORK_PROXY_H_
